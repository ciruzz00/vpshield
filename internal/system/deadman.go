package system

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"
)

// The dead-man switch: after a risky change (SSH port, SSH auth) we schedule
// an automatic rollback that runs OUTSIDE this process, so it still fires if
// the SSH session drops and the TUI dies with it. The user cancels it by
// confirming from a second, fresh SSH session (`vpshield confirm`) or from
// the TUI.

const deadmanFile = "/run/vpshield-deadman.json"
const deadmanUnit = "vpshield-deadman"

type Deadman struct {
	SnapshotID string    `json:"snapshot_id"`
	Deadline   time.Time `json:"deadline"`
	Mode       string    `json:"mode"` // systemd | process
	PID        int       `json:"pid,omitempty"`
	Reason     string    `json:"reason"`
}

func (h *Host) ArmDeadman(snapshotID string, after time.Duration, reason string) (*Deadman, error) {
	d := &Deadman{SnapshotID: snapshotID, Deadline: time.Now().Add(after), Reason: reason}
	if h.DryRun {
		h.logf("[dry-run] arm dead-man switch: rollback %s in %s", snapshotID, after)
		d.Mode = "dry-run"
		return d, nil
	}
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	_ = h.DisarmDeadman() // never stack two timers
	secs := strconv.Itoa(int(after.Seconds()))
	if h.Distro.Init == InitSystemd && h.Has("systemd-run") {
		_, _ = exe(10*time.Second, "systemctl", "reset-failed", deadmanUnit+".service", deadmanUnit+".timer")
		_, err := exe(15*time.Second, "systemd-run", "--unit="+deadmanUnit, "--on-active="+secs+"s",
			"--timer-property=AccuracySec=1s", "--description=vpshield automatic rollback",
			self, "rollback", snapshotID, "--deadman")
		if err == nil {
			d.Mode = "systemd"
			h.logf("dead-man armed via systemd-run: rollback %s in %ss", snapshotID, secs)
			return d, d.save()
		}
		h.logf("systemd-run failed (%v), falling back to detached process", err)
	}
	cmd := exec.Command("/bin/sh", "-c", fmt.Sprintf("sleep %s; exec %q rollback %q --deadman", secs, self, snapshotID))
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	devnull, _ := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = devnull, devnull, devnull
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	d.Mode = "process"
	d.PID = cmd.Process.Pid
	_ = cmd.Process.Release()
	h.logf("dead-man armed (pid %d): rollback %s in %ss", d.PID, snapshotID, secs)
	return d, d.save()
}

func (d *Deadman) save() error {
	b, _ := json.Marshal(d)
	return os.WriteFile(deadmanFile, b, 0o600)
}

// ActiveDeadman returns the pending switch, if any.
func ActiveDeadman() *Deadman {
	b, err := os.ReadFile(deadmanFile)
	if err != nil {
		return nil
	}
	var d Deadman
	if json.Unmarshal(b, &d) != nil {
		return nil
	}
	if time.Now().After(d.Deadline.Add(2 * time.Minute)) {
		os.Remove(deadmanFile)
		return nil
	}
	return &d
}

// DisarmDeadman cancels the pending rollback (the change is kept).
func (h *Host) DisarmDeadman() error {
	if h.DryRun {
		h.logf("[dry-run] disarm dead-man switch")
		return nil
	}
	d := ActiveDeadman()
	var errs []error
	if h.Distro.Init == InitSystemd && h.Has("systemctl") {
		_, _ = exe(10*time.Second, "systemctl", "stop", deadmanUnit+".timer")
		_, _ = exe(10*time.Second, "systemctl", "reset-failed", deadmanUnit+".service", deadmanUnit+".timer")
	}
	if d != nil && d.Mode == "process" && d.PID > 0 {
		// negative pid = whole process group created by Setsid
		if err := syscall.Kill(-d.PID, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
			errs = append(errs, err)
		}
	}
	os.Remove(deadmanFile)
	if d != nil {
		h.logf("dead-man disarmed (snapshot %s kept)", d.SnapshotID)
	}
	return errors.Join(errs...)
}

// ClearDeadmanMarker is called by the rollback itself once it has fired.
func ClearDeadmanMarker() { os.Remove(deadmanFile) }
