// Package updates configures automatic (security) updates per distro.
package updates

import (
	"fmt"
	"strings"

	"vpshield/internal/cron"
	"vpshield/internal/plan"
	"vpshield/internal/system"
)

type Config struct {
	SecurityOnly bool
	AutoReboot   bool
	RebootTime   string // HH:MM
}

const (
	aptPeriodic = "/etc/apt/apt.conf.d/20auto-upgrades"
	aptVpshield = "/etc/apt/apt.conf.d/52vpshield-unattended"
	dnfConf     = "/etc/dnf/automatic.conf"
)

// Status returns a one line summary.
func Status(h *system.Host) (bool, string) {
	switch h.Distro.Family {
	case system.FamilyDebian:
		c := system.ReadFile(aptPeriodic)
		on := strings.Contains(c, `Unattended-Upgrade "1"`)
		return on, map[bool]string{true: "unattended-upgrades enabled", false: "unattended-upgrades not configured"}[on]
	case system.FamilyRHEL:
		for _, t := range []string{"dnf-automatic.timer", "dnf-automatic-install.timer", "dnf5-automatic.timer"} {
			if h.ServiceEnabled(t) {
				return true, t + " enabled"
			}
		}
		return false, "dnf-automatic not enabled"
	case system.FamilyAlpine, system.FamilyArch:
		for _, j := range cron.Load(h) {
			if j.ID == "autoupdate" {
				return true, "cron job: " + j.Schedule
			}
		}
		return false, "no update cron job"
	}
	return false, "unsupported distribution"
}

func renderApt(c Config, ubuntu bool) string {
	var b strings.Builder
	b.WriteString("// Managed by vpshield\n")
	if !c.SecurityOnly {
		if ubuntu {
			b.WriteString("Unattended-Upgrade::Allowed-Origins {\n\t\"${distro_id}:${distro_codename}-updates\";\n};\n")
		} else {
			b.WriteString("Unattended-Upgrade::Origins-Pattern {\n\t\"origin=Debian,codename=${distro_codename}-updates\";\n};\n")
		}
	}
	fmt.Fprintf(&b, "Unattended-Upgrade::Automatic-Reboot \"%t\";\n", c.AutoReboot)
	fmt.Fprintf(&b, "Unattended-Upgrade::Automatic-Reboot-Time \"%s\";\n", c.RebootTime)
	b.WriteString("Unattended-Upgrade::Remove-Unused-Kernel-Packages \"true\";\n")
	b.WriteString("Unattended-Upgrade::Remove-Unused-Dependencies \"true\";\n")
	return b.String()
}

// SetIni sets key=value inside [section] of an ini file, adding what is missing.
func SetIni(content, section, key, value string) string {
	lines := strings.Split(content, "\n")
	in := false
	secIdx := -1
	for i, l := range lines {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			if in { // leaving the section without finding the key
				j := i
				for j-1 > secIdx && strings.TrimSpace(lines[j-1]) == "" {
					j--
				}
				lines = append(lines[:j], append([]string{key + " = " + value}, lines[j:]...)...)
				return strings.Join(lines, "\n")
			}
			in = t == "["+section+"]"
			if in {
				secIdx = i
			}
			continue
		}
		if in {
			k, _, ok := strings.Cut(strings.TrimLeft(t, "#; "), "=")
			if ok && strings.TrimSpace(k) == key {
				lines[i] = key + " = " + value
				return strings.Join(lines, "\n")
			}
		}
	}
	if secIdx >= 0 {
		return strings.TrimRight(strings.Join(lines, "\n"), "\n") + "\n" + key + " = " + value + "\n"
	}
	return strings.TrimRight(content, "\n") + "\n\n[" + section + "]\n" + key + " = " + value + "\n"
}

func BuildPlan(h *system.Host, c Config) *plan.Plan {
	p := &plan.Plan{Title: "Configure automatic updates"}
	switch h.Distro.Family {
	case system.FamilyDebian:
		p.Add(plan.Install(h, "autoupdates"),
			plan.File(aptPeriodic, "// Managed by vpshield\nAPT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\nAPT::Periodic::AutocleanInterval \"7\";\n", 0o644),
			plan.File(aptVpshield, renderApt(c, h.Distro.ID == "ubuntu"), 0o644),
			plan.Step{Title: "dry-run unattended-upgrade", Optional: true, Run: func(h *system.Host) (string, error) {
				out, err := h.Query("unattended-upgrade", "--dry-run")
				return lastN(out, 5), err
			}},
		)
	case system.FamilyRHEL:
		conf := system.ReadFile(dnfConf)
		utype := "default"
		if c.SecurityOnly {
			utype = "security"
		}
		reboot := "never"
		if c.AutoReboot {
			reboot = "when-needed"
		}
		conf = SetIni(conf, "commands", "upgrade_type", utype)
		conf = SetIni(conf, "commands", "download_updates", "yes")
		conf = SetIni(conf, "commands", "apply_updates", "yes")
		conf = SetIni(conf, "commands", "reboot", reboot)
		p.Add(plan.Install(h, "autoupdates"), plan.File(dnfConf, conf, 0o644), plan.EnableService("dnf-automatic.timer"))
		if c.AutoReboot {
			p.Warn("reboot=when-needed requires dnf-automatic >= 4.15 (RHEL 9.2+); older versions ignore it")
		}
	case system.FamilyAlpine:
		jobs := upsertJob(cron.Load(h), cron.Job{ID: "autoupdate", Schedule: "0 4 * * *",
			Command: "apk update -q && apk upgrade -q --available >>/var/log/vpshield/apk-upgrade.log 2>&1", Comment: "automatic apk upgrade"})
		p.Steps = append(p.Steps, cron.SavePlan(h, jobs, "").Steps...)
		p.Warn("Alpine has no security-only channel: the job applies all available upgrades")
	case system.FamilyArch:
		jobs := upsertJob(cron.Load(h), cron.Job{ID: "autoupdate", Schedule: "0 6 * * *",
			Command: "checkupdates > /var/log/vpshield/pending-updates.txt 2>&1", Comment: "list pending updates (notify only)"})
		p.Add(plan.Install(h, "autoupdates"))
		p.Steps = append(p.Steps, cron.SavePlan(h, jobs, "").Steps...)
		p.Warn("Arch is rolling release: unattended upgrades break systems. vpshield only logs pending updates daily to /var/log/vpshield/pending-updates.txt")
	default:
		p.Warn("unsupported distribution")
	}
	if c.AutoReboot && h.Distro.Family != system.FamilyRHEL && h.Distro.Family != system.FamilyDebian {
		p.Warn("automatic reboot is not supported on this distro, ignored")
	}
	return p
}

func upsertJob(jobs []cron.Job, j cron.Job) []cron.Job {
	var out []cron.Job
	for _, x := range jobs {
		if x.ID != j.ID {
			out = append(out, x)
		}
	}
	return append(out, j)
}

func lastN(s string, n int) string {
	l := strings.Split(strings.TrimSpace(s), "\n")
	if len(l) > n {
		l = l[len(l)-n:]
	}
	return strings.Join(l, "\n")
}
