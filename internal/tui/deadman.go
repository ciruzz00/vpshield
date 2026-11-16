package tui

import (
	"fmt"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"vpshield/internal/system"
)

type tickMsg time.Time

func tick() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg { return tickMsg(t) })
}

// deadmanScreen counts down the automatic rollback after an SSH change.
type deadmanScreen struct {
	c         *ctx
	d         *system.Deadman
	onConfirm func() tea.Cmd
	status    string
	finished  bool
	total     time.Duration
}

func newDeadman(c *ctx, d *system.Deadman, onConfirm func() tea.Cmd) *deadmanScreen {
	total := time.Until(d.Deadline)
	if total <= 0 {
		total = time.Second
	}
	return &deadmanScreen{c: c, d: d, onConfirm: onConfirm, total: total}
}

func (s *deadmanScreen) Title() string { return "Confirm SSH access" }
func (s *deadmanScreen) Help() string {
	if s.finished {
		return helpLine("enter", "back")
	}
	return helpLine("c", "it works, keep it", "r", "roll back now")
}
func (s *deadmanScreen) Init() tea.Cmd { return tick() }

func (s *deadmanScreen) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch m := msg.(type) {
	case tickMsg:
		if s.finished {
			return s, nil
		}
		if time.Now().After(s.d.Deadline) {
			s.finished = true
			s.status = sCrit.Render("Time is up: the automatic rollback has been triggered. Old configuration restored.")
			return s, nil
		}
		return s, tick()
	case tea.KeyMsg:
		if s.finished {
			if m.String() == "enter" || m.String() == "esc" {
				return s, pop()
			}
			return s, nil
		}
		switch m.String() {
		case "c", "C":
			if err := s.c.h.DisarmDeadman(); err != nil {
				s.status = sCrit.Render("disarm failed: " + err.Error())
				return s, nil
			}
			s.finished = true
			if s.onConfirm != nil {
				if next := s.onConfirm(); next != nil {
					return s, next
				}
			}
			s.status = sOK.Render("Confirmed. New configuration kept.")
			return s, nil
		case "r", "R":
			_ = s.c.h.DisarmDeadman()
			rep, err := s.c.h.Restore(s.d.SnapshotID)
			*s.c.st = *system.LoadState()
			s.finished = true
			s.status = sWarn.Render("Rolled back:\n") + sMuted.Render(strings.Join(rep, "\n"))
			if err != nil {
				s.status += "\n" + sCrit.Render(err.Error())
			}
			return s, nil
		}
	}
	return s, nil
}

func (s *deadmanScreen) View() string {
	var b strings.Builder
	left := time.Until(s.d.Deadline).Round(time.Second)
	if left < 0 {
		left = 0
	}
	b.WriteString(sTitle.Render("Dead-man switch armed") + "\n\n")
	b.WriteString(sText.Render("The SSH change is live. DO NOT close this session.") + "\n")
	b.WriteString(sText.Render("Open a NEW terminal and log in again, for example:") + "\n\n")
	port := s.c.st.SSHPort
	if p := sshPortHint(s.c); p > 0 {
		port = p
	}
	b.WriteString("    " + sKey.Render(fmt.Sprintf("ssh -p %d %s@%s", port, system.LoginUser(), hostHint())) + "\n\n")
	b.WriteString(sText.Render("If it works press ") + sKey.Render("c") + sText.Render(" here, or run ") + sKey.Render("vpshield confirm") + sText.Render(" from the new session.") + "\n")
	b.WriteString(sText.Render("If nothing is confirmed, the previous configuration is restored automatically.") + "\n\n")
	if !s.finished {
		bar := 40
		fmt.Fprintf(&b, "%s %s\n", sWarn.Render("rollback in"), sCrit.Render(left.String()))
		filled := int(float64(bar) * left.Seconds() / s.total.Seconds())
		if filled > bar {
			filled = bar
		}
		b.WriteString(sWarn.Render(strings.Repeat("█", filled)) + sMuted.Render(strings.Repeat("░", bar-filled)) + "\n")
		if s.d.Mode == "dry-run" {
			b.WriteString("\n" + sBadge.Render("DRY-RUN") + sMuted.Render(" no real timer was started") + "\n")
		}
	}
	if s.status != "" {
		b.WriteString("\n" + s.status + "\n")
	}
	return b.String()
}

func sshPortHint(c *ctx) int {
	return c.lastSSHPort
}

func hostHint() string {
	if ip := serverIP(); ip != "" {
		return ip
	}
	return system.Hostname()
}

func serverIP() string {
	// SSH_CONNECTION = client_ip client_port server_ip server_port
	f := strings.Fields(os.Getenv("SSH_CONNECTION"))
	if len(f) >= 3 {
		return f[2]
	}
	return ""
}
