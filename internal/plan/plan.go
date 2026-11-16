// Package plan models every change as a reviewable list of steps.
// The TUI shows the plan, asks for confirmation, then executes it inside a
// snapshot so it can be rolled back.
package plan

import (
	"fmt"
	"os"
	"strings"

	"vpshield/internal/system"
)

type Step struct {
	Title    string
	Detail   string // commands or file content shown during review
	Run      func(h *system.Host) (string, error)
	Optional bool // a failure is reported but does not abort the plan
}

type Plan struct {
	Title    string
	Warnings []string
	Steps    []Step
	// Deadman, when > 0, arms an automatic rollback of this plan's snapshot
	// after it succeeds (seconds). Used for SSH changes.
	Deadman int
	// AfterApply runs once all steps succeed (state updates etc.).
	AfterApply func(h *system.Host) error
	// Backups lists files to snapshot before the first step (e.g. firewall
	// state files changed by commands rather than by WriteFile).
	Backups []string
	// RestoreHooks are run when the snapshot is rolled back.
	RestoreHooks [][]string
}

func (p *Plan) Add(s ...Step) { p.Steps = append(p.Steps, s...) }
func (p *Plan) Warn(format string, a ...any) {
	p.Warnings = append(p.Warnings, fmt.Sprintf(format, a...))
}

// Cmd is a step that runs one mutating command.
func Cmd(title string, name string, args ...string) Step {
	return Step{
		Title:  title,
		Detail: "$ " + system.CmdString(name, args...),
		Run:    func(h *system.Host) (string, error) { return h.Run(name, args...) },
	}
}

// OptCmd is like Cmd but a failure does not abort the plan.
func OptCmd(title string, name string, args ...string) Step {
	s := Cmd(title, name, args...)
	s.Optional = true
	return s
}

// File writes content to path (backed up first).
func File(path, content string, perm os.FileMode) Step {
	return Step{
		Title:  "write " + path,
		Detail: preview(content),
		Run: func(h *system.Host) (string, error) {
			return fmt.Sprintf("%d bytes", len(content)), h.WriteFile(path, []byte(content), perm)
		},
	}
}

// Func wraps arbitrary logic.
func Func(title, detail string, fn func(h *system.Host) (string, error)) Step {
	return Step{Title: title, Detail: detail, Run: fn}
}

func Install(h *system.Host, logical string) Step {
	pkgs := h.Distro.Packages(logical)
	return Step{
		Title:  "install " + logical,
		Detail: "packages: " + strings.Join(pkgs, " "),
		Run:    func(h *system.Host) (string, error) { return h.Install(logical) },
	}
}

func EnableService(svc string) Step {
	return Step{
		Title:  "enable & start " + svc,
		Detail: "enable at boot and start now",
		Run:    func(h *system.Host) (string, error) { return h.ServiceEnableNow(svc) },
	}
}

func RestartService(svc string) Step {
	return Step{
		Title: "restart " + svc,
		Run:   func(h *system.Host) (string, error) { return h.ServiceRestart(svc) },
	}
}

func preview(content string) string {
	lines := strings.Split(strings.TrimRight(content, "\n"), "\n")
	if len(lines) > 40 {
		lines = append(lines[:40], fmt.Sprintf("... (%d more lines)", len(lines)-40))
	}
	return strings.Join(lines, "\n")
}

// Result of executing a plan.
type Result struct {
	Step   Step
	Output string
	Err    error
}
