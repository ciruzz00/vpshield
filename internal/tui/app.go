// Package tui is the Bubbletea interface of vpshield.
package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"vpshield/internal/system"
)

// Screen is one page of the interface.
type Screen interface {
	tea.Model
	Title() string
	Help() string
}

// navigation messages
type pushMsg struct{ s Screen }
type popMsg struct{ n int }
type replaceMsg struct{ s Screen }
type focusMsg struct{} // sent to the screen that becomes visible again after a pop

func push(s Screen) tea.Cmd    { return func() tea.Msg { return pushMsg{s} } }
func pop() tea.Cmd             { return func() tea.Msg { return popMsg{1} } }
func popN(n int) tea.Cmd       { return func() tea.Msg { return popMsg{n} } }
func replace(s Screen) tea.Cmd { return func() tea.Msg { return replaceMsg{s} } }

// ctx is shared by every screen.
type ctx struct {
	h      *system.Host
	st     *system.State
	width  int
	height int // height available to a screen body
	// lastSSHPort is the port being tested on the dead-man screen
	lastSSHPort int
}

type App struct {
	c     *ctx
	stack []Screen
	w, h  int
}

// Run starts the TUI.
func Run(h *system.Host, st *system.State) error {
	c := &ctx{h: h, st: st, width: 80, height: 20}
	app := &App{c: c}
	app.stack = []Screen{newHome(c)}
	p := tea.NewProgram(app, tea.WithAltScreen())
	_, err := p.Run()
	return err
}

func (a *App) top() Screen { return a.stack[len(a.stack)-1] }

func (a *App) Init() tea.Cmd { return a.top().Init() }

func (a *App) sizeMsg() tea.WindowSizeMsg {
	return tea.WindowSizeMsg{Width: a.c.width, Height: a.c.height}
}

func (a *App) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch m := msg.(type) {
	case tea.WindowSizeMsg:
		a.w, a.h = m.Width, m.Height
		a.c.width = m.Width - 2
		a.c.height = m.Height - 5 // header (2) + crumb (1) + footer (2)
		if a.c.height < 5 {
			a.c.height = 5
		}
		var cmds []tea.Cmd
		for i, s := range a.stack {
			ns, cmd := s.Update(a.sizeMsg())
			a.stack[i] = ns.(Screen)
			cmds = append(cmds, cmd)
		}
		return a, tea.Batch(cmds...)
	case tea.KeyMsg:
		if m.String() == "ctrl+c" {
			return a, tea.Quit
		}
	case pushMsg:
		a.stack = append(a.stack, m.s)
		ns, cmd := m.s.Update(a.sizeMsg())
		a.stack[len(a.stack)-1] = ns.(Screen)
		return a, tea.Batch(ns.Init(), cmd)
	case replaceMsg:
		a.stack[len(a.stack)-1] = m.s
		ns, cmd := m.s.Update(a.sizeMsg())
		a.stack[len(a.stack)-1] = ns.(Screen)
		return a, tea.Batch(ns.Init(), cmd)
	case popMsg:
		n := m.n
		if n >= len(a.stack) {
			n = len(a.stack) - 1
		}
		if n <= 0 {
			return a, nil
		}
		a.stack = a.stack[:len(a.stack)-n]
		ns, cmd := a.top().Update(focusMsg{})
		a.stack[len(a.stack)-1] = ns.(Screen)
		return a, cmd
	}
	ns, cmd := a.top().Update(msg)
	a.stack[len(a.stack)-1] = ns.(Screen)
	return a, cmd
}

func (a *App) View() string {
	d := a.c.h.Distro
	left := sLogo.Render("vpshield") + " " + sText.Render(system.Hostname()) + sMuted.Render("  "+d.Name+" · "+string(d.Init))
	right := ""
	if a.c.h.DryRun {
		right = sBadge.Render("DRY-RUN")
	}
	if !system.IsRoot() {
		right += " " + sCrit.Render("not root: read-only views only")
	}
	gap := a.w - lipgloss.Width(left) - lipgloss.Width(right) - 2
	if gap < 1 {
		gap = 1
	}
	header := " " + left + strings.Repeat(" ", gap) + right

	var crumbs []string
	for _, s := range a.stack {
		crumbs = append(crumbs, s.Title())
	}
	crumb := " " + sCrumb.Render(strings.Join(crumbs, " › "))

	body := lipgloss.NewStyle().MaxHeight(a.c.height).MaxWidth(a.w - 1).Render(a.top().View())
	bodyLines := lipgloss.Height(body)
	pad := ""
	if bodyLines < a.c.height {
		pad = strings.Repeat("\n", a.c.height-bodyLines)
	}
	footer := " " + a.top().Help() + sHelp.Render("  ·  ") + sKey.Render("ctrl+c") + sHelp.Render(" quit")
	return fmt.Sprintf("%s\n\n%s\n%s%s\n%s", header, crumb, indent(body, 1), pad, footer)
}

func indent(s string, n int) string {
	p := strings.Repeat(" ", n)
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = p + l
	}
	return strings.Join(lines, "\n")
}
