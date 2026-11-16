package tui

import (
	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
)

// formScreen hosts a huh form. onDone runs after submit and returns the next
// navigation (usually replace(planScreen)).
type formScreen struct {
	c      *ctx
	title  string
	form   *huh.Form
	onDone func() tea.Cmd
	done   bool
}

func newForm(c *ctx, title string, onDone func() tea.Cmd, groups ...*huh.Group) *formScreen {
	km := huh.NewDefaultKeyMap()
	km.Quit = key.NewBinding(key.WithKeys("esc"), key.WithHelp("esc", "cancel"))
	f := huh.NewForm(groups...).
		WithTheme(formTheme()).
		WithKeyMap(km).
		WithShowHelp(true).
		WithShowErrors(true)
	return &formScreen{c: c, title: title, form: f, onDone: onDone}
}

func (f *formScreen) Title() string { return f.title }
func (f *formScreen) Help() string {
	return helpLine("tab/enter", "next", "shift+tab", "prev", "esc", "cancel")
}
func (f *formScreen) Init() tea.Cmd { return f.form.Init() }

func (f *formScreen) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if f.done {
		return f, nil
	}
	if ws, ok := msg.(tea.WindowSizeMsg); ok {
		w := ws.Width
		if w > 100 {
			w = 100
		}
		f.form = f.form.WithWidth(w).WithHeight(ws.Height)
	}
	m, cmd := f.form.Update(msg)
	if ff, ok := m.(*huh.Form); ok {
		f.form = ff
	}
	switch f.form.State {
	case huh.StateAborted:
		f.done = true
		return f, pop()
	case huh.StateCompleted:
		f.done = true
		if f.onDone == nil {
			return f, pop()
		}
		next := f.onDone()
		if next == nil {
			return f, pop()
		}
		return f, next
	}
	return f, cmd
}

func (f *formScreen) View() string { return f.form.View() }

// confirmScreen asks yes/no and runs fn on yes.
func confirmScreen(c *ctx, title, question, desc string, fn func() tea.Cmd) Screen {
	ok := false
	return newForm(c, title, func() tea.Cmd {
		if !ok {
			return pop()
		}
		return fn()
	}, huh.NewGroup(
		huh.NewConfirm().Title(question).Description(desc).Affirmative("Yes").Negative("No").Value(&ok),
	))
}
