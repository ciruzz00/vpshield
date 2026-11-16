package tui

import (
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ---- async helpers --------------------------------------------------------

type loadedMsg struct {
	id   *int // identity of the requesting screen
	text string
	rows []table.Row
	err  error
}

type actionDoneMsg struct {
	out string
	err error
}

// action runs fn off the UI goroutine and reports back.
func action(fn func() (string, error)) tea.Cmd {
	return func() tea.Msg {
		out, err := fn()
		return actionDoneMsg{out, err}
	}
}

// ---- text screen ----------------------------------------------------------

type textKey struct {
	key, help string
	fn        func() tea.Cmd
}

// textScreen shows (and refreshes) a block of text.
type textScreen struct {
	c       *ctx
	title   string
	loader  func() string
	keys    []textKey
	vp      viewport.Model
	spin    spinner.Model
	loading bool
	status  string
	ident   int
}

func newText(c *ctx, title string, loader func() string, keys ...textKey) *textScreen {
	sp := spinner.New()
	sp.Spinner = spinner.MiniDot
	sp.Style = sSel
	t := &textScreen{c: c, title: title, loader: loader, keys: keys, spin: sp}
	t.vp = viewport.New(c.width, c.height-1)
	return t
}

func (t *textScreen) Title() string { return t.title }
func (t *textScreen) Help() string {
	pairs := []string{"↑↓/pgup/pgdn", "scroll", "r", "refresh"}
	for _, k := range t.keys {
		pairs = append(pairs, k.key, k.help)
	}
	return helpLine(append(pairs, "esc", "back")...)
}

func (t *textScreen) load() tea.Cmd {
	t.loading = true
	id := &t.ident
	return tea.Batch(t.spin.Tick, func() tea.Msg { return loadedMsg{id: id, text: t.loader()} })
}

func (t *textScreen) Init() tea.Cmd { return t.load() }

func (t *textScreen) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch m := msg.(type) {
	case tea.WindowSizeMsg:
		t.vp.Width, t.vp.Height = m.Width, m.Height-1
	case focusMsg:
		return t, t.load()
	case spinner.TickMsg:
		if t.loading {
			var cmd tea.Cmd
			t.spin, cmd = t.spin.Update(m)
			return t, cmd
		}
		return t, nil
	case loadedMsg:
		if m.id != &t.ident {
			return t, nil
		}
		t.loading = false
		t.vp.SetContent(m.text)
		return t, nil
	case actionDoneMsg:
		t.status = statusText(m.out, m.err)
		return t, t.load()
	case tea.KeyMsg:
		switch m.String() {
		case "esc", "q", "left", "h":
			return t, pop()
		case "r":
			t.status = ""
			return t, t.load()
		}
		for _, k := range t.keys {
			if m.String() == k.key {
				return t, k.fn()
			}
		}
	}
	var cmd tea.Cmd
	t.vp, cmd = t.vp.Update(msg)
	return t, cmd
}

func (t *textScreen) View() string {
	top := ""
	if t.loading {
		top = t.spin.View() + sMuted.Render(" loading…")
	} else if t.status != "" {
		top = t.status
	}
	return top + "\n" + t.vp.View()
}

func statusText(out string, err error) string {
	if err != nil {
		return sCrit.Render("✗ " + firstLine(err.Error()))
	}
	if out == "" {
		out = "done"
	}
	return sOK.Render("✓ " + firstLine(out))
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "\n"); i >= 0 {
		return s[:i]
	}
	return s
}

// ---- table screen ---------------------------------------------------------

type tableKey struct {
	key, help string
	// fn receives the selected row (nil when the table is empty).
	fn func(row table.Row) tea.Cmd
	// needRow: ignore the key when nothing is selected
	needRow bool
}

type tableScreen struct {
	c       *ctx
	title   string
	cols    []table.Column
	loader  func() ([]table.Row, error)
	keys    []tableKey
	header  func() string
	t       table.Model
	spin    spinner.Model
	loading bool
	status  string
	err     error
	ident   int
}

func newTable(c *ctx, title string, cols []table.Column, loader func() ([]table.Row, error), keys ...tableKey) *tableScreen {
	t := table.New(table.WithColumns(cols), table.WithFocused(true), table.WithHeight(c.height-3))
	st := table.DefaultStyles()
	st.Header = st.Header.BorderStyle(lipgloss.NormalBorder()).BorderForeground(cMuted).BorderBottom(true).Bold(true).Foreground(cAccent)
	st.Selected = st.Selected.Foreground(lipgloss.Color("#0A0A0A")).Background(cAccent).Bold(false)
	t.SetStyles(st)
	sp := spinner.New()
	sp.Spinner = spinner.MiniDot
	sp.Style = sSel
	return &tableScreen{c: c, title: title, cols: cols, loader: loader, keys: keys, t: t, spin: sp}
}

func (s *tableScreen) Title() string { return s.title }
func (s *tableScreen) Help() string {
	pairs := []string{}
	for _, k := range s.keys {
		pairs = append(pairs, k.key, k.help)
	}
	return helpLine(append(pairs, "r", "refresh", "esc", "back")...)
}

func (s *tableScreen) load() tea.Cmd {
	s.loading = true
	id := &s.ident
	return tea.Batch(s.spin.Tick, func() tea.Msg {
		rows, err := s.loader()
		return loadedMsg{id: id, rows: rows, err: err}
	})
}

func (s *tableScreen) Init() tea.Cmd { return s.load() }

func (s *tableScreen) resize(w, h int) {
	s.t.SetWidth(w)
	extra := 3
	if s.header != nil {
		extra += lipgloss.Height(s.header()) + 1
	}
	s.t.SetHeight(h - extra)
	// stretch the last column to fill the width
	total := 0
	for _, c := range s.cols[:len(s.cols)-1] {
		total += c.Width + 2
	}
	cols := append([]table.Column(nil), s.cols...)
	if last := w - total - 4; last > cols[len(cols)-1].Width {
		cols[len(cols)-1].Width = last
	}
	s.t.SetColumns(cols)
}

func (s *tableScreen) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch m := msg.(type) {
	case tea.WindowSizeMsg:
		s.resize(m.Width, m.Height)
		return s, nil
	case focusMsg:
		return s, s.load()
	case spinner.TickMsg:
		if s.loading {
			var cmd tea.Cmd
			s.spin, cmd = s.spin.Update(m)
			return s, cmd
		}
		return s, nil
	case loadedMsg:
		if m.id != &s.ident {
			return s, nil
		}
		s.loading = false
		s.err = m.err
		cur := s.t.Cursor()
		s.t.SetRows(m.rows)
		if cur >= len(m.rows) {
			cur = len(m.rows) - 1
		}
		if cur < 0 {
			cur = 0
		}
		s.t.SetCursor(cur)
		s.resize(s.c.width, s.c.height)
		return s, nil
	case actionDoneMsg:
		s.status = statusText(m.out, m.err)
		return s, s.load()
	case tea.KeyMsg:
		switch m.String() {
		case "esc", "q", "left", "h":
			return s, pop()
		case "r":
			s.status = ""
			return s, s.load()
		}
		for _, k := range s.keys {
			if m.String() == k.key {
				row := s.t.SelectedRow()
				if k.needRow && row == nil {
					return s, nil
				}
				s.status = ""
				return s, k.fn(row)
			}
		}
	}
	var cmd tea.Cmd
	s.t, cmd = s.t.Update(msg)
	return s, cmd
}

func (s *tableScreen) View() string {
	var b strings.Builder
	if s.header != nil {
		b.WriteString(s.header() + "\n\n")
	}
	b.WriteString(s.t.View() + "\n")
	switch {
	case s.loading:
		b.WriteString(s.spin.View() + sMuted.Render(" loading…"))
	case s.err != nil:
		b.WriteString(sCrit.Render("✗ " + s.err.Error()))
	case s.status != "":
		b.WriteString(s.status)
	case len(s.t.Rows()) == 0:
		b.WriteString(sMuted.Render("(empty)"))
	}
	return b.String()
}
