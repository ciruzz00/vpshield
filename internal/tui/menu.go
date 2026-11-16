package tui

import (
	"fmt"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

type menuItem struct {
	label  string
	desc   string
	badge  func() string // optional live status, evaluated on render
	action func() tea.Cmd
}

// menuScreen is a vertical list of actions.
type menuScreen struct {
	c       *ctx
	title   string
	header  func() string // optional block shown above the list
	items   []menuItem
	cursor  int
	root    bool
	onKey   func(k string) tea.Cmd // optional hook (used by the easter egg)
	onFocus func()
	status  string
	offset  int // first visible item when the list is taller than the screen
}

func newMenu(c *ctx, title string, items ...menuItem) *menuScreen {
	return &menuScreen{c: c, title: title, items: items}
}

func (m *menuScreen) Init() tea.Cmd { return nil }
func (m *menuScreen) Title() string { return m.title }
func (m *menuScreen) Help() string {
	back := "back"
	if m.root {
		back = "quit"
	}
	return helpLine("↑↓/jk", "move", "enter", "select", "1-9", "jump", "esc", back)
}

func (m *menuScreen) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch k := msg.(type) {
	case actionDoneMsg:
		m.status = statusText(k.out, k.err)
	case focusMsg:
		if m.onFocus != nil {
			m.onFocus()
		}
	case tea.KeyMsg:
		key := k.String()
		m.status = ""
		if m.onKey != nil {
			if cmd := m.onKey(key); cmd != nil {
				return m, cmd
			}
		}
		switch key {
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			} else {
				m.cursor = len(m.items) - 1
			}
		case "down", "j":
			if m.cursor < len(m.items)-1 {
				m.cursor++
			} else {
				m.cursor = 0
			}
		case "home", "g":
			m.cursor = 0
		case "end", "G":
			m.cursor = len(m.items) - 1
		case "enter", " ", "l", "right":
			if m.root && (key == "l" || key == "right") {
				return m, nil // keeps ←→ free on the home screen ;)
			}
			if it := m.items[m.cursor]; it.action != nil {
				return m, it.action()
			}
		case "esc", "q", "h", "left", "backspace":
			if m.root {
				if key == "q" || key == "esc" {
					return m, tea.Quit
				}
				return m, nil
			}
			return m, pop()
		default:
			if n, err := strconv.Atoi(key); err == nil && n >= 1 && n <= len(m.items) {
				m.cursor = n - 1
				if it := m.items[m.cursor]; it.action != nil {
					return m, it.action()
				}
			}
		}
	}
	return m, nil
}

func (m *menuScreen) View() string {
	var b strings.Builder
	used := 0
	if m.header != nil {
		hd := m.header()
		b.WriteString(hd)
		b.WriteString("\n\n")
		used += strings.Count(hd, "\n") + 2
	}
	if m.status != "" {
		used += 2
	}
	first, last := 0, len(m.items)
	if avail := m.c.height - used; avail >= 3 && len(m.items) > avail {
		rows := avail - 2 // room for the ↑/↓ markers
		if m.cursor < m.offset {
			m.offset = m.cursor
		}
		if m.cursor >= m.offset+rows {
			m.offset = m.cursor - rows + 1
		}
		if m.offset > len(m.items)-rows {
			m.offset = len(m.items) - rows
		}
		first, last = m.offset, m.offset+rows
	}
	labelW := 0
	for _, it := range m.items {
		if len(it.label) > labelW {
			labelW = len(it.label)
		}
	}
	if first > 0 || last < len(m.items) {
		b.WriteString(sMuted.Render(map[bool]string{true: "   ↑ more", false: ""}[first > 0]) + "\n")
	}
	for i := first; i < last; i++ {
		it := m.items[i]
		num := sMuted.Render(fmt.Sprintf("%2d.", i+1))
		label := it.label + strings.Repeat(" ", labelW-len(it.label))
		line := ""
		if i == m.cursor {
			line = sSel.Render("▸ ") + num + " " + sSel.Render(label)
		} else {
			line = "  " + num + " " + sText.Render(label)
		}
		if it.badge != nil {
			line += "  " + it.badge()
		}
		if it.desc != "" && m.c.width > labelW+30 {
			line += "  " + sMuted.Render(truncate(it.desc, m.c.width-labelW-24))
		}
		b.WriteString(line + "\n")
	}
	if first > 0 || last < len(m.items) {
		b.WriteString(sMuted.Render(map[bool]string{true: "   ↓ more", false: ""}[last < len(m.items)]) + "\n")
	}
	if m.status != "" {
		b.WriteString("\n" + m.status + "\n")
	}
	return b.String()
}
