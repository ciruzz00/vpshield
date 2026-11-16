package tui

// HackThePlan

import (
	"math/rand"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var konami = []string{"up", "up", "down", "down", "left", "right", "left", "right", "b", "a"}

// konamiTracker returns true when the full sequence has been typed.
type konamiTracker struct{ pos int }

func (k *konamiTracker) feed(key string) bool {
	if key == konami[k.pos] {
		k.pos++
		if k.pos == len(konami) {
			k.pos = 0
			return true
		}
		return false
	}
	k.pos = 0
	if key == konami[0] {
		k.pos = 1
	}
	return false
}

func bannerHTP() []string {
	// "HackThePlan" in a box-drawing figlet style, built per letter so the
	// columns always line up.
	letters := [][3]string{
		{"╦ ╦", "╠═╣", "╩ ╩"}, // H
		{"┌─┐", "├─┤", "┴ ┴"}, // a
		{"┌─┐", "│  ", "└─┘"}, // c
		{"┬┌─", "├┴┐", "┴ ┴"}, // k
		{"╔╦╗", " ║ ", " ╩ "}, // T
		{"┬ ┬", "├─┤", "┴ ┴"}, // h
		{"┌─┐", "├┤ ", "└─┘"}, // e
		{"╔═╗", "╠═╝", "╩  "}, // P
		{"┬  ", "│  ", "┴─┘"}, // l
		{"┌─┐", "├─┤", "┴ ┴"}, // a
		{"┌┐┌", "│││", "┘└┘"}, // n
	}
	rows := make([]string, 3)
	for _, l := range letters {
		for i := 0; i < 3; i++ {
			rows[i] += l[i]
		}
	}
	return rows
}

type eggTick struct{}

type eggScreen struct {
	c     *ctx
	drops []int
	speed []int
	frame int
	rnd   *rand.Rand
}

const glyphs = "ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄ0123456789ABCDEF<>/{}$#"

func newEgg(c *ctx) *eggScreen {
	return &eggScreen{c: c, rnd: rand.New(rand.NewSource(time.Now().UnixNano()))}
}

func (e *eggScreen) Title() string { return "???" }
func (e *eggScreen) Help() string  { return helpLine("any key", "back to work") }

func (e *eggScreen) Init() tea.Cmd { return e.tick() }

func (e *eggScreen) tick() tea.Cmd {
	return tea.Tick(70*time.Millisecond, func(time.Time) tea.Msg { return eggTick{} })
}

func (e *eggScreen) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg.(type) {
	case eggTick:
		e.frame++
		e.step()
		return e, e.tick()
	case tea.KeyMsg:
		return e, pop()
	}
	return e, nil
}

func (e *eggScreen) step() {
	w := e.c.width
	if len(e.drops) != w {
		e.drops = make([]int, w)
		e.speed = make([]int, w)
		for i := range e.drops {
			e.drops[i] = -e.rnd.Intn(e.c.height * 2)
			e.speed[i] = 1 + e.rnd.Intn(2)
		}
	}
	for i := range e.drops {
		if e.frame%e.speed[i] == 0 {
			e.drops[i]++
		}
		if e.drops[i] > e.c.height+12 {
			e.drops[i] = -e.rnd.Intn(e.c.height)
		}
	}
}

func (e *eggScreen) View() string {
	w, h := e.c.width, e.c.height
	if len(e.drops) != w || w < 40 || h < 10 {
		return sTitle.Render("HackThePlan")
	}
	g := []rune(glyphs)
	head := lipgloss.NewStyle().Foreground(lipgloss.Color("#E0FFE0")).Bold(true)
	bright := lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF66"))
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("#006622"))

	banner := bannerHTP()
	tag := []string{"", "  stay root, stay humble  ", "", "  [ any key ]  "}
	bw := lipgloss.Width(banner[0]) + 4
	bh := len(banner) + len(tag) + 2
	bx, by := (w-bw)/2, (h-bh)/2

	var b strings.Builder
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			if y >= by && y < by+bh && x >= bx && x < bx+bw {
				if x == bx {
					b.WriteString(e.boxLine(y-by, banner, tag, bw))
				}
				continue
			}
			d := y - e.drops[x]
			switch {
			case d == 0:
				b.WriteString(head.Render(string(g[e.rnd.Intn(len(g))])))
			case d > 0 && d < 4:
				b.WriteString(bright.Render(string(g[(x*7+y*3+e.frame/3)%len(g)])))
			case d >= 4 && d < 12:
				b.WriteString(dim.Render(string(g[(x*5+y+e.frame/5)%len(g)])))
			default:
				b.WriteString(" ")
			}
		}
		if y < h-1 {
			b.WriteString("\n")
		}
	}
	return b.String()
}

func (e *eggScreen) boxLine(row int, banner, tag []string, bw int) string {
	box := lipgloss.NewStyle().Foreground(cAccent)
	inner := bw - 2
	center := func(s string) string {
		pad := inner - lipgloss.Width(s)
		l := pad / 2
		return strings.Repeat(" ", l) + s + strings.Repeat(" ", pad-l)
	}
	switch {
	case row == 0:
		return box.Render("╭" + strings.Repeat("─", inner) + "╮")
	case row == len(banner)+len(tag)+1:
		return box.Render("╰" + strings.Repeat("─", inner) + "╯")
	case row-1 < len(banner):
		return box.Render("│") + sSel.Render(center(banner[row-1])) + box.Render("│")
	default:
		return box.Render("│") + sMuted.Render(center(tag[row-1-len(banner)])) + box.Render("│")
	}
}
