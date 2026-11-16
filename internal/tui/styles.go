package tui

import (
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
)

var (
	cAccent  = lipgloss.Color("#00D7AF")
	cAccent2 = lipgloss.Color("#5FAFFF")
	cWarn    = lipgloss.Color("#FFAF00")
	cCrit    = lipgloss.Color("#FF5F5F")
	cOK      = lipgloss.Color("#5FD75F")
	cMuted   = lipgloss.Color("#767676")
	cText    = lipgloss.Color("#D0D0D0")

	sTitle = lipgloss.NewStyle().Bold(true).Foreground(cAccent)
	sLogo  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#0A0A0A")).Background(cAccent).Padding(0, 1)
	sBadge = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#0A0A0A")).Background(cWarn).Padding(0, 1)
	sMuted = lipgloss.NewStyle().Foreground(cMuted)
	sText  = lipgloss.NewStyle().Foreground(cText)
	sOK    = lipgloss.NewStyle().Foreground(cOK)
	sWarn  = lipgloss.NewStyle().Foreground(cWarn)
	sCrit  = lipgloss.NewStyle().Foreground(cCrit).Bold(true)
	sInfo  = lipgloss.NewStyle().Foreground(cAccent2)
	sSel   = lipgloss.NewStyle().Foreground(cAccent).Bold(true)
	sBox   = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(cMuted).Padding(0, 1)
	sHelp  = lipgloss.NewStyle().Foreground(cMuted)
	sKey   = lipgloss.NewStyle().Foreground(cAccent)
	sCrumb = lipgloss.NewStyle().Foreground(cAccent2)
)

func dot(ok bool) string {
	if ok {
		return sOK.Render("●")
	}
	return sCrit.Render("●")
}

func onOff(ok bool, on, off string) string {
	if ok {
		return sOK.Render(on)
	}
	return sCrit.Render(off)
}

// helpLine renders "k action · k action".
func helpLine(pairs ...string) string {
	var parts []string
	for i := 0; i+1 < len(pairs); i += 2 {
		parts = append(parts, sKey.Render(pairs[i])+" "+sHelp.Render(pairs[i+1]))
	}
	return strings.Join(parts, sHelp.Render("  ·  "))
}

func formTheme() *huh.Theme {
	t := huh.ThemeCharm()
	t.Focused.Title = t.Focused.Title.Foreground(cAccent)
	t.Focused.SelectSelector = t.Focused.SelectSelector.Foreground(cAccent)
	t.Focused.MultiSelectSelector = t.Focused.MultiSelectSelector.Foreground(cAccent)
	t.Focused.SelectedOption = t.Focused.SelectedOption.Foreground(cAccent)
	t.Focused.SelectedPrefix = t.Focused.SelectedPrefix.Foreground(cAccent)
	t.Focused.FocusedButton = t.Focused.FocusedButton.Background(cAccent).Foreground(lipgloss.Color("#0A0A0A"))
	t.Focused.Base = t.Focused.Base.BorderForeground(cAccent)
	return t
}

func truncate(s string, n int) string {
	if n <= 1 {
		return ""
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
