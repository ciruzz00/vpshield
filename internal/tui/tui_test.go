package tui

import (
	"testing"

	"github.com/charmbracelet/lipgloss"
)

func TestKonami(t *testing.T) {
	var k konamiTracker
	seq := append([]string{"up", "x"}, konami...)
	hit := false
	for _, s := range seq {
		if k.feed(s) {
			hit = true
		}
	}
	if !hit {
		t.Fatal("sequence not detected")
	}
}

func TestBannerAligned(t *testing.T) {
	b := bannerHTP()
	w := lipgloss.Width(b[0])
	for _, l := range b {
		if lipgloss.Width(l) != w {
			t.Fatalf("misaligned banner: %q", l)
		}
	}
}
