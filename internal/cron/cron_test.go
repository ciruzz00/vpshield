package cron

import (
	"strings"
	"testing"

	"vpshield/internal/system"
)

func TestRoundTrip(t *testing.T) {
	jobs := []Job{{ID: "audit", Schedule: "15 6 * * *", Command: "/usr/local/bin/vpshield audit --save", Comment: "daily audit"},
		{ID: "boot", Schedule: "@reboot", Command: "echo hi", Comment: "x"}}
	for _, withUser := range []bool{true, false} {
		got := Parse(Render(jobs, withUser), withUser)
		if len(got) != 2 || got[0] != jobs[0] || got[1] != jobs[1] {
			t.Fatalf("withUser=%v: %+v", withUser, got)
		}
	}
}

func TestValidate(t *testing.T) {
	good := []string{"* * * * *", "*/15 * * * *", "0 3 * * 1-5", "0 0 1,15 * *", "30 4 * * sun", "@daily"}
	bad := []string{"* * * *", "60 * * * *", "0 24 * * *", "0 0 0 * *", "a b c d e", "@sometimes"}
	for _, g := range good {
		if err := Validate(g); err != nil {
			t.Errorf("%q: %v", g, err)
		}
	}
	for _, b := range bad {
		if Validate(b) == nil {
			t.Errorf("%q accepted", b)
		}
	}
}

func TestAlpineBlock(t *testing.T) {
	h := &system.Host{Distro: system.Distro{Family: system.FamilyAlpine}}
	_ = h
	cur := "*/15 * * * * run-parts /etc/periodic/15min\n"
	block := blockBegin + "\n" + Render([]Job{{ID: "a", Schedule: "@daily", Command: "x"}}, false) + blockEnd + "\n"
	merged := strings.TrimRight(cur, "\n") + "\n\n" + block
	if got := Parse(extractBlock(merged), false); len(got) != 1 || got[0].Command != "x" {
		t.Fatalf("%+v", got)
	}
	if EscapePercent("date +%F") != `date +\%F` || EscapePercent(`a\%b`) != `a\%b` {
		t.Fatal("percent escaping")
	}
}
