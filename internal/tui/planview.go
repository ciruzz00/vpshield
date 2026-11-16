package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"

	"vpshield/internal/plan"
	"vpshield/internal/system"
)

type planPhase int

const (
	phaseReview planPhase = iota
	phaseRunning
	phaseDone
)

type stepDoneMsg struct {
	idx int
	out string
	err error
}

type rollbackDoneMsg struct {
	report []string
	err    error
}

// planScreen: review -> apply -> result. Every apply runs in a snapshot and
// a failure of a required step rolls the snapshot back automatically.
type planScreen struct {
	c       *ctx
	p       *plan.Plan
	phase   planPhase
	details bool
	results []plan.Result
	current int
	failed  bool
	snap    *system.Snapshot
	rolled  []string
	vp      viewport.Model
	spin    spinner.Model
	// onSuccess may return the next navigation (e.g. dead-man screen).
	onSuccess func() tea.Cmd
	nextCmd   tea.Cmd
}

func newPlan(c *ctx, p *plan.Plan, onSuccess func() tea.Cmd) *planScreen {
	sp := spinner.New()
	sp.Spinner = spinner.MiniDot
	sp.Style = sSel
	ps := &planScreen{c: c, p: p, details: true, spin: sp, onSuccess: onSuccess}
	ps.vp = viewport.New(c.width, c.height-2)
	return ps
}

func (s *planScreen) Title() string { return s.p.Title }

func (s *planScreen) Help() string {
	switch s.phase {
	case phaseReview:
		if len(s.p.Steps) == 0 {
			return helpLine("esc", "back")
		}
		return helpLine("y/enter", "apply", "d", "toggle details", "↑↓", "scroll", "esc", "cancel")
	case phaseRunning:
		return sMuted.Render("applying…")
	}
	if s.nextCmd != nil {
		return helpLine("enter", "continue", "↑↓", "scroll")
	}
	return helpLine("enter/esc", "back", "↑↓", "scroll")
}

func (s *planScreen) Init() tea.Cmd { s.refresh(); return nil }

func (s *planScreen) runStep(i int) tea.Cmd {
	st := s.p.Steps[i]
	h := s.c.h
	return func() tea.Msg {
		out, err := st.Run(h)
		return stepDoneMsg{idx: i, out: out, err: err}
	}
}

func (s *planScreen) start() tea.Cmd {
	s.phase = phaseRunning
	h := s.c.h
	s.snap = h.BeginSnapshot(s.p.Title)
	for _, f := range s.p.Backups {
		_ = h.Backup(f)
	}
	for _, hk := range s.p.RestoreHooks {
		h.AddRestoreHook(hk...)
	}
	s.refresh()
	return tea.Batch(s.spin.Tick, s.runStep(0))
}

func (s *planScreen) finish() tea.Cmd {
	h := s.c.h
	snap := h.EndSnapshot()
	if s.failed {
		s.phase = phaseDone
		if snap != nil {
			id := snap.ID
			s.refresh()
			return func() tea.Msg {
				rep, err := h.Restore(id)
				return rollbackDoneMsg{rep, err}
			}
		}
		s.refresh()
		return nil
	}
	if s.p.AfterApply != nil {
		if err := s.p.AfterApply(h); err != nil {
			s.results = append(s.results, plan.Result{Step: plan.Step{Title: "save state"}, Err: err})
		}
	}
	s.phase = phaseDone
	if s.p.Deadman > 0 {
		id := "dry-run"
		if snap != nil {
			id = snap.ID
		}
		d, err := h.ArmDeadman(id, time.Duration(s.p.Deadman)*time.Second, s.p.Title)
		if err != nil {
			s.results = append(s.results, plan.Result{Step: plan.Step{Title: "arm dead-man switch"}, Err: err})
		} else {
			s.nextCmd = replace(newDeadman(s.c, d, s.onSuccess))
			s.refresh()
			return s.nextCmd
		}
	}
	if s.onSuccess != nil {
		s.nextCmd = s.onSuccess()
	}
	s.refresh()
	return nil
}

func (s *planScreen) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch m := msg.(type) {
	case tea.WindowSizeMsg:
		s.vp.Width, s.vp.Height = m.Width, m.Height-1
		s.refresh()
	case spinner.TickMsg:
		if s.phase == phaseRunning {
			var cmd tea.Cmd
			s.spin, cmd = s.spin.Update(m)
			s.refresh()
			return s, cmd
		}
	case stepDoneMsg:
		st := s.p.Steps[m.idx]
		s.results = append(s.results, plan.Result{Step: st, Output: m.out, Err: m.err})
		if m.err != nil && !st.Optional {
			s.failed = true
			return s, s.finish()
		}
		if m.idx+1 < len(s.p.Steps) {
			s.current = m.idx + 1
			s.refresh()
			return s, s.runStep(m.idx + 1)
		}
		return s, s.finish()
	case rollbackDoneMsg:
		*s.c.st = *system.LoadState()
		s.rolled = m.report
		if m.err != nil {
			s.rolled = append(s.rolled, "ROLLBACK ERROR: "+m.err.Error())
		}
		s.refresh()
	case tea.KeyMsg:
		switch s.phase {
		case phaseReview:
			switch m.String() {
			case "y", "enter":
				if len(s.p.Steps) == 0 {
					return s, pop()
				}
				if !system.IsRoot() && !s.c.h.DryRun {
					s.p.Warnings = append([]string{"you must run vpshield as root to apply changes (or use --dry-run)"}, s.p.Warnings...)
					s.refresh()
					return s, nil
				}
				return s, s.start()
			case "d":
				s.details = !s.details
				s.refresh()
			case "esc", "n", "q":
				return s, pop()
			}
		case phaseDone:
			switch m.String() {
			case "enter", "esc", "q":
				if s.nextCmd != nil && !s.failed {
					return s, s.nextCmd
				}
				return s, pop()
			}
		}
	}
	var cmd tea.Cmd
	s.vp, cmd = s.vp.Update(msg)
	return s, cmd
}

func (s *planScreen) refresh() {
	var b strings.Builder
	if s.c.h.DryRun {
		b.WriteString(sBadge.Render("DRY-RUN") + sWarn.Render(" nothing will be changed, commands are only logged") + "\n\n")
	}
	for _, w := range s.p.Warnings {
		b.WriteString(sCrit.Render("⚠ ") + sWarn.Render(w) + "\n")
	}
	if len(s.p.Warnings) > 0 {
		b.WriteString("\n")
	}
	if len(s.p.Steps) == 0 {
		b.WriteString(sMuted.Render("nothing to do"))
	}
	for i, st := range s.p.Steps {
		mark := sMuted.Render("○")
		var res *plan.Result
		if i < len(s.results) {
			res = &s.results[i]
		}
		switch {
		case res != nil && res.Err == nil:
			mark = sOK.Render("✓")
		case res != nil && st.Optional:
			mark = sWarn.Render("!")
		case res != nil:
			mark = sCrit.Render("✗")
		case s.phase == phaseRunning && i == s.current:
			mark = s.spin.View()
		}
		title := st.Title
		if st.Optional {
			title += sMuted.Render(" (optional)")
		}
		fmt.Fprintf(&b, "%s %s\n", mark, title)
		if s.phase == phaseReview && s.details && st.Detail != "" {
			b.WriteString(indent(sMuted.Render(st.Detail), 4) + "\n")
		}
		if res != nil {
			if res.Err != nil {
				b.WriteString(indent(sCrit.Render(res.Err.Error()), 4) + "\n")
			} else if o := strings.TrimSpace(res.Output); o != "" && (s.c.h.DryRun || len(o) < 300) {
				b.WriteString(indent(sMuted.Render(lastLinesN(o, 4)), 4) + "\n")
			}
		}
	}
	// extra results (state save, dead-man errors)
	for _, r := range s.results[min(len(s.results), len(s.p.Steps)):] {
		fmt.Fprintf(&b, "%s %s: %v\n", sCrit.Render("✗"), r.Step.Title, r.Err)
	}
	if s.phase == phaseDone {
		b.WriteString("\n")
		if s.failed {
			b.WriteString(sCrit.Render("Plan failed: changes are being rolled back automatically.") + "\n")
			for _, l := range s.rolled {
				b.WriteString(indent(sMuted.Render(l), 2) + "\n")
			}
		} else {
			msg := "Done."
			if s.snap != nil && !s.c.h.DryRun {
				msg += sMuted.Render(" Snapshot " + s.snap.ID + " (Backups & rollback to undo)")
			}
			b.WriteString(sOK.Render(msg) + "\n")
		}
	}
	if s.phase == phaseReview && len(s.p.Steps) > 0 {
		b.WriteString("\n" + sTitle.Render("Apply this plan? ") + sKey.Render("[y]") + sMuted.Render("es / ") + sKey.Render("[n]") + sMuted.Render("o"))
	}
	s.vp.SetContent(b.String())
	if s.phase != phaseReview {
		s.vp.GotoBottom()
	}
}

func (s *planScreen) View() string { return s.vp.View() }

func lastLinesN(s string, n int) string {
	l := strings.Split(s, "\n")
	if len(l) > n {
		l = append([]string{"…"}, l[len(l)-n:]...)
	}
	return strings.Join(l, "\n")
}
