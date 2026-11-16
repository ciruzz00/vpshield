package tui

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"

	"vpshield/internal/audit"
	"vpshield/internal/cron"
	"vpshield/internal/sysctl"
	"vpshield/internal/system"
	"vpshield/internal/updates"
)

// ---- cron -----------------------------------------------------------------

func cronMenu(c *ctx) Screen {
	return newMenu(c, "Cron jobs",
		menuItem{label: "vpshield jobs", desc: "jobs managed by vpshield (" + cron.Path(c.h) + ")", action: func() tea.Cmd { return push(cronJobs(c)) }},
		menuItem{label: "Add job", desc: "from a preset or custom", action: func() tea.Cmd { return push(cronAddForm(c)) }},
		menuItem{label: "All system jobs", desc: "crontab, cron.d, root crontab, systemd timers (read only)", action: func() tea.Cmd {
			return push(newText(c, "System cron", func() string { return cron.SystemListing(c.h) }))
		}},
	)
}

func cronJobs(c *ctx) Screen {
	cols := []table.Column{{Title: "ID", Width: 16}, {Title: "Schedule", Width: 14}, {Title: "Description", Width: 30}, {Title: "Command", Width: 30}}
	loader := func() ([]table.Row, error) {
		var rows []table.Row
		for _, j := range cron.Load(c.h) {
			rows = append(rows, table.Row{j.ID, j.Schedule, j.Comment, j.Command})
		}
		return rows, nil
	}
	return newTable(c, "vpshield jobs", cols, loader,
		tableKey{key: "a", help: "add", fn: func(table.Row) tea.Cmd { return push(cronAddForm(c)) }},
		tableKey{key: "d", help: "delete", needRow: true, fn: func(row table.Row) tea.Cmd {
			var keep []cron.Job
			for _, j := range cron.Load(c.h) {
				if j.ID != row[0] {
					keep = append(keep, j)
				}
			}
			return push(newPlan(c, cron.SavePlan(c.h, keep, "Delete cron job "+row[0]), nil))
		}},
	)
}

func cronAddForm(c *ctx) Screen {
	presets := cron.Presets(c.h)
	choice := presets[0].ID
	sched := "preset"
	var custom, command, comment string
	var opts []huh.Option[string]
	for _, p := range presets {
		if p.Available(c.h) {
			opts = append(opts, huh.NewOption(p.Name, p.ID))
		}
	}
	opts = append(opts, huh.NewOption("Custom command", "custom"))
	presetByID := func(id string) (cron.Preset, bool) {
		for _, p := range presets {
			if p.ID == id {
				return p, true
			}
		}
		return cron.Preset{}, false
	}
	return newForm(c, "Add cron job", func() tea.Cmd {
		jobs := cron.Load(c.h)
		j := cron.Job{}
		if p, ok := presetByID(choice); ok {
			j.ID = cron.NextID(jobs, p.ID)
			j.Command = strings.ReplaceAll(p.Command, "%SELF%", cron.Self())
			j.Comment = p.Name
			j.Schedule = p.Schedule
		} else {
			j.ID = cron.NextID(jobs, "custom")
			j.Command = cron.EscapePercent(strings.TrimSpace(command))
			j.Comment = strings.TrimSpace(comment)
			j.Schedule = "0 3 * * *"
		}
		switch sched {
		case "preset":
		case "custom":
			j.Schedule = strings.TrimSpace(custom)
		default:
			j.Schedule = sched
		}
		return replace(newPlan(c, cron.SavePlan(c.h, append(jobs, j), "Add cron job "+j.ID), nil))
	},
		huh.NewGroup(
			huh.NewSelect[string]().Title("Job").Options(opts...).Value(&choice),
			huh.NewSelect[string]().Title("When").Options(
				huh.NewOption("preset default", "preset"),
				huh.NewOption("every hour", "0 * * * *"),
				huh.NewOption("every day at 03:00", "0 3 * * *"),
				huh.NewOption("every Sunday at 04:00", "0 4 * * 0"),
				huh.NewOption("1st of the month at 05:00", "0 5 1 * *"),
				huh.NewOption("at boot", "@reboot"),
				huh.NewOption("custom expression", "custom"),
			).Value(&sched),
		),
		huh.NewGroup(
			huh.NewInput().Title("Cron expression").Description("min hour day month weekday, e.g. */15 * * * *").Value(&custom).Validate(cron.Validate),
		).WithHideFunc(func() bool { return sched != "custom" }),
		huh.NewGroup(
			huh.NewInput().Title("Command").Description("runs as root via /bin/sh; % is escaped for you").Value(&command).Validate(func(s string) error {
				if strings.TrimSpace(s) == "" {
					return fmt.Errorf("required")
				}
				if strings.Contains(s, "\n") {
					return fmt.Errorf("single line only")
				}
				return nil
			}),
			huh.NewInput().Title("Description").Value(&comment).CharLimit(60),
		).WithHideFunc(func() bool { return choice != "custom" }),
	)
}

// ---- updates --------------------------------------------------------------

func updatesMenu(c *ctx) Screen {
	return newMenu(c, "Automatic updates",
		menuItem{label: "Status", action: func() tea.Cmd {
			return push(newText(c, "Updates status", func() string { return updatesStatus(c) }))
		}},
		menuItem{label: "Configure", desc: "security only, automatic reboot window", action: func() tea.Cmd { return push(updatesForm(c)) }},
	)
}

func updatesStatus(c *ctx) string {
	on, msg := updates.Status(c.h)
	var b strings.Builder
	b.WriteString(dot(on) + " " + msg + "\n\n")
	switch c.h.Distro.Family {
	case system.FamilyDebian:
		b.WriteString(sTitle.Render("/etc/apt/apt.conf.d/20auto-upgrades") + "\n" + system.ReadFile("/etc/apt/apt.conf.d/20auto-upgrades") + "\n")
		b.WriteString(sTitle.Render("last unattended-upgrades log") + "\n" + tail("/var/log/unattended-upgrades/unattended-upgrades.log", 30))
	case system.FamilyRHEL:
		if out, err := c.h.Query("systemctl", "list-timers", "dnf-automatic*", "--no-pager"); err == nil {
			b.WriteString(out)
		}
	default:
		b.WriteString(tail(system.LogDir+"/pending-updates.txt", 40))
	}
	if system.Exists("/var/run/reboot-required") {
		b.WriteString("\n\n" + sWarn.Render("⚠ reboot required"))
	}
	return b.String()
}

func updatesForm(c *ctx) Screen {
	cfg := updates.Config{SecurityOnly: true, AutoReboot: false, RebootTime: "04:00"}
	fam := c.h.Distro.Family
	return newForm(c, "Automatic updates", func() tea.Cmd {
		return replace(newPlan(c, updates.BuildPlan(c.h, cfg), nil))
	},
		huh.NewGroup(
			huh.NewConfirm().Title("Security updates only?").Description("recommended on servers; 'no' also installs regular updates").Value(&cfg.SecurityOnly),
		).WithHideFunc(func() bool { return fam != system.FamilyDebian && fam != system.FamilyRHEL }),
		huh.NewGroup(
			huh.NewConfirm().Title("Reboot automatically when an update needs it?").Value(&cfg.AutoReboot),
			huh.NewInput().Title("Reboot time (HH:MM)").Value(&cfg.RebootTime).Validate(func(s string) error {
				if _, err := time.Parse("15:04", s); err != nil {
					return fmt.Errorf("use HH:MM")
				}
				return nil
			}),
		).WithHideFunc(func() bool { return fam != system.FamilyDebian && fam != system.FamilyRHEL }),
		huh.NewGroup(
			huh.NewNote().Title("Distro: "+c.h.Distro.Name).Description(map[system.Family]string{
				system.FamilyAlpine: "Alpine: a daily cron job runs apk upgrade.",
				system.FamilyArch:   "Arch: rolling release, vpshield only logs pending updates daily (no auto upgrade).",
			}[fam]),
		).WithHideFunc(func() bool { return fam == system.FamilyDebian || fam == system.FamilyRHEL }),
	)
}

// ---- sysctl ---------------------------------------------------------------

func sysctlMenu(c *ctx) Screen {
	return newMenu(c, "Kernel hardening",
		menuItem{label: "Current values", desc: "each key: current vs hardened", action: func() tea.Cmd {
			return push(newText(c, "sysctl", sysctlStatus))
		}},
		menuItem{label: "Apply hardening", desc: "choose groups, write " + sysctl.File, action: func() tea.Cmd { return push(sysctlForm(c)) }},
	)
}

func sysctlStatus() string {
	var b strings.Builder
	for _, it := range sysctl.Items {
		ok, total := sysctl.Compliance(it)
		fmt.Fprintf(&b, "%s %s %s\n", dot(ok == total), sTitle.Render(it.ID), sMuted.Render(it.Desc))
		for _, k := range sysctl.SortedKeys(it.Values) {
			v := it.Values[k]
			cur := sysctl.Current(k)
			mark := sOK.Render("=")
			if cur != v {
				mark = sWarn.Render("≠")
			}
			fmt.Fprintf(&b, "    %-45s %s %s %s\n", k, sText.Render(cur), mark, sMuted.Render(v))
		}
	}
	return b.String()
}

func sysctlForm(c *ctx) Screen {
	var sel []string
	var opts []huh.Option[string]
	for _, it := range sysctl.Items {
		label := fmt.Sprintf("%-12s %s", it.ID, it.Desc)
		if it.Skip != nil {
			if why := it.Skip(c.h); why != "" {
				label += "  (" + why + ")"
			}
		}
		if ok, total := sysctl.Compliance(it); ok == total {
			label += "  ✓"
		}
		o := huh.NewOption(label, it.ID)
		if it.Default {
			o = o.Selected(true)
		}
		opts = append(opts, o)
	}
	return newForm(c, "Kernel hardening", func() tea.Cmd {
		return replace(newPlan(c, sysctl.BuildPlan(c.h, sel), nil))
	}, huh.NewGroup(
		huh.NewMultiSelect[string]().Title("Groups to apply").Description("✓ = already compliant").Options(opts...).Value(&sel).Height(16),
	))
}

// ---- audit ----------------------------------------------------------------

func auditScreen(c *ctx) Screen {
	var last audit.Report
	render := func() string {
		last = audit.Run(c.h, c.st)
		return renderReport(last)
	}
	return newText(c, "Security audit", render, textKey{key: "s", help: "save report", fn: func() tea.Cmd {
		return action(func() (string, error) {
			if c.h.DryRun {
				return "[dry-run] report not saved", nil
			}
			p, err := last.Save()
			return "saved " + p, err
		})
	}})
}

func renderReport(r audit.Report) string {
	var b strings.Builder
	sc := sOK
	switch {
	case r.Score < 60:
		sc = sCrit
	case r.Score < 85:
		sc = sWarn
	}
	b.WriteString(sTitle.Render("Score ") + sc.Render(strconv.Itoa(r.Score)+"/100") + sMuted.Render("   "+r.Time.Format("2006-01-02 15:04")) + "\n")
	area := ""
	for _, f := range r.Findings {
		if f.Area != area {
			area = f.Area
			b.WriteString("\n" + sInfo.Render(strings.ToUpper(area)) + "\n")
		}
		var tag string
		switch f.Sev {
		case audit.OK:
			tag = sOK.Render(" OK ")
		case audit.Info:
			tag = sMuted.Render("INFO")
		case audit.Warn:
			tag = sWarn.Render("WARN")
		case audit.Crit:
			tag = sCrit.Render("CRIT")
		}
		b.WriteString("  " + tag + "  " + sText.Render(f.Title) + "\n")
		if f.Detail != "" && f.Sev >= audit.Warn {
			for _, l := range strings.Split(strings.TrimSpace(f.Detail), "\n") {
				b.WriteString("        " + sMuted.Render(l) + "\n")
			}
		}
	}
	return b.String()
}

// ---- backups --------------------------------------------------------------

func backupsScreen(c *ctx) Screen {
	cols := []table.Column{{Title: "Snapshot", Width: 18}, {Title: "Created", Width: 16}, {Title: "Files", Width: 5}, {Title: "Change", Width: 30}}
	loader := func() ([]table.Row, error) {
		snaps, err := system.ListSnapshots()
		if err != nil {
			return nil, err
		}
		var rows []table.Row
		for _, s := range snaps {
			rows = append(rows, table.Row{s.ID, s.Created.Format("2006-01-02 15:04"), strconv.Itoa(len(s.Entries)), s.Label})
		}
		return rows, nil
	}
	return newTable(c, "Backups & rollback", cols, loader,
		tableKey{key: "enter", help: "restore", needRow: true, fn: func(row table.Row) tea.Cmd {
			id := row[0]
			return push(confirmScreen(c, "Restore", "Restore snapshot "+id+"?", "Puts back the files as they were BEFORE \""+row[3]+"\" and reloads the services.\nNewer changes to the same files are lost.", func() tea.Cmd {
				return tea.Sequence(pop(), action(func() (string, error) {
					rep, err := c.h.Restore(id)
					*c.st = *system.LoadState()
					return fmt.Sprintf("restored %s (%d actions)", id, len(rep)), err
				}))
			}))
		}},
		tableKey{key: "v", help: "view", needRow: true, fn: func(row table.Row) tea.Cmd {
			id := row[0]
			return push(newText(c, id, func() string {
				s, err := system.LoadSnapshot(id)
				if err != nil {
					return err.Error()
				}
				var b strings.Builder
				fmt.Fprintf(&b, "%s\n%s\n\n", sTitle.Render(s.Label), s.Created.Format(time.RFC1123))
				for _, e := range s.Entries {
					state := "saved"
					if !e.Existed {
						state = "did not exist (will be removed)"
					} else if e.Symlink != "" {
						state = "symlink → " + e.Symlink
					}
					fmt.Fprintf(&b, "  %s  %s\n", e.Path, sMuted.Render(state))
				}
				if len(s.Hooks) > 0 {
					b.WriteString("\n" + sTitle.Render("after restore") + "\n")
					for _, hk := range s.Hooks {
						b.WriteString("  $ " + system.CmdString(hk[0], hk[1:]...) + "\n")
					}
				}
				return b.String()
			}))
		}},
		tableKey{key: "p", help: "prune >30d", fn: func(table.Row) tea.Cmd {
			return action(func() (string, error) {
				if c.h.DryRun {
					return "[dry-run] nothing pruned", nil
				}
				n, err := system.PruneSnapshots(30 * 24 * time.Hour)
				return fmt.Sprintf("pruned %d snapshots", n), err
			})
		}},
	)
}

// ---- activity log ---------------------------------------------------------

func logScreen(c *ctx) Screen {
	return newText(c, "Activity log", func() string {
		l := c.h.Log()
		if len(l) == 0 {
			return sMuted.Render("no actions yet in this session. Persistent log: " + system.LogDir + "/vpshield.log")
		}
		return strings.Join(l, "\n")
	})
}
