package tui

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"

	"vpshield/internal/fail2ban"
	"vpshield/internal/firewall"
	"vpshield/internal/plan"
	"vpshield/internal/system"
)

func f2bMenu(c *ctx) Screen {
	return newMenu(c, "Fail2ban",
		menuItem{label: "Jails & banned IPs", desc: "live status, unban / ban manually", action: func() tea.Cmd { return push(f2bJails(c)) }},
		menuItem{label: "Configure (wizard)", desc: "edit ban policy, sshd jail, extra jails, whitelist (starts from the current config)", action: func() tea.Cmd { return push(f2bWizard(c)) }},
		menuItem{label: "Edit config file", desc: "edit " + fail2ban.JailFile + " directly, validated before reload", action: func() tea.Cmd { return push(f2bEditForm(c)) }},
		menuItem{label: "Log", desc: "last lines of " + fail2ban.LogFile, action: func() tea.Cmd {
			return push(newText(c, "fail2ban log", func() string { return tail(fail2ban.LogFile, 300) }))
		}},
		menuItem{label: "Current config", desc: fail2ban.JailFile, action: func() tea.Cmd {
			return push(newText(c, "jail config", func() string {
				s := system.ReadFile(fail2ban.JailFile)
				if s == "" {
					return "no vpshield jail file yet: run the wizard"
				}
				return s
			}, textKey{key: "e", help: "edit", fn: func() tea.Cmd { return push(f2bEditForm(c)) }},
				textKey{key: "w", help: "wizard", fn: func() tea.Cmd { return push(f2bWizard(c)) }}))
		}},
		menuItem{label: "Unban everyone", desc: "clear all bans in all jails", action: func() tea.Cmd {
			return push(confirmScreen(c, "Unban all", "Unban every IP in every jail?", "", func() tea.Cmd {
				return tea.Sequence(pop(), action(func() (string, error) { return fail2ban.UnbanAll(c.h) }))
			}))
		}},
	)
}

func tail(path string, n int) string {
	s := system.ReadFile(path)
	if s == "" {
		return "(empty or missing) " + path
	}
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	for i, l := range lines {
		switch {
		case strings.Contains(l, " Ban "):
			lines[i] = sCrit.Render(l)
		case strings.Contains(l, " Unban "):
			lines[i] = sOK.Render(l)
		case strings.Contains(l, "ERROR"):
			lines[i] = sWarn.Render(l)
		}
	}
	return strings.Join(lines, "\n")
}

func f2bJails(c *ctx) Screen {
	cols := []table.Column{{Title: "Jail", Width: 20}, {Title: "Banned now", Width: 11}, {Title: "Total banned", Width: 12}, {Title: "Failing now", Width: 11}, {Title: "Total failed", Width: 12}}
	loader := func() ([]table.Row, error) {
		if !c.h.Has("fail2ban-client") {
			return nil, fmt.Errorf("fail2ban is not installed: run the wizard")
		}
		if !fail2ban.Running(c.h) {
			return nil, fmt.Errorf("fail2ban is not running")
		}
		all, err := fail2ban.AllStatus(c.h)
		if err != nil {
			return nil, err
		}
		var rows []table.Row
		for _, j := range all {
			rows = append(rows, table.Row{j.Name, strconv.Itoa(j.CurBanned), strconv.Itoa(j.TotBanned), strconv.Itoa(j.CurFailed), strconv.Itoa(j.TotFailed)})
		}
		return rows, nil
	}
	return newTable(c, "Jails", cols, loader,
		tableKey{key: "enter", help: "banned IPs", needRow: true, fn: func(row table.Row) tea.Cmd { return push(f2bBanned(c, row[0])) }},
		tableKey{key: "b", help: "ban IP", needRow: true, fn: func(row table.Row) tea.Cmd { return push(banForm(c, row[0])) }},
	)
}

func f2bBanned(c *ctx, jail string) Screen {
	cols := []table.Column{{Title: "Banned IP", Width: 40}, {Title: "Note", Width: 20}}
	loader := func() ([]table.Row, error) {
		ji, err := fail2ban.JailStatus(c.h, jail)
		if err != nil {
			return nil, err
		}
		me := system.ClientIP()
		var rows []table.Row
		for _, ip := range ji.IPs {
			note := ""
			if ip == me {
				note = "← THIS IS YOU"
			}
			rows = append(rows, table.Row{ip, note})
		}
		return rows, nil
	}
	return newTable(c, jail, cols, loader,
		tableKey{key: "u", help: "unban", needRow: true, fn: func(row table.Row) tea.Cmd {
			ip := row[0]
			return action(func() (string, error) {
				_, err := fail2ban.Unban(c.h, jail, ip)
				return "unbanned " + ip, err
			})
		}},
		tableKey{key: "b", help: "ban IP", fn: func(table.Row) tea.Cmd { return push(banForm(c, jail)) }},
	)
}

func banForm(c *ctx, jail string) Screen {
	var ip string
	return newForm(c, "Ban IP in "+jail, func() tea.Cmd {
		ip := strings.TrimSpace(ip)
		return tea.Sequence(pop(), action(func() (string, error) {
			_, err := fail2ban.Ban(c.h, jail, ip)
			return "banned " + ip, err
		}))
	}, huh.NewGroup(
		huh.NewInput().Title("IP address").Value(&ip).Validate(func(s string) error {
			s = strings.TrimSpace(s)
			if net.ParseIP(s) == nil {
				return fmt.Errorf("invalid IP")
			}
			if s == system.ClientIP() {
				return fmt.Errorf("that is your own IP")
			}
			return nil
		}),
	))
}

var banActions = map[string]string{
	"ufw":                    "ufw",
	"firewallcmd-rich-rules": "firewallcmd-allports",
	"nftables-multiport":     "nftables-allports",
	"iptables-multiport":     "iptables-allports",
}

func f2bWizard(c *ctx) Screen {
	fw := firewall.Detect(c.h, c.st)
	sshPort := currentSSHPort(c)
	// ban through the active firewall, or straight nftables/iptables if none
	def := fw.Fail2banAction()
	if !fw.Active() {
		def = "iptables-multiport"
		if c.h.Has("nft") {
			def = "nftables-multiport"
		}
	}
	cfg, existing := fail2ban.Load(fail2ban.Defaults(c.h, sshPort, def, banActions[def]))
	if existing && cfg.SSHPort != sshPort {
		cfg.SSHPort = sshPort // follow the real sshd port
	}
	ignore := strings.Join(cfg.IgnoreIP, " ")
	intro := "No vpshield config yet: recommended defaults are pre-selected."
	if existing {
		intro = "Current values loaded from " + fail2ban.JailFile + ": change what you need, the rest stays as it is."
	}

	var jailOpts []huh.Option[string]
	for _, j := range fail2ban.Catalog {
		label := fmt.Sprintf("%-16s %s", j.Name, j.Desc)
		avail := j.Available(c.h)
		if !avail {
			label += "  (not detected)"
		}
		o := huh.NewOption(label, j.ID)
		for _, id := range cfg.Jails {
			if id == j.ID {
				o = o.Selected(true)
			}
		}
		jailOpts = append(jailOpts, o)
	}
	var actOpts []huh.Option[string]
	acts := []string{"ufw", "firewallcmd-rich-rules", "nftables-multiport", "iptables-multiport"}
	if _, known := banActions[cfg.BanAction]; !known && cfg.BanAction != "" {
		acts = append(acts, cfg.BanAction)
	}
	for _, a := range acts {
		label := a
		if a == def {
			label += "  ★ recommended"
		}
		actOpts = append(actOpts, huh.NewOption(label, a))
	}
	myIP := system.ClientIP()
	ipNote := "your current IP is pre-filled so you cannot ban yourself"
	if myIP == "" {
		ipNote = "add your home/office IP or VPN range"
	}

	return newForm(c, "Fail2ban wizard", func() tea.Cmd {
		cfg.IgnoreIP, _ = fail2ban.ParseIgnoreIP(ignore)
		if all, known := banActions[cfg.BanAction]; known {
			cfg.BanAllPorts = all
		}
		p := fail2ban.BuildPlan(c.h, cfg)
		for _, j := range cfg.Jails {
			if j == "portscan" && fw.Active() {
				if pre := fail2ban.PortscanPrereq(fw.Name()); len(pre) > 0 {
					p.Steps = append(firewall.Wrap(fw, pre), p.Steps...)
				}
			}
			if j == "portscan" && !fw.Active() {
				p.Warn("portscan jail needs an active firewall that logs dropped packets: enable the firewall first")
			}
		}
		if !fw.Active() {
			p.Warn("firewall %s is not active: bans use %s directly", fw.Name(), cfg.BanAction)
		}
		return replace(newPlan(c, p, nil))
	},
		huh.NewGroup(
			huh.NewNote().Title("1/4 · Ban policy").Description(intro+"\nAn IP failing <maxretry> times within <findtime> is banned for <bantime>."),
			huh.NewSelect[string]().Title("Ban time").Options(withCurrent(cfg.BanTime,
				huh.NewOption("10 minutes", "10m"), huh.NewOption("1 hour (recommended)", "1h"), huh.NewOption("6 hours", "6h"),
				huh.NewOption("1 day", "1d"), huh.NewOption("1 week", "1w"),
			)...).Value(&cfg.BanTime),
			huh.NewSelect[string]().Title("Find time (window)").Options(withCurrent(cfg.FindTime,
				huh.NewOption("5 minutes", "5m"), huh.NewOption("10 minutes (recommended)", "10m"), huh.NewOption("30 minutes", "30m"),
				huh.NewOption("1 hour", "1h"), huh.NewOption("1 day", "1d"),
			)...).Value(&cfg.FindTime),
			huh.NewSelect[int]().Title("Max retries (default for all jails)").Options(withCurrent(cfg.MaxRetry,
				huh.NewOption("3", 3), huh.NewOption("5 (recommended)", 5), huh.NewOption("10", 10),
			)...).Value(&cfg.MaxRetry),
			huh.NewConfirm().Title("Incremental bans?").Description("each new ban of the same IP lasts twice as long").Value(&cfg.Increment),
			huh.NewSelect[string]().Title("Max incremental ban").Options(withCurrent(cfg.MaxBanTime,
				huh.NewOption("1 week", "1w"), huh.NewOption("4 weeks", "4w"), huh.NewOption("1 year", "52w"),
			)...).Value(&cfg.MaxBanTime),
		),
		huh.NewGroup(
			huh.NewNote().Title("2/4 · SSH jail").Description(fmt.Sprintf("Watches sshd on port %d (journal or auth log, auto-detected).", sshPort)),
			huh.NewSelect[string]().Title("Detection mode").Options(withCurrent(cfg.SSHMode,
				huh.NewOption("aggressive: everything below (recommended)", "aggressive"),
				huh.NewOption("normal: failed passwords / invalid users", "normal"),
				huh.NewOption("ddos: pre-auth floods, dropped connections", "ddos"),
				huh.NewOption("extra: normal + protocol errors", "extra"),
			)...).Value(&cfg.SSHMode),
			huh.NewSelect[int]().Title("SSH max retries").Options(withCurrent(cfg.SSHMaxRetry,
				huh.NewOption("2", 2), huh.NewOption("3 (recommended)", 3), huh.NewOption("5", 5),
			)...).Value(&cfg.SSHMaxRetry),
		),
		huh.NewGroup(
			huh.NewNote().Title("3/4 · Extra jails").Description("Jails for services not found on this host are pre-unselected: enabling them fails if their log is missing."),
			huh.NewMultiSelect[string]().Title("Enable").Options(jailOpts...).Value(&cfg.Jails),
		),
		huh.NewGroup(
			huh.NewNote().Title("4/4 · Whitelist & ban action"),
			huh.NewInput().Title("Never ban (ignoreip)").Description(ipNote).Value(&ignore).Validate(func(s string) error {
				_, err := fail2ban.ParseIgnoreIP(s)
				return err
			}),
			huh.NewSelect[string]().Title("Ban action").Description("how bans are enforced").Options(actOpts...).Value(&cfg.BanAction),
		),
	)
}

// withCurrent appends cur as an extra option when it is not one of the
// presets, so loading a hand-edited value does not silently reset it.
func withCurrent[T comparable](cur T, opts ...huh.Option[T]) []huh.Option[T] {
	var zero T
	if cur == zero {
		return opts
	}
	for _, o := range opts {
		if o.Value == cur {
			return opts
		}
	}
	return append(opts, huh.NewOption(fmt.Sprintf("%v (current)", cur), cur))
}

// f2bEditForm edits the jail file as text. The plan writes it, runs
// fail2ban-client -t and reloads: a rejected file is rolled back.
func f2bEditForm(c *ctx) Screen {
	content := system.ReadFile(fail2ban.JailFile)
	if content == "" {
		fw := firewall.Detect(c.h, c.st)
		act := fw.Fail2banAction()
		content = fail2ban.Render(c.h, fail2ban.Defaults(c.h, currentSSHPort(c), act, banActions[act]))
	}
	orig := content
	lines := c.height - 8
	if lines < 6 {
		lines = 6
	}
	return newForm(c, "Edit jail file", func() tea.Cmd {
		if content == orig {
			return pop()
		}
		p := &plan.Plan{Title: "Edit " + fail2ban.JailFile}
		if !c.h.Has("fail2ban-client") {
			p.Warn("fail2ban is not installed: the file is written but nothing enforces it (run the wizard to install)")
		}
		if !strings.HasSuffix(content, "\n") {
			content += "\n"
		}
		p.Add(plan.File(fail2ban.JailFile, content, 0o644))
		if c.h.Has("fail2ban-client") {
			p.Add(plan.Func("test configuration", "$ fail2ban-client -t", func(h *system.Host) (string, error) {
				out, err := h.Run("fail2ban-client", "-t")
				if err != nil && strings.Contains(strings.ToLower(out), "usage") {
					return "fail2ban too old for -t, skipped", nil
				}
				if err != nil {
					return out, fmt.Errorf("fail2ban rejected the file, it will be restored: %w", err)
				}
				return out, nil
			}))
			if fail2ban.Running(c.h) {
				p.Add(plan.Cmd("reload fail2ban", "fail2ban-client", "reload"))
			} else {
				p.Add(plan.EnableService("fail2ban"))
			}
			p.RestoreHooks = append(p.RestoreHooks, []string{"fail2ban-client", "reload"})
		}
		return replace(newPlan(c, p, nil))
	}, huh.NewGroup(
		huh.NewText().Title(fail2ban.JailFile).
			Description("ctrl+e opens $EDITOR · the wizard keeps the values it knows, other custom lines are dropped if you run it again").
			Lines(lines).CharLimit(0).ShowLineNumbers(true).Value(&content),
	))
}
