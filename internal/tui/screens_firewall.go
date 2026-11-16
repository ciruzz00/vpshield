package tui

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"

	"vpshield/internal/firewall"
	"vpshield/internal/plan"
	"vpshield/internal/sshd"
	"vpshield/internal/system"
)

func currentSSHPort(c *ctx) int {
	if p := sshd.Current(c.h).Port; p > 0 {
		return p
	}
	if c.st.SSHPort > 0 {
		return c.st.SSHPort
	}
	return 22
}

func firewallMenu(c *ctx) Screen {
	fw := func() firewall.Backend { return firewall.Detect(c.h, c.st) }
	return newMenu(c, "Firewall & ports",
		menuItem{label: "Rules", desc: "allowed ports: add, remove, toggle rate limit", action: func() tea.Cmd { return push(firewallRules(c)) }},
		menuItem{label: "Enable / setup", desc: "pick backend, default deny inbound, whitelist services", action: func() tea.Cmd { return push(firewallEnableForm(c)) }},
		menuItem{label: "Listening ports", desc: "what is really listening and if it is exposed", action: func() tea.Cmd {
			return push(newText(c, "Listening ports", func() string { return listenersText(c) }))
		}},
		menuItem{label: "Live status", desc: "raw backend output", action: func() tea.Cmd {
			return push(newText(c, "Firewall status", func() string { return fw().Status() }))
		}},
		menuItem{label: "Disable firewall", desc: "stop filtering (not recommended)", action: func() tea.Cmd {
			b := fw()
			p := &plan.Plan{Title: "Disable " + b.Name()}
			p.Warn("the server will accept connections on every listening port")
			p.Add(firewall.Wrap(b, b.DisableSteps())...)
			return push(newPlan(c, p, nil))
		}},
	)
}

func listenersText(c *ctx) string {
	fw := firewall.Detect(c.h, c.st)
	allowed := map[string]bool{}
	if rules, err := fw.Rules(); err == nil {
		for _, r := range rules {
			allowed[fmt.Sprintf("%d/%s", r.Port, r.Proto)] = true
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%-6s %-7s %-22s %-18s %s\n", "PROTO", "PORT", "BIND", "PROCESS", "EXPOSURE")
	for _, l := range c.h.Listeners() {
		exp := sMuted.Render("local only")
		if l.Public() {
			switch {
			case !fw.Active():
				exp = sCrit.Render("PUBLIC (no firewall)")
			case allowed[fmt.Sprintf("%d/%s", l.Port, l.Proto)]:
				exp = sWarn.Render("public, allowed")
			default:
				exp = sOK.Render("blocked by firewall")
			}
		}
		fmt.Fprintf(&b, "%-6s %-7d %-22s %-18s %s\n", l.Proto, l.Port, truncate(l.Addr, 22), truncate(l.Process, 18), exp)
	}
	return b.String()
}

func firewallRules(c *ctx) Screen {
	cols := []table.Column{{Title: "Port", Width: 7}, {Title: "Proto", Width: 6}, {Title: "Rate limit", Width: 10}, {Title: "Comment", Width: 20}}
	var t *tableScreen
	loader := func() ([]table.Row, error) {
		fw := firewall.Detect(c.h, c.st)
		if !fw.Active() {
			return nil, fmt.Errorf("%s is not active: use 'Enable / setup' first", fw.Name())
		}
		rules, err := fw.Rules()
		if err != nil {
			return nil, err
		}
		var rows []table.Row
		for _, r := range rules {
			lim := ""
			if r.Limit {
				lim = "yes"
			}
			rows = append(rows, table.Row{strconv.Itoa(r.Port), r.Proto, lim, r.Comment})
		}
		return rows, nil
	}
	t = newTable(c, "Rules", cols, loader,
		tableKey{key: "a", help: "add port", fn: func(table.Row) tea.Cmd { return push(addPortForm(c)) }},
		tableKey{key: "d", help: "remove", needRow: true, fn: func(row table.Row) tea.Cmd {
			port, _ := strconv.Atoi(row[0])
			fw := firewall.Detect(c.h, c.st)
			p := &plan.Plan{Title: fmt.Sprintf("Close %s/%s", row[0], row[1])}
			if port == currentSSHPort(c) && row[1] == "tcp" {
				p.Warn("THIS IS YOUR SSH PORT: closing it will lock you out of the server")
			}
			p.Add(firewall.Wrap(fw, fw.RemoveSteps(port, row[1]))...)
			return push(newPlan(c, p, nil))
		}},
		tableKey{key: "l", help: "toggle rate limit", needRow: true, fn: func(row table.Row) tea.Cmd {
			port, _ := strconv.Atoi(row[0])
			fw := firewall.Detect(c.h, c.st)
			r := system.PortRule{Port: port, Proto: row[1], Limit: row[2] == "", Comment: row[3]}
			title := "Rate limit " + row[0] + "/" + row[1]
			if !r.Limit {
				title = "Remove rate limit on " + row[0] + "/" + row[1]
			}
			p := &plan.Plan{Title: title}
			p.Add(firewall.Wrap(fw, fw.AllowSteps(r))...)
			return push(newPlan(c, p, nil))
		}},
	)
	t.header = func() string {
		fw := firewall.Detect(c.h, c.st)
		return sMuted.Render("backend: ") + sText.Render(fw.Name()) + sMuted.Render("   ssh port: ") + sText.Render(strconv.Itoa(currentSSHPort(c)))
	}
	return t
}

func addPortForm(c *ctx) Screen {
	var spec, comment string
	limit := false
	return newForm(c, "Open port", func() tea.Cmd {
		port, proto, _ := firewall.ParsePortSpec(spec)
		fw := firewall.Detect(c.h, c.st)
		p := &plan.Plan{Title: fmt.Sprintf("Open %d/%s", port, proto)}
		p.Add(firewall.Wrap(fw, fw.AllowSteps(system.PortRule{Port: port, Proto: proto, Limit: limit, Comment: comment}))...)
		return replace(newPlan(c, p, nil))
	}, huh.NewGroup(
		huh.NewInput().Title("Port").Description("e.g. 443, 51820/udp").Value(&spec).Validate(firewall.ValidPort),
		huh.NewConfirm().Title("Rate limit new connections per source IP?").
			Description("ufw: 6 conn/30s · nftables: 10/min · firewalld: global 30/min. Good for SSH, bad for busy web ports.").
			Value(&limit),
		huh.NewInput().Title("Comment").Placeholder("optional").Value(&comment).CharLimit(40),
	))
}

type svcOpt struct {
	label string
	spec  string
}

var commonServices = []svcOpt{
	{"HTTP (80/tcp)", "80/tcp"}, {"HTTPS (443/tcp)", "443/tcp"}, {"HTTP/3 QUIC (443/udp)", "443/udp"},
	{"WireGuard (51820/udp)", "51820/udp"}, {"DNS (53/udp)", "53/udp"}, {"DNS (53/tcp)", "53/tcp"},
	{"SMTP (25/tcp)", "25/tcp"}, {"Submission (587/tcp)", "587/tcp"}, {"SMTPS (465/tcp)", "465/tcp"},
	{"IMAPS (993/tcp)", "993/tcp"}, {"OpenVPN (1194/udp)", "1194/udp"},
}

func firewallEnableForm(c *ctx) Screen {
	cur := firewall.Detect(c.h, c.st)
	backend := cur.Name()
	sshPort := strconv.Itoa(currentSSHPort(c))
	limitSSH := true
	var services []string
	var extra string

	// preselect services that already listen publicly
	listening := map[string]bool{}
	for _, l := range c.h.Listeners() {
		if l.Public() {
			listening[fmt.Sprintf("%d/%s", l.Port, l.Proto)] = true
		}
	}
	var svcOpts []huh.Option[string]
	for _, s := range commonServices {
		o := huh.NewOption(s.label, s.spec)
		if listening[s.spec] {
			o = huh.NewOption(s.label+"  ← listening now", s.spec).Selected(true)
		}
		svcOpts = append(svcOpts, o)
	}
	var beOpts []huh.Option[string]
	for _, n := range firewall.Names {
		b := firewall.New(c.h, c.st, n)
		label := n
		switch {
		case b.Active():
			label += "  (active)"
		case b.Installed():
			label += "  (installed)"
		default:
			label += "  (will be installed)"
		}
		if n == firewall.DefaultFor(c.h.Distro.Family) {
			label += "  ★ distro default"
		}
		beOpts = append(beOpts, huh.NewOption(label, n))
	}

	return newForm(c, "Firewall setup", func() tea.Cmd {
		fw := firewall.New(c.h, c.st, backend)
		port, _ := strconv.Atoi(sshPort)
		p := &plan.Plan{Title: "Enable " + backend}
		// two firewalls fighting over the same packets is a classic lockout
		for _, n := range firewall.Names {
			if n == backend {
				continue
			}
			other := firewall.New(c.h, c.st, n)
			if other.Active() {
				p.Warn("%s is active and will be disabled to avoid conflicts", n)
				p.Add(firewall.Wrap(other, other.DisableSteps())...)
			}
		}
		p.Add(fw.InstallSteps()...)
		steps := fw.EnableSteps(port)
		if limitSSH {
			steps = append(steps, fw.AllowSteps(system.PortRule{Port: port, Proto: "tcp", Limit: true, Comment: "ssh"})...)
		}
		for _, s := range services {
			pt, proto, _ := firewall.ParsePortSpec(s)
			steps = append(steps, fw.AllowSteps(system.PortRule{Port: pt, Proto: proto})...)
		}
		for _, s := range strings.FieldsFunc(extra, func(r rune) bool { return r == ',' || r == ' ' }) {
			pt, proto, err := firewall.ParsePortSpec(s)
			if err == nil {
				steps = append(steps, fw.AllowSteps(system.PortRule{Port: pt, Proto: proto})...)
			}
		}
		p.Add(firewall.Wrap(fw, steps)...)
		if ip := system.ClientIP(); ip != "" {
			p.Warn("you are connected from %s on SSH port %d: that port is allowed before the default-deny policy is enabled", ip, port)
		}
		p.AfterApply = func(h *system.Host) error {
			c.st.FirewallBackend = backend
			return h.SaveState(c.st)
		}
		return replace(newPlan(c, p, nil))
	},
		huh.NewGroup(
			huh.NewSelect[string]().Title("Firewall backend").Options(beOpts...).Value(&backend),
			huh.NewInput().Title("SSH port to keep open (anti-lockout)").Value(&sshPort).Validate(func(s string) error {
				_, _, err := firewall.ParsePortSpec(s)
				return err
			}),
			huh.NewConfirm().Title("Rate limit SSH per source IP?").Description("slows down brute force before fail2ban even sees it").Value(&limitSSH),
		),
		huh.NewGroup(
			huh.NewMultiSelect[string]().Title("Services to allow").Description("space to toggle, enter to confirm").Options(svcOpts...).Value(&services),
			huh.NewInput().Title("Other ports").Description("comma separated, e.g. 8443, 25565/tcp, 60000/udp").Value(&extra).Validate(func(s string) error {
				for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' }) {
					if err := firewall.ValidPort(f); err != nil {
						return err
					}
				}
				return nil
			}),
		),
	)
}
