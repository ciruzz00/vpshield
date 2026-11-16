package tui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"vpshield/internal/fail2ban"
	"vpshield/internal/firewall"
	"vpshield/internal/sshd"
	"vpshield/internal/sysctl"
	"vpshield/internal/system"
	"vpshield/internal/updates"
	"vpshield/internal/users"
)

type dashData struct {
	fwName    string
	fwActive  bool
	openPorts string
	f2bOn     bool
	f2bJails  int
	f2bBanned int
	sshPort   int
	rootLogin string
	passAuth  bool
	updOn     bool
	updMsg    string
	kernOK    int
	kernTotal int
	deadman   *system.Deadman
	accounts  users.Summary
	backupOK  bool
	backupMsg string
	loadedAt  time.Time
}

type dashMsg struct{ d dashData }

func loadDash(c *ctx) tea.Cmd {
	return func() tea.Msg {
		h := c.h
		var d dashData
		fw := firewall.Detect(h, c.st)
		d.fwName, d.fwActive = fw.Name(), fw.Active()
		if rules, err := fw.Rules(); err == nil {
			var ps []string
			for _, r := range rules {
				s := fmt.Sprintf("%d/%s", r.Port, r.Proto)
				if r.Limit {
					s += "⏱"
				}
				ps = append(ps, s)
			}
			d.openPorts = strings.Join(ps, " ")
		}
		d.f2bOn = fail2ban.Running(h)
		if d.f2bOn {
			if all, err := fail2ban.AllStatus(h); err == nil {
				d.f2bJails = len(all)
				for _, j := range all {
					d.f2bBanned += j.CurBanned
				}
			}
		}
		cur := sshd.Current(h)
		d.sshPort, d.rootLogin, d.passAuth = cur.Port, cur.PermitRootLogin, cur.PasswordAuth
		if c.st.SSHPort == 0 {
			c.st.SSHPort = cur.Port
		}
		d.updOn, d.updMsg = updates.Status(h)
		for _, it := range sysctl.Items {
			if it.Default {
				d.kernTotal++
				if ok, total := sysctl.Compliance(it); ok == total {
					d.kernOK++
				}
			}
		}
		d.deadman = system.ActiveDeadman()
		d.accounts = users.Summarize(users.List())
		d.backupOK, d.backupMsg = backupDash()
		d.loadedAt = time.Now()
		return dashMsg{d}
	}
}

type homeScreen struct {
	c      *ctx
	m      *menuScreen
	dash   *dashData
	konami konamiTracker
}

func newHome(c *ctx) *homeScreen {
	h := &homeScreen{c: c}
	m := newMenu(c, "home",
		menuItem{label: "Firewall & ports", desc: "default deny, open/close ports, rate limiting", action: func() tea.Cmd { return push(firewallMenu(c)) }},
		menuItem{label: "SSH", desc: "change port, hardening, authorized keys", action: func() tea.Cmd { return push(sshMenu(c)) }},
		menuItem{label: "Users & access", desc: "admin user instead of root, sudo policy, lock accounts", action: func() tea.Cmd { return push(usersMenu(c)) }},
		menuItem{label: "Fail2ban", desc: "wizard, jails, banned IPs, unban", action: func() tea.Cmd { return push(f2bMenu(c)) }},
		menuItem{label: "Banners & fingerprint", desc: "hide service versions, MOTD/issue, anti port-scan", action: func() tea.Cmd { return push(bannerMenu(c)) }},
		menuItem{label: "DNS records", desc: "Cloudflare zones and records", action: func() tea.Cmd { return push(cfMenu(c)) }},
		menuItem{label: "DNS resolver", desc: "resolvers used by this server, DoT, DNSSEC", action: func() tea.Cmd { return push(resolverMenu(c)) }},
		menuItem{label: "Cron jobs", desc: "managed jobs and presets, view system crontabs", action: func() tea.Cmd { return push(cronMenu(c)) }},
		menuItem{label: "Automatic updates", desc: "unattended security updates", action: func() tea.Cmd { return push(updatesMenu(c)) }},
		menuItem{label: "Kernel hardening", desc: "sysctl network/kernel knobs", action: func() tea.Cmd { return push(sysctlMenu(c)) }},
		menuItem{label: "Security audit", desc: "score and findings", action: func() tea.Cmd { return push(auditScreen(c)) }},
		menuItem{label: "Remote backups", desc: "rclone: back up folders to S3, B2, SFTP, Drive... on a schedule", action: func() tea.Cmd { return push(backupMenu(c)) }},
		menuItem{label: "Backups & rollback", desc: "undo any change vpshield made", action: func() tea.Cmd { return push(backupsScreen(c)) }},
		menuItem{label: "Activity log", desc: "commands run in this session", action: func() tea.Cmd { return push(logScreen(c)) }},
		menuItem{label: "Quit", action: func() tea.Cmd { return tea.Quit }},
	)
	m.root = true
	m.header = h.renderDash
	h.m = m
	return h
}

func (h *homeScreen) Title() string { return "home" }
func (h *homeScreen) Help() string  { return h.m.Help() }
func (h *homeScreen) Init() tea.Cmd { return loadDash(h.c) }

func (h *homeScreen) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch m := msg.(type) {
	case dashMsg:
		d := m.d
		h.dash = &d
		return h, nil
	case focusMsg:
		return h, loadDash(h.c)
	case tea.KeyMsg:
		if h.konami.feed(m.String()) {
			return h, push(newEgg(h.c))
		}
		if m.String() == "r" {
			return h, loadDash(h.c)
		}
	}
	_, cmd := h.m.Update(msg)
	return h, cmd
}

func (h *homeScreen) View() string { return h.m.View() }

func (h *homeScreen) renderDash() string {
	d := h.dash
	if d == nil {
		return sBox.Render(sMuted.Render("reading system status…"))
	}
	kv := func(k, v string) string { return sMuted.Render(fmt.Sprintf("%-10s", k)) + v }
	ports := d.openPorts
	if ports == "" {
		ports = sMuted.Render("-")
	}
	col1 := []string{
		kv("firewall", dot(d.fwActive)+" "+d.fwName+" "+onOff(d.fwActive, "active", "inactive")),
		kv("allowed", truncate(ports, 38)),
		kv("fail2ban", dot(d.f2bOn)+" "+onOff(d.f2bOn, fmt.Sprintf("%d jails, %d banned now", d.f2bJails, d.f2bBanned), "not running")),
		kv("updates", dot(d.updOn)+" "+d.updMsg),
		kv("admins", adminsCell(d.accounts)),
	}
	root := d.rootLogin
	rootOK := root != "yes"
	col2 := []string{
		kv("ssh port", fmt.Sprintf("%d", d.sshPort)+map[bool]string{true: sMuted.Render(" (default)"), false: ""}[d.sshPort == 22]),
		kv("root", dot(rootOK)+" "+root),
		kv("password", dot(!d.passAuth)+" "+onOff(!d.passAuth, "disabled (keys only)", "enabled")),
		kv("kernel", dot(d.kernOK == d.kernTotal)+fmt.Sprintf(" %d/%d sysctl groups hardened", d.kernOK, d.kernTotal)),
		kv("backups", dot(d.backupOK)+" "+d.backupMsg),
	}
	left := strings.Join(col1, "\n")
	right := strings.Join(col2, "\n")
	body := lipgloss.JoinHorizontal(lipgloss.Top, left, "    ", right)
	if h.c.width < 100 {
		body = left + "\n" + right
	}
	if d.accounts.OnlyRoot {
		body += "\n\n" + sCrit.Render("⚠ only root can log in: create a personal admin user (Users & access)")
	}
	if d.deadman != nil {
		body += "\n\n" + sCrit.Render(fmt.Sprintf("⚠ pending automatic rollback in %s: run 'vpshield confirm' to keep the change",
			time.Until(d.deadman.Deadline).Round(time.Second)))
	}
	return sBox.Render(body)
}

func adminsCell(s users.Summary) string {
	switch {
	case s.OnlyRoot:
		return dot(false) + " " + sCrit.Render("only root")
	case len(s.Admins) == 0:
		return dot(false) + " no sudo user"
	}
	return dot(true) + " " + truncate(strings.Join(s.Admins, ", "), 36)
}
