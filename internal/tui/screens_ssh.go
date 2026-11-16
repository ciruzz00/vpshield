package tui

import (
	"fmt"
	"os/user"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"

	"vpshield/internal/firewall"
	"vpshield/internal/plan"
	"vpshield/internal/sshd"
	"vpshield/internal/system"
	"vpshield/internal/users"
)

func sshMenu(c *ctx) Screen {
	return newMenu(c, "SSH",
		menuItem{label: "Current settings", desc: "effective sshd config and key holders", action: func() tea.Cmd {
			return push(newText(c, "SSH settings", func() string { return sshSummary(c) }))
		}},
		menuItem{label: "Change port", desc: "e.g. 22 → 2222, with firewall, SELinux and auto-rollback", action: func() tea.Cmd { return push(sshPortForm(c)) }},
		menuItem{label: "Hardening", desc: "root login, passwords, timeouts, AllowUsers", action: func() tea.Cmd { return push(sshHardenForm(c)) }},
		menuItem{label: "Add authorized key", desc: "install a public key before disabling passwords", action: func() tea.Cmd { return push(sshKeyForm(c)) }},
	)
}

func sshSummary(c *ctx) string {
	e := sshd.Effective(c.h)
	var b strings.Builder
	if len(e) == 0 {
		b.WriteString(sWarn.Render("cannot run 'sshd -T' (root needed): showing defaults") + "\n\n")
	}
	cur := sshd.Current(c.h)
	row := func(k, v string, good bool) {
		fmt.Fprintf(&b, "  %s %-24s %s\n", dot(good), k, v)
	}
	row("Port", strconv.Itoa(cur.Port), cur.Port != 22)
	row("PermitRootLogin", cur.PermitRootLogin, cur.PermitRootLogin != "yes")
	row("PasswordAuthentication", map[bool]string{true: "yes", false: "no"}[cur.PasswordAuth], !cur.PasswordAuth)
	row("MaxAuthTries", strconv.Itoa(cur.MaxAuthTries), cur.MaxAuthTries <= 4)
	row("LoginGraceTime", strconv.Itoa(cur.LoginGraceTime)+"s", cur.LoginGraceTime <= 60)
	row("ClientAliveInterval", strconv.Itoa(cur.ClientAliveInterval), cur.ClientAliveInterval > 0)
	row("X11Forwarding", map[bool]string{true: "yes", false: "no"}[cur.X11Forwarding], !cur.X11Forwarding)
	row("AllowTcpForwarding", map[bool]string{true: "yes", false: "no"}[cur.AllowTcpForwarding], true)
	au := strings.Join(cur.AllowUsers, " ")
	if au == "" {
		au = "(everyone)"
	}
	row("AllowUsers", au, true)
	b.WriteString("\n" + sTitle.Render("Accounts with authorized_keys") + "\n")
	if k := sshd.KeyHolders(); len(k) > 0 {
		b.WriteString("  " + strings.Join(k, ", ") + "\n")
	} else {
		b.WriteString("  " + sCrit.Render("none: do NOT disable password login yet") + "\n")
	}
	if d := system.ReadFile(sshd.DropIn); d != "" {
		b.WriteString("\n" + sTitle.Render(sshd.DropIn) + "\n" + sMuted.Render(d))
	}
	return b.String()
}

func deadmanOptions() []huh.Option[int] {
	return []huh.Option[int]{
		huh.NewOption("2 minutes", 120), huh.NewOption("3 minutes (recommended)", 180),
		huh.NewOption("5 minutes", 300), huh.NewOption("1 minute", 60),
	}
}

func sshPortForm(c *ctx) Screen {
	cur := sshd.Current(c.h)
	newPort := "2222"
	if cur.Port != 22 {
		newPort = strconv.Itoa(cur.Port)
	}
	limit := true
	deadman := 180
	fwName := firewall.Detect(c.h, c.st).Name()

	return newForm(c, "Change SSH port", func() tea.Cmd {
		n, _ := strconv.Atoi(newPort)
		fw := firewall.Detect(c.h, c.st)
		want := cur
		want.Port = n
		p := sshd.BuildPlan(c.h, fw, cur, want, sshd.Options{LimitNewPort: limit, DeadmanSeconds: deadman})
		p.Title = fmt.Sprintf("SSH port %d → %d", cur.Port, n)
		c.lastSSHPort = n
		oldPort := cur.Port
		return replace(newPlan(c, p, func() tea.Cmd { return replace(sshFinalizeForm(c, oldPort, n)) }))
	}, huh.NewGroup(
		huh.NewNote().Title("Current port: "+strconv.Itoa(cur.Port)).
			Description("Flow: open new port in "+fwName+" → write config → sshd -t → restart → you test from a new terminal.\nIf you do not confirm in time, everything is rolled back automatically."),
		huh.NewInput().Title("New SSH port").Description("pick 1024-65535, avoid well-known ports").Value(&newPort).Validate(func(s string) error {
			n, err := strconv.Atoi(strings.TrimSpace(s))
			if err != nil || n < 1 || n > 65535 {
				return fmt.Errorf("1-65535")
			}
			if n == cur.Port {
				return fmt.Errorf("that is already the SSH port")
			}
			for _, l := range c.h.Listeners() {
				if l.Proto == "tcp" && l.Port == n && !strings.Contains(l.Process, "ssh") {
					return fmt.Errorf("port %d is used by %s", n, l.Process)
				}
			}
			return nil
		}),
		huh.NewConfirm().Title("Rate limit the new port in the firewall?").Value(&limit),
		huh.NewSelect[int]().Title("Auto-rollback if not confirmed within").Options(deadmanOptions()...).Value(&deadman),
	))
}

func sshFinalizeForm(c *ctx, oldPort, newPort int) Screen {
	closeOld := true
	return newForm(c, "Finalize SSH port", func() tea.Cmd {
		fw := firewall.Detect(c.h, c.st)
		return replace(newPlan(c, sshd.FinalizePortPlan(c.h, fw, c.st, oldPort, newPort, closeOld), nil))
	}, huh.NewGroup(
		huh.NewNote().Title(fmt.Sprintf("Port %d confirmed working", newPort)),
		huh.NewConfirm().Title(fmt.Sprintf("Close old port %d in the firewall?", oldPort)).
			Description("also updates the fail2ban sshd jail to the new port").Value(&closeOld),
	))
}

func sshHardenForm(c *ctx) Screen {
	cur := sshd.Current(c.h)
	want := sshd.Hardened(cur)
	pass := want.PasswordAuth
	maxTries := want.MaxAuthTries
	grace := want.LoginGraceTime
	idle := "600"
	allow := strings.Join(cur.AllowUsers, " ")
	deadman := 180
	holders := sshd.KeyHolders()
	keyNote := "key holders: " + strings.Join(holders, ", ")
	if len(holders) == 0 {
		keyNote = "⚠ NO authorized_keys found: keep passwords ON or add a key first (SSH › Add authorized key)"
		pass = true
	}
	rootNote := "no: only works once a personal admin user with sudo exists"
	if us := users.Summarize(users.List()); us.OnlyRoot || len(us.Admins) == 0 {
		rootNote = "⚠ no admin user with sudo yet: keep prohibit-password, create one in Users & access first"
	}
	return newForm(c, "SSH hardening", func() tea.Cmd {
		want.PasswordAuth = pass
		want.MaxAuthTries = maxTries
		want.LoginGraceTime = grace
		switch idle {
		case "0":
			want.ClientAliveInterval, want.ClientAliveCountMax = 0, 3
		case "600":
			want.ClientAliveInterval, want.ClientAliveCountMax = 300, 2
		case "1800":
			want.ClientAliveInterval, want.ClientAliveCountMax = 600, 3
		}
		want.AllowUsers, _ = sshd.ParseUsers(allow)
		fw := firewall.Detect(c.h, c.st)
		p := sshd.BuildPlan(c.h, fw, cur, want, sshd.Options{DeadmanSeconds: deadman})
		p.Title = "SSH hardening"
		c.lastSSHPort = cur.Port
		return replace(newPlan(c, p, nil))
	},
		huh.NewGroup(
			huh.NewSelect[string]().Title("Root login").Description(rootNote).Options(
				huh.NewOption("prohibit-password: root only with keys (recommended)", "prohibit-password"),
				huh.NewOption("no: root cannot log in, use sudo", "no"),
				huh.NewOption("yes: root with password (insecure)", "yes"),
			).Value(&want.PermitRootLogin),
			huh.NewConfirm().Title("Allow password login?").Description(keyNote).Affirmative("Yes").Negative("No, keys only").Value(&pass),
			huh.NewSelect[int]().Title("Max auth attempts per connection").Options(
				huh.NewOption("3 (recommended)", 3), huh.NewOption("4", 4), huh.NewOption("6 (OpenSSH default)", 6),
			).Value(&maxTries),
			huh.NewSelect[int]().Title("Login grace time").Options(
				huh.NewOption("20 s", 20), huh.NewOption("30 s (recommended)", 30), huh.NewOption("60 s", 60), huh.NewOption("120 s (default)", 120),
			).Value(&grace),
		),
		huh.NewGroup(
			huh.NewSelect[string]().Title("Disconnect idle/dead sessions").Options(
				huh.NewOption("after ~10 min (recommended)", "600"), huh.NewOption("after ~30 min", "1800"), huh.NewOption("never", "0"),
			).Value(&idle),
			huh.NewConfirm().Title("X11 forwarding?").Value(&want.X11Forwarding),
			huh.NewConfirm().Title("TCP forwarding / tunnels?").Description("needed by VS Code Remote-SSH, ssh -L/-R tunnels").Value(&want.AllowTcpForwarding),
			huh.NewConfirm().Title("Agent forwarding?").Description("ssh -A, risky on shared servers").Value(&want.AllowAgentForward),
			huh.NewInput().Title("AllowUsers").Description("space separated, empty = everyone. Include yourself!").
				Placeholder(system.LoginUser()).Value(&allow).Validate(func(s string) error { _, err := sshd.ParseUsers(s); return err }),
			huh.NewSelect[int]().Title("Auto-rollback if not confirmed within").Options(deadmanOptions()...).Value(&deadman),
		),
	)
}

func sshKeyForm(c *ctx) Screen { return sshKeyFormFor(c, system.LoginUser()) }

func sshKeyFormFor(c *ctx, username string) Screen {
	var key string
	return newForm(c, "Add authorized key", func() tea.Cmd {
		k := strings.TrimSpace(key)
		u := strings.TrimSpace(username)
		p := &plan.Plan{Title: "Authorize key for " + u}
		p.Add(plan.Func("append key to ~"+u+"/.ssh/authorized_keys", truncate(k, 60), func(h *system.Host) (string, error) {
			return addAuthorizedKey(h, u, k)
		}))
		return replace(newPlan(c, p, nil))
	}, huh.NewGroup(
		huh.NewInput().Title("User").Value(&username).Validate(func(s string) error {
			if _, err := user.Lookup(strings.TrimSpace(s)); err != nil {
				return fmt.Errorf("unknown user")
			}
			return nil
		}),
		huh.NewText().Title("Public key").Description("paste the content of ~/.ssh/id_ed25519.pub from YOUR computer").
			Lines(4).Value(&key).Validate(func(s string) error {
			s = strings.TrimSpace(s)
			for _, pfx := range []string{"ssh-ed25519 ", "ssh-rsa ", "ecdsa-sha2-", "sk-ssh-ed25519@", "sk-ecdsa-sha2-"} {
				if strings.HasPrefix(s, pfx) && !strings.Contains(s, "\n") {
					return nil
				}
			}
			return fmt.Errorf("not a single-line OpenSSH public key")
		}),
	))
}

func addAuthorizedKey(h *system.Host, username, key string) (string, error) {
	return users.AddAuthorizedKey(h, username, key)
}
