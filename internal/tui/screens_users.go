package tui

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"

	"vpshield/internal/sshd"
	"vpshield/internal/system"
	"vpshield/internal/users"
)

func usersMenu(c *ctx) Screen {
	m := newMenu(c, "Users & access",
		menuItem{label: "Accounts", desc: "who can log in, sudo rights, password and key status", action: func() tea.Cmd { return push(usersTable(c)) }},
		menuItem{label: "Create admin user", desc: "personal account with sudo + SSH key, instead of working as root", action: func() tea.Cmd { return push(adminUserForm(c)) }},
		menuItem{label: "Sudo policy", desc: "log every sudo command, use_pty, password timeout", action: func() tea.Cmd { return push(sudoForm(c)) }},
		menuItem{label: "Lock root password", desc: "no root password login (console, su); use sudo", action: func() tea.Cmd {
			return push(newPlan(c, users.LockPlan(c.h, "root", true), nil))
		}},
		menuItem{label: "Sudo rules", desc: "enabled lines of /etc/sudoers and sudoers.d (read only)", action: func() tea.Cmd {
			return push(newText(c, "Sudo rules", sudoRulesText))
		}},
	)
	m.header = func() string { return usersHeader(c) }
	return m
}

// usersHeader is the "internal security" verdict shown on top of the menu.
func usersHeader(c *ctx) string {
	s := users.Summarize(users.List())
	var lines []string
	if s.OnlyRoot {
		lines = append(lines,
			sCrit.Render("⚠ root is the only account that can log in"),
			sMuted.Render("Every mistake, script or stolen key runs with full power and nothing is traceable to a person."),
			sMuted.Render("Create an admin user (2), log in with it, then set Root login = no in SSH › Hardening."))
	} else if len(s.Admins) == 0 {
		lines = append(lines, sWarn.Render("⚠ no personal account has sudo: you still need root to administer"))
	} else {
		lines = append(lines, sOK.Render("● admins with sudo: ")+sText.Render(strings.Join(s.Admins, ", ")))
	}
	if len(s.NoPasswd) > 0 {
		lines = append(lines, sWarn.Render("⚠ passwordless sudo: "+strings.Join(s.NoPasswd, ", ")))
	}
	if cur := sshd.Current(c.h); cur.PermitRootLogin != "no" && len(s.Admins) > 0 {
		lines = append(lines, sMuted.Render("root can still log in over SSH ("+cur.PermitRootLogin+"): disable it once your admin user works"))
	}
	return sBox.Render(strings.Join(lines, "\n"))
}

func usersTable(c *ctx) Screen {
	cols := []table.Column{{Title: "User", Width: 14}, {Title: "UID", Width: 6}, {Title: "Sudo", Width: 10}, {Title: "Password", Width: 9}, {Title: "Keys", Width: 5}, {Title: "Shell / groups", Width: 30}}
	all := false
	loader := func() ([]table.Row, error) {
		var rows []table.Row
		for _, a := range users.List() {
			if !all && !a.Human() {
				continue
			}
			sudo := "-"
			if a.UID == 0 {
				sudo = "is root"
			} else if a.NoPasswd {
				sudo = "NOPASSWD"
			} else if a.Sudo {
				sudo = "yes"
			}
			rows = append(rows, table.Row{a.Name, strconv.Itoa(a.UID), sudo, a.Password, strconv.Itoa(a.Keys), a.Shell + "  " + strings.Join(a.Groups, ",")})
		}
		return rows, nil
	}
	t := newTable(c, "Accounts", cols, loader,
		tableKey{key: "l", help: "lock/unlock", needRow: true, fn: func(row table.Row) tea.Cmd {
			lock := row[3] != "locked"
			if row[0] == system.LoginUser() && lock {
				return action(func() (string, error) { return "", fmt.Errorf("refusing to lock the account you are using") })
			}
			return push(newPlan(c, users.LockPlan(c.h, row[0], lock), nil))
		}},
		tableKey{key: "k", help: "add SSH key", needRow: true, fn: func(row table.Row) tea.Cmd { return push(sshKeyFormFor(c, row[0])) }},
		tableKey{key: "n", help: "new admin", fn: func(table.Row) tea.Cmd { return push(adminUserForm(c)) }},
		tableKey{key: "s", help: "show system accounts", fn: func(table.Row) tea.Cmd {
			all = !all
			return func() tea.Msg {
				return actionDoneMsg{out: map[bool]string{true: "showing all accounts", false: "showing login accounts"}[all]}
			}
		}},
	)
	t.header = func() string {
		return sMuted.Render("Password: set · locked (!) · none (key-only or disabled) · empty = anyone can log in!")
	}
	return t
}

func adminUserForm(c *ctx) Screen {
	o := users.AdminOptions{CopyRootKeys: system.Exists("/root/.ssh/authorized_keys")}
	var pw2 string
	sudoMode := "password"
	group := users.AdminGroup(c.h)
	rootKeys := "root has no authorized_keys to copy"
	if o.CopyRootKeys {
		rootKeys = "the keys you use for root today will also open this account"
	}
	return newForm(c, "Create admin user", func() tea.Cmd {
		o.Name = strings.TrimSpace(o.Name)
		o.NoPasswd = sudoMode == "nopasswd"
		return replace(newPlan(c, users.CreateAdminPlan(c.h, o), nil))
	},
		huh.NewGroup(
			huh.NewNote().Title("Personal admin account").Description(fmt.Sprintf(
				"Creates a user in group %q (sudo), copies your SSH keys and sets a password for sudo.\nAfterwards: log in with it, check 'sudo -v', then disable root login in SSH › Hardening.", group)),
			huh.NewInput().Title("Username").Value(&o.Name).Validate(func(s string) error { return users.ValidName(strings.TrimSpace(s)) }),
			huh.NewSelect[string]().Title("sudo asks for").Options(
				huh.NewOption("the user's password (recommended)", "password"),
				huh.NewOption("nothing: NOPASSWD (key-only account, less safe)", "nopasswd"),
			).Value(&sudoMode),
		),
		huh.NewGroup(
			huh.NewInput().Title("Password").Description("at least 10 characters, used by sudo and console login").
				EchoMode(huh.EchoModePassword).Value(&o.Password).Validate(func(s string) error {
				if sudoMode == "password" && len(s) < 10 {
					return fmt.Errorf("at least 10 characters")
				}
				if strings.ContainsAny(s, ":\n") {
					return fmt.Errorf("':' and newlines are not allowed")
				}
				return nil
			}),
			huh.NewInput().Title("Repeat password").EchoMode(huh.EchoModePassword).Value(&pw2).Validate(func(s string) error {
				if s != o.Password {
					return fmt.Errorf("passwords do not match")
				}
				return nil
			}),
		).WithHideFunc(func() bool { return sudoMode != "password" }),
		huh.NewGroup(
			huh.NewConfirm().Title("Copy root's authorized_keys?").Description(rootKeys).Value(&o.CopyRootKeys),
			huh.NewText().Title("Extra public key (optional)").Description("content of ~/.ssh/id_ed25519.pub from your computer").
				Lines(3).CharLimit(0).Value(&o.Key).Validate(func(s string) error {
				s = strings.TrimSpace(s)
				if s == "" {
					if !o.CopyRootKeys && sudoMode == "nopasswd" {
						return fmt.Errorf("a NOPASSWD account needs a key or it cannot log in")
					}
					return nil
				}
				if len(strings.Fields(s)) < 2 || strings.Contains(s, "\n") || !strings.HasPrefix(s, "ssh-") && !strings.HasPrefix(s, "ecdsa-") && !strings.HasPrefix(s, "sk-") {
					return fmt.Errorf("not a single-line OpenSSH public key")
				}
				return nil
			}),
		),
	)
}

func sudoForm(c *ctx) Screen {
	sel := users.CurrentSudoDefaults()
	if len(sel) == 0 {
		sel = []string{"use_pty", "logfile", "timeout", "tries"}
	}
	var opts []huh.Option[string]
	for _, d := range users.SudoDefaults {
		opts = append(opts, huh.NewOption(fmt.Sprintf("%-8s %s", d.ID, d.Desc), d.ID))
	}
	return newForm(c, "Sudo policy", func() tea.Cmd {
		return replace(newPlan(c, users.SudoHardenPlan(c.h, sel), nil))
	}, huh.NewGroup(
		huh.NewNote().Title("Written to "+users.SudoDefaultsFile).Description("validated with visudo before it takes effect; an invalid file is rolled back"),
		huh.NewMultiSelect[string]().Title("Enable").Options(opts...).Value(&sel),
	))
}

func sudoRulesText() string {
	rules := users.SudoRules()
	if len(rules) == 0 {
		if !system.IsRoot() {
			return sWarn.Render("sudoers is readable by root only")
		}
		return "no sudo rules found (is sudo installed?)"
	}
	var b strings.Builder
	file := ""
	for _, r := range rules {
		if r.File != file {
			file = r.File
			b.WriteString("\n" + sTitle.Render(file) + "\n")
		}
		tag := sText.Render(r.Who)
		note := ""
		if r.NoPasswd {
			note = sWarn.Render("  NOPASSWD")
		}
		if !r.All {
			note += sMuted.Render("  (limited commands)")
		}
		b.WriteString("  " + tag + note + "\n")
	}
	return strings.TrimLeft(b.String(), "\n")
}
