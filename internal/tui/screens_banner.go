package tui

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"

	"vpshield/internal/banner"
)

func bannerMenu(c *ctx) Screen {
	return newMenu(c, "Banners & fingerprint",
		menuItem{label: "What scanners see", desc: "SSH identification, issue files, web/mail banners", action: func() tea.Cmd {
			return push(newText(c, "Exposure", func() string { return banner.Exposure(c.h) }))
		}},
		menuItem{label: "Hide versions & banners", desc: "SSH distro suffix, MOTD/issue, nginx, Apache, Postfix", action: func() tea.Cmd { return push(bannerForm(c)) }},
		menuItem{label: "Port-scan protection", desc: "fail2ban jail on dropped packets (in the fail2ban wizard)", action: func() tea.Cmd { return push(f2bWizard(c)) }},
	)
}

func bannerForm(c *ctx) Screen {
	var sel []string
	cfg := banner.Config{WarnText: banner.DefaultWarn}
	var opts []huh.Option[string]
	for _, it := range banner.Items {
		label := it.Name + "  " + sMuted.Render(it.Desc)
		avail := it.Available(c.h)
		if !avail {
			label += "  (not installed)"
		}
		opts = append(opts, huh.NewOption(label, it.ID).Selected(avail))
	}
	return newForm(c, "Hide versions & banners", func() tea.Cmd {
		for _, id := range sel {
			switch id {
			case "ssh":
				cfg.SSHVersion = true
			case "motd":
				cfg.Motd = true
			case "nginx":
				cfg.Nginx = true
			case "apache":
				cfg.Apache = true
			case "postfix":
				cfg.Postfix = true
			}
		}
		return replace(newPlan(c, banner.BuildPlan(c.h, cfg), nil))
	},
		huh.NewGroup(
			huh.NewMultiSelect[string]().Title("Harden").Options(opts...).Value(&sel),
		),
		huh.NewGroup(
			huh.NewConfirm().Title("Show a legal warning before SSH login?").
				Description("shown to anyone connecting, contains no version info").Value(&cfg.PreLogin),
			huh.NewInput().Title("Warning text (pre-login and /etc/issue)").Value(&cfg.WarnText).CharLimit(200),
			huh.NewInput().Title("MOTD after login").Placeholder("empty = nothing").Value(&cfg.MotdText).CharLimit(200),
		),
	)
}
