// Package banner reduces what the server tells scanners about itself:
// service version strings, distro banners, MOTD and pre-login issue files.
package banner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"vpshield/internal/plan"
	"vpshield/internal/system"
)

const (
	SSHDropIn   = "/etc/ssh/sshd_config.d/01-vpshield-banner.conf"
	SSHBanner   = "/etc/ssh/vpshield-banner"
	nginxConf   = "/etc/nginx/conf.d/00-vpshield-hardening.conf"
	DefaultWarn = "Authorized access only. All activity is logged and may be reported."
)

type Config struct {
	SSHVersion bool   // hide distro suffix / addendum in the SSH identification string
	PreLogin   bool   // show a legal warning before SSH authentication
	Motd       bool   // disable dynamic motd, neutral /etc/motd, /etc/issue, /etc/issue.net
	MotdText   string // text for /etc/motd (empty = nothing)
	WarnText   string // pre-login / issue text
	Nginx      bool
	Apache     bool
	Postfix    bool
}

type Item struct {
	ID, Name, Desc string
	Available      func(h *system.Host) bool
}

func always(*system.Host) bool { return true }

var Items = []Item{
	{"ssh", "SSH identification", "drop the distro suffix (e.g. OpenSSH_9.6p1 Ubuntu-3ubuntu13 → OpenSSH_9.6p1)", always},
	{"motd", "MOTD & issue", "no distro/kernel version in /etc/issue, /etc/issue.net, dynamic motd off", always},
	{"nginx", "nginx", "server_tokens off: no version in headers and error pages",
		func(h *system.Host) bool { return h.Has("nginx") }},
	{"apache", "Apache", "ServerTokens Prod, ServerSignature Off, TraceEnable Off",
		func(h *system.Host) bool { return h.Has("apache2") || h.Has("httpd") }},
	{"postfix", "Postfix", "neutral SMTP greeting ($myhostname ESMTP)",
		func(h *system.Host) bool { return h.Has("postconf") }},
}

func apacheConf(h *system.Host) string {
	if h.Distro.Family == system.FamilyDebian {
		return "/etc/apache2/conf-enabled/zz-vpshield-hardening.conf"
	}
	if h.Distro.Family == system.FamilyAlpine {
		return "/etc/apache2/conf.d/zz-vpshield-hardening.conf"
	}
	return "/etc/httpd/conf.d/zz-vpshield-hardening.conf"
}

// RenderSSH builds the SSH banner drop-in. DebianBanner only exists in the
// Debian/Ubuntu OpenSSH patch set: elsewhere it would make sshd -t fail.
func RenderSSH(c Config, family system.Family) string {
	var b strings.Builder
	b.WriteString("# Managed by vpshield - banner hardening\n")
	if c.SSHVersion {
		if family == system.FamilyDebian {
			b.WriteString("DebianBanner no\n")
		}
		b.WriteString("VersionAddendum none\n")
	}
	if c.PreLogin {
		b.WriteString("Banner " + SSHBanner + "\n")
	} else {
		b.WriteString("Banner none\n")
	}
	return b.String()
}

func wrap(text string) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}
	return text + "\n"
}

func BuildPlan(h *system.Host, c Config) *plan.Plan {
	p := &plan.Plan{Title: "Banner & fingerprint hardening"}
	if c.WarnText == "" {
		c.WarnText = DefaultWarn
	}

	if c.SSHVersion || c.PreLogin {
		p.Backups = append(p.Backups, SSHDropIn)
		if c.PreLogin {
			p.Add(plan.File(SSHBanner, wrap(c.WarnText), 0o644))
		}
		p.Add(
			plan.Func("create /etc/ssh/sshd_config.d", "", func(h *system.Host) (string, error) {
				if h.DryRun {
					return "[dry-run]", nil
				}
				return "", os.MkdirAll("/etc/ssh/sshd_config.d", 0o755)
			}),
			plan.File(SSHDropIn, RenderSSH(c, h.Distro.Family), 0o600),
			plan.Func("validate sshd config", "$ sshd -t", func(h *system.Host) (string, error) {
				out, err := h.Run("sshd", "-t")
				if err != nil {
					return out, fmt.Errorf("sshd rejected the config: %w", err)
				}
				return "ok", nil
			}),
			plan.Func("reload sshd", "existing sessions are not affected", func(h *system.Host) (string, error) {
				svc := h.Distro.Service("sshd")
				h.AddRestoreHook("sh", "-c", "systemctl reload "+svc+" 2>/dev/null || rc-service "+svc+" reload")
				return h.ServiceReload(svc)
			}),
		)
		if !strings.Contains(system.ReadFile("/etc/ssh/sshd_config"), "sshd_config.d") {
			p.Warn("sshd_config has no Include for sshd_config.d: run SSH › Hardening once (it adds it), or this file is ignored")
		}
		p.Warn("the SSH protocol always announces 'SSH-2.0-OpenSSH_x.y': only the distro part can be hidden")
	}

	if c.Motd {
		issue := wrap(c.WarnText)
		p.Add(
			plan.File("/etc/issue", issue, 0o644),
			plan.File("/etc/issue.net", issue, 0o644),
			plan.File("/etc/motd", wrap(c.MotdText), 0o644),
		)
		if system.Exists("/etc/default/motd-news") {
			cur := system.ReadFile("/etc/default/motd-news")
			p.Add(plan.File("/etc/default/motd-news", strings.ReplaceAll(cur, "ENABLED=1", "ENABLED=0"), 0o644))
		}
		if scripts, _ := filepath.Glob("/etc/update-motd.d/*"); len(scripts) > 0 {
			// keep only the script that prints /etc/motd-like content harmlessly: none
			p.Add(plan.Func("disable dynamic motd scripts", strings.Join(scripts, "\n"), func(h *system.Host) (string, error) {
				n := 0
				for _, s := range scripts {
					st, err := os.Stat(s)
					if err != nil || st.Mode()&0o111 == 0 {
						continue
					}
					if err := h.Backup(s); err != nil {
						return "", err
					}
					if !h.DryRun {
						if err := os.Chmod(s, st.Mode()&^0o111); err != nil {
							return "", err
						}
					}
					n++
				}
				return fmt.Sprintf("%d scripts made non-executable", n), nil
			}))
		}
		if h.Distro.Family == system.FamilyRHEL && system.Exists("/etc/motd.d") {
			p.Warn("cockpit/insights may add files to /etc/motd.d: review them manually")
		}
	}

	if c.Nginx && h.Has("nginx") {
		p.Add(
			plan.File(nginxConf, "# Managed by vpshield\nserver_tokens off;\n", 0o644),
			plan.Func("test nginx config", "$ nginx -t", func(h *system.Host) (string, error) {
				out, err := h.Run("nginx", "-t")
				if err != nil && strings.Contains(out, "duplicate") {
					return out, fmt.Errorf("server_tokens already set elsewhere: remove it there or delete %s", nginxConf)
				}
				return out, err
			}),
			plan.Func("reload nginx", "", func(h *system.Host) (string, error) {
				h.AddRestoreHook("nginx", "-s", "reload")
				return h.ServiceReload("nginx")
			}),
		)
	}

	if c.Apache && (h.Has("apache2") || h.Has("httpd")) {
		svc, ctl := "httpd", "apachectl"
		if h.Distro.Family == system.FamilyDebian {
			svc, ctl = "apache2", "apache2ctl"
		}
		p.Add(
			plan.File(apacheConf(h), "# Managed by vpshield\nServerTokens Prod\nServerSignature Off\nTraceEnable Off\n", 0o644),
			plan.Cmd("test apache config", ctl, "configtest"),
			plan.Func("reload "+svc, "", func(h *system.Host) (string, error) {
				h.AddRestoreHook(ctl, "graceful")
				return h.ServiceReload(svc)
			}),
		)
	}

	if c.Postfix && h.Has("postconf") {
		p.Backups = append(p.Backups, "/etc/postfix/main.cf")
		p.Add(
			plan.Cmd("neutral SMTP banner", "postconf", "-e", "smtpd_banner = $myhostname ESMTP"),
			plan.Func("reload postfix", "", func(h *system.Host) (string, error) {
				h.AddRestoreHook("postfix", "reload")
				return h.Run("postfix", "reload")
			}),
		)
	}
	return p
}

// Exposure shows what a scanner currently sees (best effort, local checks).
func Exposure(h *system.Host) string {
	var b strings.Builder
	if out, err := h.Query("ssh", "-V"); err == nil {
		fmt.Fprintf(&b, "OpenSSH client/server build: %s\n", strings.TrimSpace(out))
	}
	eff, _ := h.Query("sshd", "-T")
	for _, k := range []string{"debianbanner", "versionaddendum", "banner"} {
		for _, l := range strings.Split(eff, "\n") {
			if strings.HasPrefix(l, k+" ") {
				fmt.Fprintf(&b, "sshd %s\n", l)
			}
		}
	}
	fmt.Fprintf(&b, "\n/etc/issue:\n%s\n", indent(system.ReadFile("/etc/issue")))
	fmt.Fprintf(&b, "/etc/issue.net:\n%s\n", indent(system.ReadFile("/etc/issue.net")))
	if scripts, _ := filepath.Glob("/etc/update-motd.d/*"); len(scripts) > 0 {
		active := 0
		for _, s := range scripts {
			if st, err := os.Stat(s); err == nil && st.Mode()&0o111 != 0 {
				active++
			}
		}
		fmt.Fprintf(&b, "dynamic motd scripts active: %d/%d\n", active, len(scripts))
	}
	if h.Has("nginx") {
		out, _ := h.Query("sh", "-c", "nginx -T 2>/dev/null | grep -E '^\\s*server_tokens' | head -3")
		fmt.Fprintf(&b, "nginx server_tokens: %s\n", orDefault(strings.TrimSpace(out), "not set (version exposed)"))
	}
	if h.Has("postconf") {
		out, _ := h.Query("postconf", "-h", "smtpd_banner")
		fmt.Fprintf(&b, "postfix smtpd_banner: %s\n", strings.TrimSpace(out))
	}
	return b.String()
}

func indent(s string) string {
	s = strings.TrimRight(s, "\n")
	if s == "" {
		return "    (empty)"
	}
	return "    " + strings.ReplaceAll(s, "\n", "\n    ")
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}
