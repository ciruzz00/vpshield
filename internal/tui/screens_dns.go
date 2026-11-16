package tui

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"

	"vpshield/internal/dns"
	"vpshield/internal/system"
)

// ---- Cloudflare -----------------------------------------------------------

func cfClient() (*dns.Client, error) {
	tok := system.ReadSecret(dns.TokenFile)
	if tok == "" {
		return nil, fmt.Errorf("no Cloudflare API token: set it first (DNS records › API token)")
	}
	return dns.NewClient(tok), nil
}

// cfWrite runs a mutating API call unless we are in dry-run.
func cfWrite(c *ctx, what string, fn func() error) (string, error) {
	if c.h.DryRun {
		return "[dry-run] would " + what, nil
	}
	if err := fn(); err != nil {
		return "", err
	}
	return what, nil
}

func cfMenu(c *ctx) Screen {
	m := newMenu(c, "DNS records",
		menuItem{label: "API token", desc: "set / replace the Cloudflare API token (Zone.DNS edit)", action: func() tea.Cmd { return push(cfTokenForm(c)) }},
		menuItem{label: "Records", desc: "list, add, edit, delete records of a zone", action: func() tea.Cmd {
			return withZone(c, false, func() tea.Cmd { return push(cfRecords(c)) })
		}},
		menuItem{label: "Point a name to this server", desc: "A/AAAA with the detected public IP", action: func() tea.Cmd {
			return withZone(c, false, func() tea.Cmd { return push(cfPointForm(c)) })
		}},
		menuItem{label: "Email & CAA records", desc: "SPF, DMARC, CAA for Let's Encrypt", action: func() tea.Cmd {
			return withZone(c, false, func() tea.Cmd { return push(cfMailForm(c)) })
		}},
		menuItem{label: "Switch zone", desc: "choose another domain", action: func() tea.Cmd {
			return withZone(c, true, func() tea.Cmd { return nil })
		}},
		menuItem{label: "Remove API token", desc: "delete the stored token", action: func() tea.Cmd {
			return push(confirmScreen(c, "Remove token", "Delete the stored Cloudflare token?", "", func() tea.Cmd {
				return tea.Sequence(pop(), action(func() (string, error) {
					c.st.CFZoneID, c.st.CFZoneName = "", ""
					_ = c.h.SaveState(c.st)
					return "token removed", c.h.DeleteSecret(dns.TokenFile)
				}))
			}))
		}},
	)
	m.header = func() string {
		tok := system.ReadSecret(dns.TokenFile) != ""
		zone := c.st.CFZoneName
		if zone == "" {
			zone = sMuted.Render("none")
		}
		return sMuted.Render("token: ") + onOff(tok, "stored", "missing") + sMuted.Render("   zone: ") + sText.Render(zone)
	}
	return m
}

func cfTokenForm(c *ctx) Screen {
	var tok string
	return newForm(c, "Cloudflare API token", func() tea.Cmd {
		t := strings.TrimSpace(tok)
		return tea.Sequence(pop(), action(func() (string, error) {
			if err := dns.NewClient(t).Verify(); err != nil {
				return "", fmt.Errorf("token rejected: %w", err)
			}
			c.st.CFZoneID, c.st.CFZoneName = "", ""
			_ = c.h.SaveState(c.st)
			return "token verified and stored in " + system.ConfigDir + "/" + dns.TokenFile + " (0600)", c.h.WriteSecret(dns.TokenFile, t)
		}))
	}, huh.NewGroup(
		huh.NewNote().Title("Create it at dash.cloudflare.com › My Profile › API Tokens").
			Description("Template \"Edit zone DNS\", limited to the zones you need. The global API key is NOT supported on purpose."),
		huh.NewInput().Title("Token").EchoMode(huh.EchoModePassword).Value(&tok).Validate(func(s string) error {
			if len(strings.TrimSpace(s)) < 30 {
				return fmt.Errorf("too short for a Cloudflare token")
			}
			return nil
		}),
	))
}

// withZone makes sure a zone is selected, then runs next.
func withZone(c *ctx, force bool, next func() tea.Cmd) tea.Cmd {
	return func() tea.Msg {
		cl, err := cfClient()
		if err != nil {
			return actionDoneMsg{err: err}
		}
		if c.st.CFZoneID != "" && !force {
			if cmd := next(); cmd != nil {
				return cmd()
			}
			return nil
		}
		zones, err := cl.Zones()
		if err != nil {
			return actionDoneMsg{err: err}
		}
		if len(zones) == 0 {
			return actionDoneMsg{err: fmt.Errorf("the token cannot see any zone")}
		}
		if len(zones) == 1 && !force {
			c.st.CFZoneID, c.st.CFZoneName = zones[0].ID, zones[0].Name
			_ = c.h.SaveState(c.st)
			if cmd := next(); cmd != nil {
				return cmd()
			}
			return nil
		}
		return pushMsg{zonePicker(c, zones, next)}
	}
}

func zonePicker(c *ctx, zones []dns.Zone, next func() tea.Cmd) Screen {
	sel := c.st.CFZoneID
	var opts []huh.Option[string]
	for _, z := range zones {
		opts = append(opts, huh.NewOption(z.Name+"  ("+z.Status+")", z.ID))
	}
	return newForm(c, "Select zone", func() tea.Cmd {
		for _, z := range zones {
			if z.ID == sel {
				c.st.CFZoneID, c.st.CFZoneName = z.ID, z.Name
			}
		}
		_ = c.h.SaveState(c.st)
		if n := next(); n != nil {
			return tea.Sequence(pop(), n)
		}
		return tea.Sequence(pop(), action(func() (string, error) { return "zone: " + c.st.CFZoneName, nil }))
	}, huh.NewGroup(huh.NewSelect[string]().Title("Zone").Options(opts...).Value(&sel)))
}

func cfRecords(c *ctx) Screen {
	cols := []table.Column{{Title: "Type", Width: 6}, {Title: "Name", Width: 30}, {Title: "Content", Width: 34}, {Title: "Proxy", Width: 5}, {Title: "TTL", Width: 6}}
	var records []dns.Record
	find := func(row table.Row) (dns.Record, bool) {
		for _, r := range records {
			if r.Type == row[0] && r.Name == row[1] && truncate(recordContent(r), 200) == row[2] {
				return r, true
			}
		}
		return dns.Record{}, false
	}
	loader := func() ([]table.Row, error) {
		cl, err := cfClient()
		if err != nil {
			return nil, err
		}
		rs, err := cl.Records(c.st.CFZoneID)
		if err != nil {
			return nil, err
		}
		records = rs
		var rows []table.Row
		for _, r := range rs {
			proxy := ""
			if r.Proxied != nil && *r.Proxied {
				proxy = "☁ on"
			}
			ttl := "auto"
			if r.TTL > 1 {
				ttl = strconv.Itoa(r.TTL)
			}
			rows = append(rows, table.Row{r.Type, r.Name, truncate(recordContent(r), 200), proxy, ttl})
		}
		return rows, nil
	}
	t := newTable(c, c.st.CFZoneName, cols, loader,
		tableKey{key: "a", help: "add", fn: func(table.Row) tea.Cmd { return push(cfRecordForm(c, nil)) }},
		tableKey{key: "e", help: "edit", needRow: true, fn: func(row table.Row) tea.Cmd {
			if r, ok := find(row); ok {
				return push(cfRecordForm(c, &r))
			}
			return nil
		}},
		tableKey{key: "d", help: "delete", needRow: true, fn: func(row table.Row) tea.Cmd {
			r, ok := find(row)
			if !ok {
				return nil
			}
			return push(confirmScreen(c, "Delete record", fmt.Sprintf("Delete %s %s?", r.Type, r.Name), recordContent(r), func() tea.Cmd {
				return tea.Sequence(pop(), action(func() (string, error) {
					cl, err := cfClient()
					if err != nil {
						return "", err
					}
					return cfWrite(c, "delete "+r.Type+" "+r.Name, func() error { return cl.Delete(c.st.CFZoneID, r.ID) })
				}))
			}))
		}},
	)
	return t
}

func recordContent(r dns.Record) string {
	if r.Content != "" {
		if r.Priority != nil && r.Type == "MX" {
			return fmt.Sprintf("%d %s", *r.Priority, r.Content)
		}
		return r.Content
	}
	if r.Data != nil {
		return fmt.Sprintf("%v %v %v", r.Data["flags"], r.Data["tag"], r.Data["value"])
	}
	return ""
}

var editableTypes = []string{"A", "AAAA", "CNAME", "MX", "TXT", "CAA", "NS"}

func cfRecordForm(c *ctx, existing *dns.Record) Screen {
	typ, name, content := "A", "", ""
	ttl := 1
	proxied := false
	prio := "10"
	title := "Add record"
	if existing != nil {
		title = "Edit record"
		typ, name, content, ttl = existing.Type, existing.Name, existing.Content, existing.TTL
		if existing.Proxied != nil {
			proxied = *existing.Proxied
		}
		if existing.Priority != nil {
			prio = strconv.Itoa(*existing.Priority)
		}
		if typ == "CAA" {
			content = recordContent(*existing)
		}
	}
	var typeOpts []huh.Option[string]
	for _, t := range editableTypes {
		typeOpts = append(typeOpts, huh.NewOption(t, t))
	}
	zone := c.st.CFZoneName
	return newForm(c, title, func() tea.Cmd {
		r := dns.Record{Type: typ, Name: dns.FQDN(name, zone), TTL: ttl}
		switch typ {
		case "CAA":
			f := strings.Fields(content)
			flags, _ := strconv.Atoi(f[0])
			r.Data = map[string]any{"flags": flags, "tag": f[1], "value": strings.Trim(strings.Join(f[2:], " "), `"`)}
		case "MX":
			p, _ := strconv.Atoi(prio)
			r.Content, r.Priority = strings.TrimSpace(content), dns.IntPtr(p)
		default:
			r.Content = strings.TrimSpace(content)
		}
		if dns.Proxiable(typ) {
			r.Proxied = dns.BoolPtr(proxied)
		}
		if existing != nil {
			r.ID = existing.ID
		}
		return tea.Sequence(pop(), action(func() (string, error) {
			cl, err := cfClient()
			if err != nil {
				return "", err
			}
			verb := "create"
			if r.ID != "" {
				verb = "update"
			}
			return cfWrite(c, fmt.Sprintf("%s %s %s", verb, r.Type, r.Name), func() error {
				var err error
				if r.ID != "" {
					_, err = cl.Update(c.st.CFZoneID, r)
				} else {
					_, err = cl.Create(c.st.CFZoneID, r)
				}
				return err
			})
		}))
	},
		huh.NewGroup(
			huh.NewSelect[string]().Title("Type").Options(typeOpts...).Value(&typ),
			huh.NewInput().Title("Name").Description("@ for the zone apex, or a subdomain like www (zone: "+zone+")").Value(&name).
				Validate(func(s string) error {
					if strings.ContainsAny(s, " /") {
						return fmt.Errorf("invalid name")
					}
					return nil
				}),
			huh.NewInput().Title("Content").DescriptionFunc(func() string {
				switch typ {
				case "A":
					return "IPv4 address"
				case "AAAA":
					return "IPv6 address"
				case "CNAME":
					return "target hostname"
				case "MX":
					return "mail server hostname"
				case "TXT":
					return "text, e.g. v=spf1 mx -all"
				case "CAA":
					return `flags tag value, e.g. 0 issue "letsencrypt.org"`
				}
				return ""
			}, &typ).Value(&content).Validate(func(s string) error {
				if typ == "CAA" {
					if len(strings.Fields(s)) < 3 {
						return fmt.Errorf(`format: 0 issue "letsencrypt.org"`)
					}
					return nil
				}
				return dns.ValidateContent(typ, s)
			}),
			huh.NewSelect[int]().Title("TTL").Options(
				huh.NewOption("auto", 1), huh.NewOption("5 min", 300), huh.NewOption("1 hour", 3600), huh.NewOption("1 day", 86400),
			).Value(&ttl),
		),
		huh.NewGroup(
			huh.NewInput().Title("MX priority").Value(&prio).Validate(func(s string) error {
				if n, err := strconv.Atoi(s); err != nil || n < 0 || n > 65535 {
					return fmt.Errorf("0-65535")
				}
				return nil
			}),
		).WithHideFunc(func() bool { return typ != "MX" }),
		huh.NewGroup(
			huh.NewConfirm().Title("Proxy through Cloudflare (orange cloud)?").
				Description("hides your IP for HTTP(S). SSH and other non-web ports do NOT work through the proxy.").Value(&proxied),
		).WithHideFunc(func() bool { return !dns.Proxiable(typ) }),
	)
}

func cfPointForm(c *ctx) Screen {
	name := "@"
	v6 := true
	proxied := false
	zone := c.st.CFZoneName
	return newForm(c, "Point name to this server", func() tea.Cmd {
		fq := dns.FQDN(name, zone)
		return tea.Sequence(pop(), action(func() (string, error) {
			cl, err := cfClient()
			if err != nil {
				return "", err
			}
			ip4, err := dns.PublicIP(false)
			if err != nil {
				return "", fmt.Errorf("cannot detect public IPv4: %w", err)
			}
			msg := []string{}
			out, err := cfWrite(c, "set A "+fq+" → "+ip4, func() error {
				_, _, err := cl.Upsert(c.st.CFZoneID, dns.Record{Type: "A", Name: fq, Content: ip4, TTL: 1, Proxied: dns.BoolPtr(proxied)})
				return err
			})
			if err != nil {
				return "", err
			}
			msg = append(msg, out)
			if v6 {
				if ip6, err := dns.PublicIP(true); err == nil {
					out, err := cfWrite(c, "AAAA → "+ip6, func() error {
						_, _, err := cl.Upsert(c.st.CFZoneID, dns.Record{Type: "AAAA", Name: fq, Content: ip6, TTL: 1, Proxied: dns.BoolPtr(proxied)})
						return err
					})
					if err != nil {
						return "", err
					}
					msg = append(msg, out)
				} else {
					msg = append(msg, "no IPv6 detected")
				}
			}
			return strings.Join(msg, ", "), nil
		}))
	}, huh.NewGroup(
		huh.NewInput().Title("Name").Description("@ = "+zone+", or e.g. vps, panel, mail").Value(&name),
		huh.NewConfirm().Title("Also create AAAA if the server has IPv6?").Value(&v6),
		huh.NewConfirm().Title("Proxied (orange cloud)?").Description("only for web traffic; use a separate DNS-only name for SSH").Value(&proxied),
	))
}

func cfMailForm(c *ctx) Screen {
	spf := "v=spf1 mx -all"
	dmarc := "quarantine"
	rua := ""
	caa := true
	zone := c.st.CFZoneName
	return newForm(c, "Email & CAA records", func() tea.Cmd {
		return tea.Sequence(pop(), action(func() (string, error) {
			cl, err := cfClient()
			if err != nil {
				return "", err
			}
			existing, err := cl.Records(c.st.CFZoneID)
			if err != nil {
				return "", err
			}
			var done []string
			upsertTXT := func(name, prefix, value string) error {
				for _, r := range existing {
					if r.Type == "TXT" && r.Name == name && strings.HasPrefix(strings.Trim(r.Content, `"`), prefix) {
						r.Content = value
						out, err := cfWrite(c, "update TXT "+name, func() error { _, err := cl.Update(c.st.CFZoneID, r); return err })
						done = append(done, out)
						return err
					}
				}
				out, err := cfWrite(c, "create TXT "+name, func() error {
					_, err := cl.Create(c.st.CFZoneID, dns.Record{Type: "TXT", Name: name, Content: value, TTL: 1})
					return err
				})
				done = append(done, out)
				return err
			}
			if spf != "" {
				if err := upsertTXT(zone, "v=spf1", spf); err != nil {
					return "", err
				}
			}
			if dmarc != "" {
				v := "v=DMARC1; p=" + dmarc
				if strings.TrimSpace(rua) != "" {
					v += "; rua=mailto:" + strings.TrimSpace(rua)
				}
				if err := upsertTXT("_dmarc."+zone, "v=DMARC1", v); err != nil {
					return "", err
				}
			}
			if caa {
				out, err := cfWrite(c, "create CAA letsencrypt.org", func() error {
					_, err := cl.Create(c.st.CFZoneID, dns.Record{Type: "CAA", Name: zone, TTL: 1,
						Data: map[string]any{"flags": 0, "tag": "issue", "value": "letsencrypt.org"}})
					return err
				})
				if err != nil && !strings.Contains(err.Error(), "already exists") {
					return "", err
				}
				done = append(done, out)
			}
			return strings.Join(done, ", "), nil
		}))
	}, huh.NewGroup(
		huh.NewSelect[string]().Title("SPF").Options(
			huh.NewOption("v=spf1 mx -all  (only MX hosts send mail)", "v=spf1 mx -all"),
			huh.NewOption("v=spf1 a mx -all  (MX + this A record)", "v=spf1 a mx -all"),
			huh.NewOption("v=spf1 -all  (domain never sends mail)", "v=spf1 -all"),
			huh.NewOption("skip", ""),
		).Value(&spf),
		huh.NewSelect[string]().Title("DMARC policy").Options(
			huh.NewOption("none (monitor only)", "none"), huh.NewOption("quarantine (recommended)", "quarantine"),
			huh.NewOption("reject", "reject"), huh.NewOption("skip", ""),
		).Value(&dmarc),
		huh.NewInput().Title("DMARC reports to (rua)").Placeholder("dmarc@"+zone+"  (optional)").Value(&rua),
		huh.NewConfirm().Title("CAA: only Let's Encrypt may issue certificates?").Value(&caa),
	))
}

// ---- resolver -------------------------------------------------------------

func resolverMenu(c *ctx) Screen {
	return newMenu(c, "DNS resolver",
		menuItem{label: "Current resolver", desc: "", action: func() tea.Cmd {
			return push(newText(c, "Resolver", func() string { return dns.ResolverStatus(c.h) }))
		}},
		menuItem{label: "Configure", desc: "provider, fallback, DNS-over-TLS, DNSSEC", action: func() tea.Cmd { return push(resolverForm(c)) }},
	)
}

func resolverForm(c *ctx) Screen {
	backend := dns.Backend(c.h)
	primary, fallback := "quad9", "cloudflare"
	dot, dnssec := "opportunistic", "allow-downgrade"
	v6 := true
	var popts, fopts []huh.Option[string]
	for _, p := range dns.Providers {
		popts = append(popts, huh.NewOption(p.Name, p.ID))
		fopts = append(fopts, huh.NewOption(p.Name, p.ID))
	}
	fopts = append(fopts, huh.NewOption("none", ""))
	return newForm(c, "Resolver", func() tea.Cmd {
		pp, _ := dns.ProviderByID(primary)
		cfg := dns.ResolverConfig{Primary: pp, DoT: dot, DNSSEC: dnssec, IPv6: v6}
		if fp, ok := dns.ProviderByID(fallback); ok && fallback != primary {
			cfg.Fallback = &fp
		}
		return replace(newPlan(c, dns.BuildResolverPlan(c.h, cfg), nil))
	},
		huh.NewGroup(
			huh.NewNote().Title("Backend: "+backend),
			huh.NewSelect[string]().Title("Primary resolver").Options(popts...).Value(&primary),
			huh.NewSelect[string]().Title("Fallback").Options(fopts...).Value(&fallback),
			huh.NewConfirm().Title("Include IPv6 resolvers?").Description("say no if the server has no IPv6").Value(&v6),
		),
		huh.NewGroup(
			huh.NewSelect[string]().Title("DNS-over-TLS").Options(
				huh.NewOption("opportunistic (encrypt when possible, recommended)", "opportunistic"),
				huh.NewOption("yes (strict, fails if 853 blocked)", "yes"),
				huh.NewOption("no", "no"),
			).Value(&dot),
			huh.NewSelect[string]().Title("DNSSEC validation").Options(
				huh.NewOption("allow-downgrade (recommended)", "allow-downgrade"),
				huh.NewOption("yes (strict)", "yes"), huh.NewOption("no", "no"),
			).Value(&dnssec),
		).WithHideFunc(func() bool { return backend != "systemd-resolved" }),
	)
}
