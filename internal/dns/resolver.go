package dns

import (
	"fmt"
	"net"
	"os"
	"strings"

	"vpshield/internal/plan"
	"vpshield/internal/system"
)

type Provider struct {
	ID, Name string
	Servers  []string // IPv4 and IPv6
	TLSName  string   // DoT server name
}

var Providers = []Provider{
	{"cloudflare", "Cloudflare (1.1.1.1)", []string{"1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"}, "cloudflare-dns.com"},
	{"cloudflare-security", "Cloudflare for Families, malware blocking (1.1.1.2)", []string{"1.1.1.2", "1.0.0.2", "2606:4700:4700::1112", "2606:4700:4700::1002"}, "security.cloudflare-dns.com"},
	{"quad9", "Quad9, malware blocking (9.9.9.9)", []string{"9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"}, "dns.quad9.net"},
	{"google", "Google (8.8.8.8)", []string{"8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"}, "dns.google"},
	{"adguard", "AdGuard, ad blocking (94.140.14.14)", []string{"94.140.14.14", "94.140.15.15", "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff"}, "dns.adguard-dns.com"},
}

func ProviderByID(id string) (Provider, bool) {
	for _, p := range Providers {
		if p.ID == id {
			return p, true
		}
	}
	return Provider{}, false
}

type ResolverConfig struct {
	Primary  Provider
	Fallback *Provider
	DoT      string // no | opportunistic | yes (systemd-resolved only)
	DNSSEC   string // no | allow-downgrade | yes
	IPv6     bool   // include IPv6 servers
}

const (
	resolvedDropIn = "/etc/systemd/resolved.conf.d/vpshield.conf"
	nmDropIn       = "/etc/NetworkManager/conf.d/90-vpshield-dns.conf"
)

// Backend reports how the resolver is managed on this host.
func Backend(h *system.Host) string {
	if h.Distro.Init == system.InitSystemd && h.ServiceActive("systemd-resolved") {
		return "systemd-resolved"
	}
	return "resolv.conf"
}

func servers(p Provider, v6 bool) []string {
	var out []string
	for _, s := range p.Servers {
		if !v6 && strings.Contains(s, ":") {
			continue
		}
		out = append(out, s)
	}
	return out
}

func RenderResolved(c ResolverConfig) string {
	withName := func(p Provider) string {
		var parts []string
		for _, s := range servers(p, c.IPv6) {
			if p.TLSName != "" {
				parts = append(parts, s+"#"+p.TLSName)
			} else {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, " ")
	}
	var b strings.Builder
	b.WriteString("# Managed by vpshield\n[Resolve]\n")
	fmt.Fprintf(&b, "DNS=%s\n", withName(c.Primary))
	if c.Fallback != nil {
		fmt.Fprintf(&b, "FallbackDNS=%s\n", withName(*c.Fallback))
	}
	fmt.Fprintf(&b, "DNSOverTLS=%s\n", c.DoT)
	fmt.Fprintf(&b, "DNSSEC=%s\n", c.DNSSEC)
	b.WriteString("Domains=~.\n")
	return b.String()
}

func RenderResolvConf(c ResolverConfig) string {
	var b strings.Builder
	b.WriteString("# Managed by vpshield\n")
	n := 0
	add := func(p Provider) {
		for _, s := range servers(p, c.IPv6) {
			if n < 3 { // glibc only uses the first 3
				fmt.Fprintf(&b, "nameserver %s\n", s)
				n++
			}
		}
	}
	add(c.Primary)
	if c.Fallback != nil {
		add(*c.Fallback)
	}
	b.WriteString("options edns0 timeout:2 attempts:2\n")
	return b.String()
}

// BuildResolverPlan writes the right files for this host and tests resolution.
func BuildResolverPlan(h *system.Host, c ResolverConfig) *plan.Plan {
	p := &plan.Plan{Title: "Configure DNS resolver"}
	switch Backend(h) {
	case "systemd-resolved":
		p.Add(
			plan.File(resolvedDropIn, RenderResolved(c), 0o644),
			plan.RestartService("systemd-resolved"),
		)
		if c.DoT == "yes" {
			p.Warn("DNSOverTLS=yes: if port 853 is blocked by your provider, DNS stops working. 'opportunistic' is safer.")
		}
	default:
		if c.DoT != "no" {
			p.Warn("DNS-over-TLS needs systemd-resolved; this host uses plain /etc/resolv.conf, DoT ignored")
		}
		if h.ServiceActive("NetworkManager") {
			p.Add(
				plan.File(nmDropIn, "# Managed by vpshield\n[main]\ndns=none\n", 0o644),
				plan.OptCmd("reload NetworkManager", "systemctl", "reload", "NetworkManager"),
			)
		}
		if system.Exists("/etc/dhcp/dhclient.conf") {
			conf := system.ReadFile("/etc/dhcp/dhclient.conf")
			if !strings.Contains(conf, "vpshield") {
				var list []string
				for _, s := range servers(c.Primary, false) {
					list = append(list, s)
				}
				conf = strings.TrimRight(conf, "\n") + "\n# vpshield: keep our resolvers on lease renewal\nsupersede domain-name-servers " + strings.Join(list, ", ") + ";\n"
				p.Add(plan.File("/etc/dhcp/dhclient.conf", conf, 0o644))
			}
		}
		if h.Distro.Family == system.FamilyAlpine {
			conf := system.ReadFile("/etc/udhcpc/udhcpc.conf")
			if !strings.Contains(conf, "RESOLV_CONF") {
				p.Add(plan.File("/etc/udhcpc/udhcpc.conf", strings.TrimRight(conf, "\n")+"\n# vpshield\nRESOLV_CONF=\"no\"\n", 0o644))
			}
		}
		if st, err := os.Lstat("/etc/resolv.conf"); err == nil && st.Mode()&os.ModeSymlink != 0 {
			p.Warn("/etc/resolv.conf is a symlink: it will be replaced by a regular file (original link saved in the snapshot)")
		}
		p.Add(plan.File("/etc/resolv.conf", RenderResolvConf(c), 0o644))
	}
	p.Add(plan.Step{
		Title:    "test resolution",
		Detail:   "lookup cloudflare.com",
		Optional: true,
		Run: func(h *system.Host) (string, error) {
			if h.DryRun {
				return "[dry-run] skipped", nil
			}
			addrs, err := net.LookupHost("cloudflare.com")
			if err != nil {
				return "", err
			}
			return strings.Join(addrs, " "), nil
		},
	})
	return p
}

// ResolverStatus is a human readable dump of the current resolver setup.
func ResolverStatus(h *system.Host) string {
	if Backend(h) == "systemd-resolved" && h.Has("resolvectl") {
		out, err := h.Query("resolvectl", "status")
		if err == nil {
			return "backend: systemd-resolved\n\n" + out
		}
	}
	return "backend: /etc/resolv.conf\n\n" + system.ReadFile("/etc/resolv.conf")
}
