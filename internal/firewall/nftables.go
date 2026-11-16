package firewall

import (
	"fmt"
	"regexp"
	"strings"

	"vpshield/internal/plan"
	"vpshield/internal/system"
)

// NFT is a native nftables backend. vpshield owns one table ("inet vpshield")
// and the distro's main nftables config file; the rule list lives in
// state.json and the file is regenerated from it on every change.
type NFT struct {
	h  *system.Host
	st *system.State
}

const nftTable = "vpshield"

func (n *NFT) Name() string             { return "nftables" }
func (n *NFT) Installed() bool          { return n.h.Has("nft") }
func (n *NFT) Fail2banAction() string   { return "nftables-multiport" }
func (n *NFT) Fail2banAllPorts() string { return "nftables-allports" }

func (n *NFT) Active() bool {
	if !n.Installed() {
		return false
	}
	_, err := n.h.Query("nft", "list", "table", "inet", nftTable)
	return err == nil
}

// ConfPath is the file the distro's nftables service loads at boot.
func (n *NFT) ConfPath() string {
	switch n.h.Distro.Family {
	case system.FamilyAlpine:
		return "/etc/nftables.nft"
	case system.FamilyRHEL:
		return "/etc/sysconfig/nftables.conf"
	}
	return "/etc/nftables.conf"
}

func (n *NFT) rate() string {
	if n.st.LimitRate != "" {
		return n.st.LimitRate
	}
	return "10/minute"
}

func (n *NFT) InstallSteps() []plan.Step {
	if n.Installed() {
		return nil
	}
	return []plan.Step{plan.Install(n.h, "nftables")}
}

var commentSafe = regexp.MustCompile(`[^a-zA-Z0-9 _.:/@-]`)

// RenderNFT produces the full ruleset file. Exported for tests.
func RenderNFT(rules []system.PortRule, rate string) string {
	var b strings.Builder
	b.WriteString("#!/usr/sbin/nft -f\n")
	b.WriteString("# Managed by vpshield - manual edits are overwritten. Use the vpshield TUI.\n")
	b.WriteString("# Re-runnable: the table is created, deleted and rebuilt atomically.\n\n")
	fmt.Fprintf(&b, "table inet %s\ndelete table inet %s\n\n", nftTable, nftTable)
	fmt.Fprintf(&b, "table inet %s {\n", nftTable)
	for _, r := range rules {
		if !r.Limit {
			continue
		}
		fmt.Fprintf(&b, "\tset lim4_%s_%d { type ipv4_addr; flags dynamic, timeout; timeout 2m; size 65535; }\n", r.Proto, r.Port)
		fmt.Fprintf(&b, "\tset lim6_%s_%d { type ipv6_addr; flags dynamic, timeout; timeout 2m; size 65535; }\n", r.Proto, r.Port)
	}
	b.WriteString("\n\tchain input {\n")
	b.WriteString("\t\ttype filter hook input priority filter; policy drop;\n\n")
	b.WriteString("\t\tct state vmap { invalid : drop, established : accept, related : accept }\n")
	b.WriteString("\t\tiifname \"lo\" accept\n")
	b.WriteString("\t\tmeta l4proto ipv6-icmp accept comment \"IPv6 needs ICMPv6 (ND, PMTU)\"\n")
	b.WriteString("\t\tip protocol icmp icmp type echo-request limit rate 10/second accept\n")
	b.WriteString("\t\tip protocol icmp icmp type { destination-unreachable, time-exceeded, parameter-problem } accept\n")
	b.WriteString("\t\tudp sport 67 udp dport 68 accept comment \"DHCPv4 client\"\n")
	b.WriteString("\t\tudp sport 547 udp dport 546 accept comment \"DHCPv6 client\"\n\n")
	for _, r := range rules {
		c := strings.TrimSpace(commentSafe.ReplaceAllString(r.Comment, ""))
		if r.Limit {
			fmt.Fprintf(&b, "\t\t%s dport %d ct state new add @lim4_%s_%d { ip saddr limit rate over %s burst 5 packets } drop\n", r.Proto, r.Port, r.Proto, r.Port, rate)
			fmt.Fprintf(&b, "\t\t%s dport %d ct state new add @lim6_%s_%d { ip6 saddr limit rate over %s burst 5 packets } drop\n", r.Proto, r.Port, r.Proto, r.Port, rate)
		}
		if c != "" {
			fmt.Fprintf(&b, "\t\t%s dport %d accept comment \"%s\"\n", r.Proto, r.Port, c)
		} else {
			fmt.Fprintf(&b, "\t\t%s dport %d accept\n", r.Proto, r.Port)
		}
	}
	b.WriteString("\n\t\t# dropped new connections are logged (rate limited) for the fail2ban portscan jail\n")
	b.WriteString("\t\tct state new limit rate 20/second log prefix \"vpshield-drop: \" level info\n")
	b.WriteString("\t}\n}\n")
	return b.String()
}

// apply writes the config for the given rule list, loads it and saves state.
func (n *NFT) apply(h *system.Host, rules []system.PortRule) (string, error) {
	sortRules(rules)
	content := RenderNFT(rules, n.rate())
	path := n.ConfPath()
	if err := h.WriteFile(path, []byte(content), 0o644); err != nil {
		return "", err
	}
	if out, err := h.Run("nft", "-c", "-f", path); err != nil {
		return out, fmt.Errorf("ruleset check failed, not loaded: %w", err)
	}
	h.AddRestoreHook("nft", "-f", path)
	out, err := h.Run("nft", "-f", path)
	if err != nil {
		return out, err
	}
	n.st.Ports = rules
	n.st.FirewallBackend = "nftables"
	return fmt.Sprintf("%d rules loaded from %s", len(rules), path), h.SaveState(n.st)
}

func upsert(rules []system.PortRule, r system.PortRule) []system.PortRule {
	out := []system.PortRule{}
	for _, x := range rules {
		if x.Port == r.Port && x.Proto == r.Proto {
			continue
		}
		out = append(out, x)
	}
	return append(out, r)
}

func (n *NFT) EnableSteps(sshPort int) []plan.Step {
	sshRule := system.PortRule{Port: sshPort, Proto: "tcp", Limit: true, Comment: "ssh"}
	preview := upsert(append([]system.PortRule(nil), n.st.Ports...), sshRule)
	old := system.ReadFile(n.ConfPath())
	steps := []plan.Step{
		plan.Func("generate & load nftables ruleset", RenderNFT(preview, n.rate()), func(h *system.Host) (string, error) {
			// computed at run time so earlier steps of the same plan are kept
			return n.apply(h, upsert(append([]system.PortRule(nil), n.st.Ports...), sshRule))
		}),
	}
	// The stock Alpine/Arch config defines its own "inet filter" table with a
	// drop policy that only allows port 22. We replaced that file, so drop
	// the runtime copy too, otherwise a non-22 SSH port stays blocked.
	if strings.Contains(old, "table inet filter") {
		steps = append(steps, plan.OptCmd("remove distro default table inet filter", "nft", "delete", "table", "inet", "filter"))
	}
	return append(steps, plan.EnableService("nftables"))
}

func (n *NFT) DisableSteps() []plan.Step {
	return []plan.Step{
		plan.File(n.ConfPath(), "#!/usr/sbin/nft -f\n# vpshield firewall disabled\n", 0o644),
		plan.OptCmd("delete table inet "+nftTable, "nft", "delete", "table", "inet", nftTable),
	}
}

func (n *NFT) AllowSteps(r system.PortRule) []plan.Step {
	preview := upsert(append([]system.PortRule(nil), n.st.Ports...), r)
	return []plan.Step{plan.Func("allow "+ruleKey(r.Port, r.Proto), RenderNFT(preview, n.rate()), func(h *system.Host) (string, error) {
		return n.apply(h, upsert(append([]system.PortRule(nil), n.st.Ports...), r))
	})}
}

func without(rules []system.PortRule, port int, proto string) []system.PortRule {
	var out []system.PortRule
	for _, x := range rules {
		if !(x.Port == port && x.Proto == proto) {
			out = append(out, x)
		}
	}
	return out
}

func (n *NFT) RemoveSteps(port int, proto string) []plan.Step {
	return []plan.Step{plan.Func("remove "+ruleKey(port, proto), RenderNFT(without(n.st.Ports, port, proto), n.rate()), func(h *system.Host) (string, error) {
		return n.apply(h, without(n.st.Ports, port, proto))
	})}
}

func (n *NFT) Status() string {
	if !n.Installed() {
		return "nftables is not installed"
	}
	out, err := n.h.Query("nft", "list", "table", "inet", nftTable)
	if err != nil {
		return "vpshield nftables table is not loaded (firewall inactive)"
	}
	return out
}

func (n *NFT) Rules() ([]system.PortRule, error) {
	if !n.Active() {
		return nil, nil
	}
	return append([]system.PortRule(nil), n.st.Ports...), nil
}

func (n *NFT) StateFiles() []string { return []string{n.ConfPath()} }
func (n *NFT) ReloadCmd() []string  { return []string{"nft", "-f", n.ConfPath()} }
