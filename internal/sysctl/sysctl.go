// Package sysctl applies a curated set of kernel/network hardening knobs.
package sysctl

import (
	"fmt"
	"os"
	"strings"

	"vpshield/internal/plan"
	"vpshield/internal/system"
)

const File = "/etc/sysctl.d/99-vpshield.conf"

type Item struct {
	ID      string
	Desc    string
	Values  map[string]string // key -> value
	Default bool              // preselected
	// Skip, when non-nil, returns a reason this item should not be applied.
	Skip func(h *system.Host) string
}

func routing(h *system.Host) string {
	for _, b := range []string{"docker", "podman", "libvirtd", "wg", "tailscale", "k3s", "kubelet", "lxc"} {
		if h.Has(b) {
			return b + " detected: needs IP forwarding"
		}
	}
	return ""
}

var Items = []Item{
	{ID: "syncookies", Desc: "SYN flood protection (tcp_syncookies)", Default: true,
		Values: map[string]string{"net.ipv4.tcp_syncookies": "1", "net.ipv4.tcp_max_syn_backlog": "4096", "net.ipv4.tcp_synack_retries": "3"}},
	{ID: "rpfilter", Desc: "anti-spoofing reverse path filter (loose mode, safe with multiple NICs)", Default: true,
		Values: map[string]string{"net.ipv4.conf.all.rp_filter": "2", "net.ipv4.conf.default.rp_filter": "2"}},
	{ID: "redirects", Desc: "ignore/send no ICMP redirects (MITM)", Default: true,
		Values: map[string]string{
			"net.ipv4.conf.all.accept_redirects": "0", "net.ipv4.conf.default.accept_redirects": "0",
			"net.ipv4.conf.all.secure_redirects": "0", "net.ipv4.conf.default.secure_redirects": "0",
			"net.ipv6.conf.all.accept_redirects": "0", "net.ipv6.conf.default.accept_redirects": "0",
			"net.ipv4.conf.all.send_redirects": "0", "net.ipv4.conf.default.send_redirects": "0",
		}},
	{ID: "sourceroute", Desc: "drop source-routed packets", Default: true,
		Values: map[string]string{
			"net.ipv4.conf.all.accept_source_route": "0", "net.ipv4.conf.default.accept_source_route": "0",
			"net.ipv6.conf.all.accept_source_route": "0", "net.ipv6.conf.default.accept_source_route": "0",
		}},
	{ID: "martians", Desc: "log packets with impossible addresses", Default: true,
		Values: map[string]string{"net.ipv4.conf.all.log_martians": "1", "net.ipv4.conf.default.log_martians": "1"}},
	{ID: "icmp", Desc: "ignore broadcast pings and bogus ICMP errors", Default: true,
		Values: map[string]string{"net.ipv4.icmp_echo_ignore_broadcasts": "1", "net.ipv4.icmp_ignore_bogus_error_responses": "1"}},
	{ID: "kernelinfo", Desc: "hide kernel pointers and dmesg from non-root", Default: true,
		Values: map[string]string{"kernel.kptr_restrict": "2", "kernel.dmesg_restrict": "1"}},
	{ID: "ptrace", Desc: "restrict ptrace to parent processes (yama)", Default: true,
		Values: map[string]string{"kernel.yama.ptrace_scope": "1"}},
	{ID: "fsprotect", Desc: "protected hard/symlinks, fifos, regular files; no SUID core dumps", Default: true,
		Values: map[string]string{
			"fs.protected_hardlinks": "1", "fs.protected_symlinks": "1",
			"fs.protected_fifos": "2", "fs.protected_regular": "2", "fs.suid_dumpable": "0",
		}},
	{ID: "bpf", Desc: "disable unprivileged eBPF, harden BPF JIT", Default: true,
		Values: map[string]string{"kernel.unprivileged_bpf_disabled": "1", "net.core.bpf_jit_harden": "2"}},
	{ID: "aslr", Desc: "full ASLR", Default: true,
		Values: map[string]string{"kernel.randomize_va_space": "2"}},
	{ID: "noforward", Desc: "disable IP forwarding (pure server, no containers/VPN)", Default: false,
		Values: map[string]string{"net.ipv4.ip_forward": "0", "net.ipv6.conf.all.forwarding": "0"},
		Skip:   routing},
	{ID: "sysrq", Desc: "disable magic SysRq key", Default: false,
		Values: map[string]string{"kernel.sysrq": "0"}},
}

// Current reads a sysctl from /proc/sys.
func Current(key string) string {
	b, err := os.ReadFile("/proc/sys/" + strings.ReplaceAll(key, ".", "/"))
	if err != nil {
		return "n/a"
	}
	return strings.Join(strings.Fields(string(b)), " ")
}

// Compliance returns how many keys of the item already match.
func Compliance(it Item) (ok, total int) {
	for k, v := range it.Values {
		total++
		if Current(k) == v {
			ok++
		}
	}
	return
}

func SortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}

func Render(h *system.Host, ids []string) (string, []string) {
	var b strings.Builder
	var skipped []string
	b.WriteString("# Managed by vpshield - kernel/network hardening\n")
	for _, it := range Items {
		sel := false
		for _, id := range ids {
			if id == it.ID {
				sel = true
			}
		}
		if !sel {
			continue
		}
		if it.Skip != nil {
			if why := it.Skip(h); why != "" {
				skipped = append(skipped, it.ID+": "+why)
				continue
			}
		}
		fmt.Fprintf(&b, "\n# %s\n", it.Desc)
		for _, k := range SortedKeys(it.Values) {
			if Current(k) == "n/a" {
				fmt.Fprintf(&b, "# %s = %s   (not supported by this kernel)\n", k, it.Values[k])
				continue
			}
			fmt.Fprintf(&b, "%s = %s\n", k, it.Values[k])
		}
	}
	return b.String(), skipped
}

func BuildPlan(h *system.Host, ids []string) *plan.Plan {
	p := &plan.Plan{Title: "Kernel hardening (sysctl)"}
	content, skipped := Render(h, ids)
	for _, s := range skipped {
		p.Warn("skipped %s", s)
	}
	p.Add(
		plan.File(File, content, 0o644),
		plan.Cmd("apply", "sysctl", "-e", "-p", File),
	)
	p.RestoreHooks = [][]string{{"sysctl", "--system"}}
	return p
}
