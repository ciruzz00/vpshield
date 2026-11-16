// Package firewall abstracts ufw, firewalld and a native nftables backend.
package firewall

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"vpshield/internal/plan"
	"vpshield/internal/system"
)

type Backend interface {
	Name() string
	// Installed reports whether the tooling exists.
	Installed() bool
	// Active reports whether it is currently filtering traffic.
	Active() bool
	// InstallSteps installs the tooling.
	InstallSteps() []plan.Step
	// EnableSteps turns on default-deny inbound, always allowing sshPort first.
	EnableSteps(sshPort int) []plan.Step
	DisableSteps() []plan.Step
	AllowSteps(r system.PortRule) []plan.Step
	RemoveSteps(port int, proto string) []plan.Step
	// Status is a human readable dump of the live rules.
	Status() string
	// Rules returns the allow rules currently in effect.
	Rules() ([]system.PortRule, error)
	// StateFiles are snapshotted before changes; ReloadCmd re-applies them.
	StateFiles() []string
	ReloadCmd() []string
	// Fail2banAction / Fail2banAllPorts are banaction values for jail.local.
	Fail2banAction() string
	Fail2banAllPorts() string
}

var Names = []string{"ufw", "firewalld", "nftables"}

// New returns a backend by name.
func New(h *system.Host, st *system.State, name string) Backend {
	switch name {
	case "ufw":
		return &UFW{h: h}
	case "firewalld":
		return &Firewalld{h: h}
	default:
		return &NFT{h: h, st: st}
	}
}

// Detect picks the backend: saved choice > whatever is already active >
// distro default.
func Detect(h *system.Host, st *system.State) Backend {
	if st.FirewallBackend != "" {
		return New(h, st, st.FirewallBackend)
	}
	fwd, ufw := &Firewalld{h: h}, &UFW{h: h}
	switch {
	case fwd.Active():
		return fwd
	case ufw.Active():
		return ufw
	case ufw.Installed() && h.Distro.Family != system.FamilyRHEL:
		return ufw
	}
	return New(h, st, DefaultFor(h.Distro.Family))
}

func DefaultFor(f system.Family) string {
	switch f {
	case system.FamilyDebian:
		return "ufw"
	case system.FamilyRHEL:
		return "firewalld"
	default:
		return "nftables"
	}
}

func ruleKey(port int, proto string) string { return strconv.Itoa(port) + "/" + proto }

// ParsePortSpec parses "2222", "2222/tcp", "53/udp".
func ParsePortSpec(s string) (int, string, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	portS, proto, ok := strings.Cut(s, "/")
	if !ok {
		proto = "tcp"
	}
	if proto != "tcp" && proto != "udp" {
		return 0, "", fmt.Errorf("protocol must be tcp or udp")
	}
	p, err := strconv.Atoi(portS)
	if err != nil || p < 1 || p > 65535 {
		return 0, "", fmt.Errorf("invalid port %q (1-65535)", portS)
	}
	return p, proto, nil
}

func ValidPort(s string) error {
	_, _, err := ParsePortSpec(s)
	return err
}

func sortRules(rs []system.PortRule) {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].Port == rs[j].Port {
			return rs[i].Proto < rs[j].Proto
		}
		return rs[i].Port < rs[j].Port
	})
}

// snapshotStep backs up the backend state before command based changes and
// registers the reload hook for rollback.
func snapshotStep(b Backend) plan.Step {
	return plan.Func("snapshot firewall state", strings.Join(b.StateFiles(), "\n"), func(h *system.Host) (string, error) {
		for _, f := range b.StateFiles() {
			if err := h.Backup(f); err != nil {
				return "", err
			}
		}
		if rc := b.ReloadCmd(); len(rc) > 0 {
			h.AddRestoreHook(rc...)
		}
		return "ok", nil
	})
}

// Wrap prefixes a list of backend steps with the snapshot step.
func Wrap(b Backend, steps []plan.Step) []plan.Step {
	return append([]plan.Step{snapshotStep(b)}, steps...)
}
