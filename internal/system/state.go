package system

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// PortRule is an inbound allow rule as vpshield understands it.
type PortRule struct {
	Port    int    `json:"port"`
	Proto   string `json:"proto"`   // tcp | udp
	Limit   bool   `json:"limit"`   // per-source rate limit on new connections
	Comment string `json:"comment"` // free text
}

// State is what vpshield remembers between runs. Secrets live elsewhere.
type State struct {
	SSHPort         int        `json:"ssh_port,omitempty"`
	FirewallBackend string     `json:"firewall_backend,omitempty"`
	Ports           []PortRule `json:"ports,omitempty"` // source of truth for the nftables backend
	LimitRate       string     `json:"limit_rate,omitempty"`
	CFZoneID        string     `json:"cf_zone_id,omitempty"`
	CFZoneName      string     `json:"cf_zone_name,omitempty"`
}

var statePath = filepath.Join(ConfigDir, "state.json")

func LoadState() *State {
	s := &State{}
	if b, err := os.ReadFile(statePath); err == nil {
		_ = json.Unmarshal(b, s)
	}
	return s
}

func (h *Host) SaveState(s *State) error {
	if h.DryRun {
		return nil
	}
	if err := os.MkdirAll(ConfigDir, 0o700); err != nil {
		return err
	}
	_ = h.Backup(statePath) // so a rollback also restores what we remember
	b, _ := json.MarshalIndent(s, "", "  ")
	return os.WriteFile(statePath, b, 0o600)
}

// Secret files (Cloudflare token) are 0600 and never part of snapshots.
func ReadSecret(name string) string {
	b, err := os.ReadFile(filepath.Join(ConfigDir, name))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func (h *Host) WriteSecret(name, value string) error {
	if h.DryRun {
		h.logf("[dry-run] store secret %s", name)
		return nil
	}
	if err := os.MkdirAll(ConfigDir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(ConfigDir, name), []byte(strings.TrimSpace(value)+"\n"), 0o600)
}

func (h *Host) DeleteSecret(name string) error {
	if h.DryRun {
		return nil
	}
	err := os.Remove(filepath.Join(ConfigDir, name))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// ClientIP returns the IP of the current SSH client, if any. Used to
// suggest a fail2ban whitelist and to warn about self-lockout.
func ClientIP() string {
	for _, v := range []string{"SSH_CLIENT", "SSH_CONNECTION"} {
		if f := strings.Fields(os.Getenv(v)); len(f) > 0 {
			return f[0]
		}
	}
	return ""
}

// LoginUser returns the human behind sudo, if any.
func LoginUser() string {
	if u := os.Getenv("SUDO_USER"); u != "" {
		return u
	}
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	return "root"
}
