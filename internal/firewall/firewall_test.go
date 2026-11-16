package firewall

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"vpshield/internal/system"
)

func TestParseUFW(t *testing.T) {
	out := `Status: active

To                         Action      From
--                         ------      ----
2222/tcp                   LIMIT       Anywhere                   # vpshield ssh
80/tcp                     ALLOW       Anywhere
OpenSSH                    ALLOW       Anywhere
51820/udp                  ALLOW       Anywhere
2222/tcp (v6)              LIMIT       Anywhere (v6)              # vpshield ssh
`
	r := parseUFW(out)
	if len(r) != 3 {
		t.Fatalf("want 3 rules, got %d: %+v", len(r), r)
	}
	if r[0].Port != 80 || r[1].Port != 2222 || !r[1].Limit || r[1].Comment != "vpshield ssh" || r[2].Proto != "udp" {
		t.Fatalf("unexpected %+v", r)
	}
}

func TestParseFirewalld(t *testing.T) {
	r := parseFirewalld("2222/tcp 51820/udp", "ssh dhcpv6-client http",
		`rule family="ipv4" port port="2222" protocol="tcp" accept limit value="30/m"`)
	keys := []string{}
	for _, x := range r {
		keys = append(keys, ruleKey(x.Port, x.Proto))
	}
	got := strings.Join(keys, " ")
	if got != "22/tcp 80/tcp 2222/tcp 51820/udp" {
		t.Fatalf("got %s", got)
	}
}

func TestParsePortSpec(t *testing.T) {
	for in, ok := range map[string]bool{"22": true, "53/udp": true, "443/TCP": true, "0": false, "70000": false, "22/icmp": false, "abc": false} {
		_, _, err := ParsePortSpec(in)
		if (err == nil) != ok {
			t.Errorf("%s: err=%v", in, err)
		}
	}
}

func TestRenderNFT(t *testing.T) {
	rules := []system.PortRule{{Port: 2222, Proto: "tcp", Limit: true, Comment: "ssh \"x\""}, {Port: 443, Proto: "tcp"}, {Port: 51820, Proto: "udp"}}
	out := RenderNFT(rules, "10/minute")
	for _, want := range []string{"policy drop", "tcp dport 2222 ct state new add @lim4_tcp_2222", "udp dport 51820 accept", "delete table inet vpshield", `comment "ssh x"`} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	// syntax check with the real nft parser when we can (needs root + nft)
	if os.Geteuid() != 0 {
		t.Skip("not root")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not installed")
	}
	f := filepath.Join(t.TempDir(), "r.nft")
	os.WriteFile(f, []byte(out), 0o600)
	if b, err := exec.Command("nft", "-c", "-f", f).CombinedOutput(); err != nil {
		if strings.Contains(string(b), "Operation not permitted") || strings.Contains(string(b), "Could not process rule: No such file") {
			t.Skipf("no netlink in this sandbox: %s", b)
		}
		t.Fatalf("nft -c failed: %v\n%s", err, b)
	}
}
