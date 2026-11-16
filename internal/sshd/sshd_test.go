package sshd

import (
	"strings"
	"testing"
)

func TestPatchMain(t *testing.T) {
	main := `Port 22
#PermitRootLogin prohibit-password
PasswordAuthentication yes
UsePAM yes
Match User backup
	PasswordAuthentication yes
`
	out, changed := PatchMain(main)
	if !changed {
		t.Fatal("expected change")
	}
	if !strings.HasPrefix(out, "# Added by vpshield\nInclude /etc/ssh/sshd_config.d/*.conf") {
		t.Fatalf("include not at top:\n%s", out)
	}
	if !strings.Contains(out, "# vpshield: Port 22") || !strings.Contains(out, "# vpshield: PasswordAuthentication yes") {
		t.Fatalf("global directives not commented:\n%s", out)
	}
	if !strings.Contains(out, "\tPasswordAuthentication yes") || strings.Contains(out, "# vpshield: \tPassword") {
		t.Fatalf("Match block must be untouched:\n%s", out)
	}
	if !strings.Contains(out, "UsePAM yes") {
		t.Fatal("unmanaged directive touched")
	}
	// idempotent
	out2, changed2 := PatchMain(out)
	if changed2 || out2 != out {
		t.Fatal("second pass changed the file")
	}
}

func TestDropIn(t *testing.T) {
	s := Settings{Port: 2222, PermitRootLogin: "prohibit-password", MaxAuthTries: 3, LoginGraceTime: 30, AllowUsers: []string{"deploy"}}
	out := RenderDropIn(s)
	for _, w := range []string{"Port 2222", "PasswordAuthentication no", "KbdInteractiveAuthentication no", "AllowUsers deploy"} {
		if !strings.Contains(out, w) {
			t.Errorf("missing %q", w)
		}
	}
}

func TestParseUsers(t *testing.T) {
	if u, err := ParseUsers("deploy, admin@10.0.0.0/8"); err != nil || len(u) != 2 {
		t.Fatal(u, err)
	}
	if _, err := ParseUsers("Bad User;"); err == nil {
		t.Fatal("accepted garbage")
	}
}
