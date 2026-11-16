package users

import (
	"strings"
	"testing"
)

const passwd = `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
`

func TestOnlyRoot(t *testing.T) {
	accts := ParsePasswd(passwd)
	s := Summarize(accts)
	if !s.OnlyRoot || len(s.Humans) != 1 || len(s.Admins) != 0 {
		t.Fatalf("%+v", s)
	}
	accts = ParsePasswd(passwd + "alice:x:1000:1000::/home/alice:/bin/bash\n")
	accts[len(accts)-1].Sudo = true
	s = Summarize(accts)
	if s.OnlyRoot || strings.Join(s.Admins, ",") != "alice" {
		t.Fatalf("%+v", s)
	}
}

func TestGroupsAndShadow(t *testing.T) {
	accts := ParsePasswd("deploy:x:1001:1001::/home/deploy:/bin/bash\n")
	g := ParseGroup("sudo:x:27:deploy,other\ndeploy:x:1001:\n", accts)
	if strings.Join(g["deploy"], ",") != "deploy,sudo" {
		t.Fatal(g)
	}
	sh := ParseShadow("root:!:19000::::::\na:$6$x$y:1::::::\nb::1::::::\nc:!$6$x:1::::::\nd:*:1::::::\n")
	for u, want := range map[string]string{"root": "none", "a": "set", "b": "empty", "c": "locked", "d": "none"} {
		if sh[u] != want {
			t.Errorf("%s: %s want %s", u, sh[u], want)
		}
	}
}

func TestSudoers(t *testing.T) {
	r := ParseSudoers(`# comment
Defaults env_reset
Defaults:%sudo !lecture
root    ALL=(ALL:ALL) ALL
%sudo   ALL=(ALL:ALL) ALL
# %wheel ALL=(ALL) ALL
ubuntu ALL=(ALL) NOPASSWD:ALL
backup ALL=(root) NOPASSWD: /usr/bin/rsync
@includedir /etc/sudoers.d
#includedir /etc/sudoers.d
`, "x")
	if len(r) != 4 {
		t.Fatalf("%+v", r)
	}
	if r[1].Who != "%sudo" || !r[1].All || r[1].NoPasswd {
		t.Errorf("%+v", r[1])
	}
	if r[2].Who != "ubuntu" || !r[2].NoPasswd || !r[2].All {
		t.Errorf("%+v", r[2])
	}
	if r[3].All {
		t.Errorf("rsync-only rule counted as ALL: %+v", r[3])
	}
}

func TestValidName(t *testing.T) {
	for _, n := range []string{"Bad", "1abc", "root", "a b", ""} {
		if ValidName(n) == nil {
			t.Errorf("%q accepted", n)
		}
	}
	if err := ValidName("vpsadmin-test"); err != nil {
		t.Error(err)
	}
}
