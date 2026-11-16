package system

import "testing"

func TestFamily(t *testing.T) {
	cases := map[[2]string]Family{
		{"ubuntu", "debian"}: FamilyDebian, {"rocky", "rhel centos fedora"}: FamilyRHEL, {"almalinux", ""}: FamilyRHEL,
		{"alpine", ""}: FamilyAlpine, {"endeavouros", "arch"}: FamilyArch, {"linuxmint", "ubuntu debian"}: FamilyDebian,
		{"gentoo", ""}: FamilyUnknown,
	}
	for in, want := range cases {
		if got := familyFor(in[0], in[1]); got != want {
			t.Errorf("%v: got %s want %s", in, got, want)
		}
	}
}

func TestParseSS(t *testing.T) {
	out := `tcp   LISTEN 0      128          0.0.0.0:2222      0.0.0.0:*    users:(("sshd",pid=812,fd=3))
tcp   LISTEN 0      4096   127.0.0.53%lo:53        0.0.0.0:*    users:(("systemd-resolve",pid=500,fd=14))
tcp   LISTEN 0      511             [::]:443          [::]:*    users:(("nginx",pid=900,fd=7))
udp   UNCONN 0      0            0.0.0.0:51820     0.0.0.0:*`
	ls := ParseSS(out)
	if len(ls) != 4 {
		t.Fatalf("%+v", ls)
	}
	if ls[0].Port != 53 || ls[0].Public() || ls[0].Addr != "127.0.0.53" {
		t.Errorf("%+v", ls[0])
	}
	if ls[1].Port != 443 || !ls[1].Public() || ls[1].Process != "nginx" {
		t.Errorf("%+v", ls[1])
	}
	if ls[2].Process != "sshd" || ls[3].Proto != "udp" {
		t.Errorf("%+v", ls)
	}
}

func TestParseNetstat(t *testing.T) {
	out := `Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      2100/sshd
tcp        0      0 :::80                   :::*                    LISTEN      2200/nginx
udp        0      0 0.0.0.0:68              0.0.0.0:*                           1900/udhcpc`
	ls := ParseNetstat(out)
	if len(ls) != 3 || ls[0].Process != "sshd" || ls[1].Proto != "udp" || ls[2].Port != 80 {
		t.Fatalf("%+v", ls)
	}
}
