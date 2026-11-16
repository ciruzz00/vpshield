package fail2ban

import (
	"strings"
	"testing"

	"vpshield/internal/system"
)

func TestParse(t *testing.T) {
	j := ParseJailList("Status\n|- Number of jail:\t2\n`- Jail list:\trecidive, sshd\n")
	if strings.Join(j, ",") != "recidive,sshd" {
		t.Fatal(j)
	}
	st := ParseJailStatus("sshd", `Status for the jail: sshd
|- Filter
|  |- Currently failed:	2
|  |- Total failed:	57
|  `+"`"+`- Journal matches:	_SYSTEMD_UNIT=sshd.service + _COMM=sshd
`+"`"+`- Actions
   |- Currently banned:	2
   |- Total banned:	9
   `+"`"+`- Banned IP list:	203.0.113.7 2001:db8::1
`)
	if st.CurFailed != 2 || st.TotFailed != 57 || st.CurBanned != 2 || st.TotBanned != 9 || len(st.IPs) != 2 {
		t.Fatalf("%+v", st)
	}
}

func TestValidate(t *testing.T) {
	for in, ok := range map[string]bool{"600": true, "10m": true, "1w": true, "4w": true, "": false, "1x": false, "m": false} {
		if (ValidateDuration(in) == nil) != ok {
			t.Errorf("duration %q", in)
		}
	}
	if _, err := ParseIgnoreIP("127.0.0.1/8 ::1, 203.0.113.4"); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseIgnoreIP("example.com"); err == nil {
		t.Fatal("hostname accepted")
	}
}

func TestRender(t *testing.T) {
	h := &system.Host{Distro: system.Distro{Family: system.FamilyDebian, Init: system.InitSystemd}}
	c := Config{BanTime: "1h", FindTime: "10m", MaxRetry: 5, Increment: true, MaxBanTime: "4w",
		IgnoreIP: []string{"127.0.0.1/8"}, BanAction: "ufw", BanAllPorts: "ufw", SSHPort: 2222, SSHMode: "aggressive", SSHMaxRetry: 3,
		Jails: []string{"recidive"}}
	out := Render(h, c)
	for _, w := range []string{"[sshd]", "port = 2222", "mode = aggressive", "backend = systemd", "_COMM=sshd-session", "[recidive]", "bantime.increment = true"} {
		if !strings.Contains(out, w) {
			t.Errorf("missing %q\n%s", w, out)
		}
	}
}
