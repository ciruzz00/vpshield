// Package audit produces a quick security report of the host.
package audit

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"vpshield/internal/backup"
	"vpshield/internal/fail2ban"
	"vpshield/internal/firewall"
	"vpshield/internal/sshd"
	"vpshield/internal/sysctl"
	"vpshield/internal/system"
	"vpshield/internal/updates"
	"vpshield/internal/users"
)

type Severity int

const (
	OK Severity = iota
	Info
	Warn
	Crit
)

func (s Severity) String() string {
	return [...]string{"OK", "INFO", "WARN", "CRIT"}[s]
}

type Finding struct {
	Sev    Severity
	Area   string
	Title  string
	Detail string
}

type Report struct {
	Host     string
	Distro   string
	Time     time.Time
	Findings []Finding
	Score    int
}

// risky services that should almost never listen on 0.0.0.0
var riskyPorts = map[int]string{
	21: "FTP", 23: "telnet", 111: "rpcbind", 445: "SMB", 2375: "Docker API (no TLS!)", 3306: "MySQL/MariaDB",
	5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 9200: "Elasticsearch", 11211: "memcached",
	27017: "MongoDB", 5984: "CouchDB", 8086: "InfluxDB",
}

func Run(h *system.Host, st *system.State) Report {
	r := Report{Host: system.Hostname(), Distro: h.Distro.Name, Time: time.Now()}
	add := func(sev Severity, area, title, detail string) {
		r.Findings = append(r.Findings, Finding{sev, area, title, detail})
	}

	// --- SSH
	eff := sshd.Effective(h)
	if len(eff) == 0 {
		add(Info, "ssh", "could not read effective sshd config", "run as root (sshd -T)")
	} else {
		port := strings.Fields(eff["port"] + " ")[0]
		if port == "22" {
			add(Info, "ssh", "SSH on default port 22", "moving it cuts log noise from bots (not real security, but useful)")
		} else {
			add(OK, "ssh", "SSH on non-default port "+port, "")
		}
		switch eff["permitrootlogin"] {
		case "yes":
			add(Crit, "ssh", "root login with password allowed", "set PermitRootLogin prohibit-password or no")
		case "no":
			add(OK, "ssh", "root login disabled", "")
		default:
			add(OK, "ssh", "root login key-only ("+eff["permitrootlogin"]+")", "")
		}
		if eff["passwordauthentication"] == "yes" {
			add(Warn, "ssh", "password authentication enabled", "use keys only once a key is installed")
		} else {
			add(OK, "ssh", "password authentication disabled", "")
		}
		if eff["permitemptypasswords"] == "yes" {
			add(Crit, "ssh", "empty passwords allowed", "")
		}
		if n, err := strconv.Atoi(eff["maxauthtries"]); err == nil && n > 4 {
			add(Info, "ssh", "MaxAuthTries "+eff["maxauthtries"], "3 is a good value")
		}
		if eff["x11forwarding"] == "yes" {
			add(Info, "ssh", "X11 forwarding enabled", "rarely needed on a server")
		}
	}

	// --- firewall
	fw := firewall.Detect(h, st)
	if fw.Active() {
		add(OK, "firewall", fw.Name()+" active", "")
	} else {
		add(Crit, "firewall", "no active firewall ("+fw.Name()+" inactive)", "enable it from Firewall & ports")
	}
	allowed := map[int]bool{}
	if rules, err := fw.Rules(); err == nil {
		for _, ru := range rules {
			allowed[ru.Port] = true
		}
	}

	// --- fail2ban
	if fail2ban.Running(h) {
		jails, _ := fail2ban.Jails(h)
		add(OK, "fail2ban", fmt.Sprintf("running, %d jails: %s", len(jails), strings.Join(jails, ", ")), "")
	} else if h.Has("fail2ban-client") {
		add(Warn, "fail2ban", "installed but not running", "")
	} else {
		add(Warn, "fail2ban", "not installed", "")
	}

	// --- updates
	if on, msg := updates.Status(h); on {
		add(OK, "updates", msg, "")
	} else {
		add(Warn, "updates", msg, "")
	}
	if system.Exists("/var/run/reboot-required") {
		add(Warn, "updates", "reboot required to finish updates", system.ReadFile("/var/run/reboot-required.pkgs"))
	}

	// --- listening sockets
	for _, l := range h.Listeners() {
		if !l.Public() {
			continue
		}
		proc := l.Process
		if proc == "" {
			proc = "?"
		}
		if name, bad := riskyPorts[l.Port]; bad {
			sev := Crit
			if fw.Active() && !allowed[l.Port] {
				sev = Warn // listening publicly but blocked by the firewall
			}
			add(sev, "network", fmt.Sprintf("%s %s/%d listening on all interfaces (%s)", name, l.Proto, l.Port, proc),
				"bind it to 127.0.0.1 or a private interface")
			continue
		}
		state := "open in firewall"
		if fw.Active() && !allowed[l.Port] {
			state = "blocked by firewall"
		}
		add(Info, "network", fmt.Sprintf("%s/%d public (%s), %s", l.Proto, l.Port, proc, state), "")
	}

	// --- accounts
	if f, err := os.Open("/etc/passwd"); err == nil {
		sc := bufio.NewScanner(f)
		var shells []string
		for sc.Scan() {
			p := strings.Split(sc.Text(), ":")
			if len(p) < 7 {
				continue
			}
			if p[2] == "0" && p[0] != "root" {
				add(Crit, "accounts", "UID 0 account besides root: "+p[0], "")
			}
			if !strings.HasSuffix(p[6], "nologin") && !strings.HasSuffix(p[6], "false") && p[6] != "/bin/sync" && p[6] != "" {
				shells = append(shells, p[0])
			}
		}
		f.Close()
		add(Info, "accounts", "accounts with a login shell: "+strings.Join(shells, ", "), "")
	}
	// --- internal security: who can become root
	us := users.Summarize(users.List())
	switch {
	case us.OnlyRoot:
		add(Warn, "accounts", "root is the only account that can log in",
			"work as a personal user with sudo: Users & access › Create admin user, then PermitRootLogin no")
	case len(us.Admins) == 0:
		add(Info, "accounts", "no personal account has sudo", "administration still requires logging in as root")
	default:
		add(OK, "accounts", "admins with sudo: "+strings.Join(us.Admins, ", "), "")
		if eff := sshd.Effective(h); eff["permitrootlogin"] != "" && eff["permitrootlogin"] != "no" {
			add(Info, "accounts", "root can still log in over SSH although admin users exist", "SSH › Hardening › Root login = no")
		}
	}
	for _, u := range us.NoPasswd {
		add(Warn, "accounts", "passwordless sudo for "+u, "a stolen key or session of "+u+" is instantly root")
	}
	if system.IsRoot() && h.Has("sudo") {
		cur := users.CurrentSudoDefaults()
		if len(cur) == 0 {
			add(Info, "accounts", "sudo commands are not logged to a file", "Users & access › Sudo policy")
		}
	}
	if st, err := os.Stat("/etc/shadow"); err == nil && st.Mode().Perm()&0o004 != 0 {
		add(Crit, "accounts", fmt.Sprintf("/etc/shadow is world readable (%o)", st.Mode().Perm()), "chmod 640 /etc/shadow")
	}
	if f, err := os.Open("/etc/shadow"); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			p := strings.Split(sc.Text(), ":")
			if len(p) > 1 && p[1] == "" {
				add(Crit, "accounts", "account with EMPTY password: "+p[0], "passwd -l "+p[0])
			}
		}
		f.Close()
	}
	for _, u := range sshd.KeyHolders() {
		home := "/home/" + u
		if u == "root" {
			home = "/root"
		}
		if st, err := os.Stat(filepath.Join(home, ".ssh")); err == nil && st.Mode().Perm()&0o077 != 0 {
			add(Warn, "accounts", fmt.Sprintf("%s/.ssh permissions %o", home, st.Mode().Perm()), "chmod 700 "+home+"/.ssh")
		}
		if st, err := os.Stat(filepath.Join(home, ".ssh", "authorized_keys")); err == nil && st.Mode().Perm()&0o022 != 0 {
			add(Warn, "accounts", fmt.Sprintf("%s/.ssh/authorized_keys writable by others (%o)", home, st.Mode().Perm()), "chmod 600")
		}
	}

	// --- backups
	jobs := backup.LoadJobs()
	if len(jobs) == 0 {
		add(Warn, "backups", "no off-server backups configured", "Remote backups › New backup job (rclone)")
	} else {
		bst := backup.LoadStatus()
		for _, j := range jobs {
			s, ok := bst[j.ID]
			switch {
			case !ok:
				add(Warn, "backups", "backup "+j.ID+" never ran", "")
			case !s.OK:
				add(Warn, "backups", "backup "+j.ID+" failed on "+s.Time.Format("2006-01-02 15:04"), s.Message)
			case j.Schedule != "" && time.Since(s.Time) > 8*24*time.Hour:
				add(Warn, "backups", "backup "+j.ID+" last succeeded "+s.Time.Format("2006-01-02"), "check the cron job and "+backup.LogFile(j.ID))
			default:
				add(OK, "backups", "backup "+j.ID+" ok ("+s.Time.Format("2006-01-02 15:04")+")", "")
			}
		}
	}

	// --- kernel
	var weak []string
	for _, it := range sysctl.Items {
		if !it.Default {
			continue
		}
		if ok, total := sysctl.Compliance(it); ok < total {
			weak = append(weak, it.ID)
		}
	}
	if len(weak) == 0 {
		add(OK, "kernel", "sysctl hardening applied", "")
	} else {
		add(Warn, "kernel", "sysctl not hardened: "+strings.Join(weak, ", "), "apply from Kernel hardening")
	}

	// --- filesystem
	if out, err := runTimeout(30*time.Second, "find", "/etc", "-xdev", "-type", "f", "-perm", "-0002"); err == nil && strings.TrimSpace(out) != "" {
		add(Warn, "files", "world-writable files in /etc", out)
	}
	if out, err := runTimeout(60*time.Second, "find", "/", "-xdev", "-type", "f", "-perm", "-4000",
		"-not", "-path", "/proc/*", "-not", "-path", "/snap/*"); err == nil {
		list := strings.Fields(out)
		add(Info, "files", fmt.Sprintf("%d SUID binaries", len(list)), strings.Join(list, "\n"))
	}

	r.Score = score(r.Findings)
	return r
}

func runTimeout(t time.Duration, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	done := make(chan struct{})
	var out []byte
	var err error
	go func() { out, err = cmd.Output(); close(done) }()
	select {
	case <-done:
		return string(out), err
	case <-time.After(t):
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		return "", fmt.Errorf("timeout")
	}
}

func score(fs []Finding) int {
	s := 100
	for _, f := range fs {
		switch f.Sev {
		case Crit:
			s -= 20
		case Warn:
			s -= 7
		}
	}
	if s < 0 {
		s = 0
	}
	return s
}

// Text renders the report as plain text (for files and cron).
func (r Report) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "vpshield security audit\nhost: %s\ndistro: %s\ndate: %s\nscore: %d/100\n\n", r.Host, r.Distro, r.Time.Format(time.RFC1123), r.Score)
	area := ""
	for _, f := range r.Findings {
		if f.Area != area {
			area = f.Area
			fmt.Fprintf(&b, "\n[%s]\n", strings.ToUpper(area))
		}
		fmt.Fprintf(&b, "  %-4s %s\n", f.Sev, f.Title)
		if f.Detail != "" && f.Sev != OK {
			for _, l := range strings.Split(strings.TrimSpace(f.Detail), "\n") {
				fmt.Fprintf(&b, "         %s\n", l)
			}
		}
	}
	return b.String()
}

// Save writes the report to /var/log/vpshield/audit-YYYY-MM-DD.txt.
func (r Report) Save() (string, error) {
	if err := os.MkdirAll(system.LogDir, 0o750); err != nil {
		return "", err
	}
	path := filepath.Join(system.LogDir, "audit-"+r.Time.Format("2006-01-02")+".txt")
	return path, os.WriteFile(path, []byte(r.Text()), 0o640)
}
