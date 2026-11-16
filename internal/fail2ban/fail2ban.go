// Package fail2ban generates jail configuration and wraps fail2ban-client.
package fail2ban

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"vpshield/internal/plan"
	"vpshield/internal/system"
)

const (
	JailFile   = "/etc/fail2ban/jail.d/vpshield.local"
	ServerFile = "/etc/fail2ban/fail2ban.d/vpshield.local"
	LogFile    = "/var/log/fail2ban.log"
)

type Config struct {
	BanTime     string
	FindTime    string
	MaxRetry    int
	Increment   bool // bantime grows for repeat offenders
	MaxBanTime  string
	IgnoreIP    []string
	BanAction   string
	BanAllPorts string
	SSHPort     int
	SSHMode     string // normal | ddos | extra | aggressive
	SSHMaxRetry int
	Jails       []string // extra jail ids
}

type JailDef struct {
	ID, Name, Desc string
	// Available reports whether the service/logs exist on this host.
	Available func(h *system.Host) bool
	render    func(h *system.Host, c Config) string
}

func fileExists(paths ...string) func(*system.Host) bool {
	return func(*system.Host) bool {
		for _, p := range paths {
			if system.Exists(p) {
				return true
			}
		}
		return false
	}
}

func journalOrFile(h *system.Host) string {
	if h.Distro.Init == system.InitSystemd {
		return "backend = systemd\n"
	}
	return "backend = auto\n"
}

// Catalog of optional jails. sshd is always on and rendered separately.
var Catalog = []JailDef{
	{
		ID: "recidive", Name: "recidive", Desc: "long ban (all ports) for IPs banned again and again",
		Available: func(*system.Host) bool { return true },
		render: func(h *system.Host, c Config) string {
			return "[recidive]\nenabled = true\nlogpath = " + LogFile + "\nbackend = auto\n" +
				"banaction = %(banaction_allports)s\nbantime = 1w\nfindtime = 1d\nmaxretry = 3\n"
		},
	},
	{
		ID: "portscan", Name: "vpshield-portscan", Desc: "ban IPs knocking on many closed ports (needs firewall logging)",
		Available: func(*system.Host) bool { return true },
		render: func(h *system.Host, c Config) string {
			return "[vpshield-portscan]\nenabled = true\nfilter = vpshield-portscan\n" + kernelLog(h) +
				"banaction = %(banaction_allports)s\nmaxretry = 15\nfindtime = 1m\nbantime = 1d\n"
		},
	},
	{
		ID: "nginx-http-auth", Name: "nginx-http-auth", Desc: "nginx basic-auth brute force",
		Available: fileExists("/var/log/nginx/error.log"),
		render: func(h *system.Host, c Config) string {
			return "[nginx-http-auth]\nenabled = true\nport = http,https\nbackend = auto\n"
		},
	},
	{
		ID: "nginx-botsearch", Name: "nginx-botsearch", Desc: "scanners probing for phpmyadmin, wp-login, .env ...",
		Available: fileExists("/var/log/nginx/error.log"),
		render: func(h *system.Host, c Config) string {
			return "[nginx-botsearch]\nenabled = true\nport = http,https\nbackend = auto\n"
		},
	},
	{
		ID: "apache-auth", Name: "apache-auth", Desc: "apache auth failures",
		Available: fileExists("/var/log/apache2/error.log", "/var/log/httpd/error_log"),
		render: func(h *system.Host, c Config) string {
			return "[apache-auth]\nenabled = true\nport = http,https\nbackend = auto\n"
		},
	},
	{
		ID: "postfix", Name: "postfix", Desc: "SMTP auth / relay abuse",
		Available: func(h *system.Host) bool { return h.Has("postfix") },
		render: func(h *system.Host, c Config) string {
			return "[postfix]\nenabled = true\nmode = aggressive\n" + journalOrFile(h)
		},
	},
	{
		ID: "dovecot", Name: "dovecot", Desc: "IMAP/POP3 brute force",
		Available: func(h *system.Host) bool { return h.Has("dovecot") },
		render: func(h *system.Host, c Config) string {
			return "[dovecot]\nenabled = true\n" + journalOrFile(h)
		},
	},
}

// Defaults returns a sensible starting configuration for this host.
func Defaults(h *system.Host, sshPort int, banAction, banAll string) Config {
	ignore := []string{"127.0.0.1/8", "::1"}
	if ip := system.ClientIP(); ip != "" {
		ignore = append(ignore, ip)
	}
	c := Config{
		BanTime: "1h", FindTime: "10m", MaxRetry: 5,
		Increment: true, MaxBanTime: "4w",
		IgnoreIP:  ignore,
		BanAction: banAction, BanAllPorts: banAll,
		SSHPort: sshPort, SSHMode: "aggressive", SSHMaxRetry: 3,
	}
	for _, j := range Catalog {
		if j.ID == "recidive" || j.Available(h) {
			c.Jails = append(c.Jails, j.ID)
		}
	}
	return c
}

// Load returns the configuration currently written in JailFile, using def
// for anything the file does not set. ok is false when there is no file.
func Load(def Config) (c Config, ok bool) {
	s := system.ReadFile(JailFile)
	if strings.TrimSpace(s) == "" {
		return def, false
	}
	return ParseConfig(s, def), true
}

// ParseConfig reads a jail file written by Render (or edited by hand).
func ParseConfig(content string, def Config) Config {
	c := def
	c.Jails = nil
	c.Increment = false
	section := ""
	enabled := map[string]bool{}
	sawMode := false
	var lastKey string
	for _, raw := range strings.Split(content, "\n") {
		line := raw
		if i := strings.IndexAny(line, "#;"); i == 0 || (i > 0 && (line[i-1] == ' ' || line[i-1] == '\t')) {
			line = line[:i]
		}
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			section = strings.TrimSpace(t[1 : len(t)-1])
			lastKey = ""
			continue
		}
		// continuation line (indented) extends the previous value
		if (raw[0] == ' ' || raw[0] == '\t') && lastKey == "ignoreip" && section == "DEFAULT" && !strings.Contains(t, "=") {
			if ips, err := ParseIgnoreIP(t); err == nil {
				c.IgnoreIP = append(c.IgnoreIP, ips...)
			}
			continue
		}
		k, v, found := strings.Cut(t, "=")
		if !found {
			continue
		}
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		lastKey = k
		num := func(def int) int {
			if n, err := strconv.Atoi(v); err == nil {
				return n
			}
			return def
		}
		switch section {
		case "DEFAULT":
			switch k {
			case "bantime":
				c.BanTime = v
			case "findtime":
				c.FindTime = v
			case "maxretry":
				c.MaxRetry = num(c.MaxRetry)
			case "bantime.increment":
				c.Increment = v == "true" || v == "yes" || v == "1"
			case "bantime.maxtime":
				c.MaxBanTime = v
			case "ignoreip":
				if ips, err := ParseIgnoreIP(v); err == nil {
					c.IgnoreIP = ips
				}
			case "banaction":
				c.BanAction = v
			case "banaction_allports":
				c.BanAllPorts = v
			}
		case "sshd":
			switch k {
			case "port":
				c.SSHPort = num(c.SSHPort)
			case "mode":
				c.SSHMode, sawMode = v, true
			case "maxretry":
				c.SSHMaxRetry = num(c.SSHMaxRetry)
			}
		default:
			if k == "enabled" {
				enabled[section] = v == "true" || v == "yes" || v == "1"
			}
		}
	}
	if !sawMode {
		c.SSHMode = "normal" // fail2ban default when the jail sets no mode
	}
	for _, j := range Catalog {
		if enabled[j.Name] {
			c.Jails = append(c.Jails, j.ID)
		}
	}
	return c
}

// PortscanFilter matches packets dropped by ufw, firewalld and the vpshield
// nftables ruleset. Kernel log lines carry SRC=<ip>.
const PortscanFilterFile = "/etc/fail2ban/filter.d/vpshield-portscan.conf"

const PortscanFilter = `# Managed by vpshield
[Definition]
failregex = \[UFW BLOCK\] .*SRC=<HOST> 
            vpshield-drop: .*SRC=<HOST> 
            filter_IN_\S+_(?:REJECT|DROP):? .*SRC=<HOST> 
ignoreregex = \[UFW BLOCK\] .*PROTO=(?:ICMP|ICMPv6|2) 
`

func kernelLog(h *system.Host) string {
	if h.Distro.Init == system.InitSystemd && h.Distro.Family != system.FamilyAlpine {
		return "backend = systemd\njournalmatch = _TRANSPORT=kernel\n"
	}
	for _, p := range []string{"/var/log/kern.log", "/var/log/messages", "/var/log/syslog"} {
		if system.Exists(p) {
			return "backend = auto\nlogpath = " + p + "\n"
		}
	}
	return "backend = auto\nlogpath = /var/log/messages\n"
}

// PortscanPrereq turns on logging of dropped packets for the firewall in use.
func PortscanPrereq(fwName string) []plan.Step {
	switch fwName {
	case "ufw":
		return []plan.Step{plan.Cmd("ufw: log blocked packets", "ufw", "logging", "low")}
	case "firewalld":
		return []plan.Step{plan.Cmd("firewalld: log denied packets", "firewall-cmd", "--set-log-denied=unicast")}
	}
	return nil // the vpshield nftables ruleset already logs drops (rate limited)
}

// sshdLog returns the backend/logpath lines for the sshd jail.
func sshdLog(h *system.Host) string {
	if h.Distro.Init == system.InitSystemd && h.Distro.Family != system.FamilyAlpine {
		// match both the classic and the OpenSSH >= 9.8 process names and
		// both unit names (Debian: ssh.service, others: sshd.service)
		return "backend = systemd\njournalmatch = _SYSTEMD_UNIT=sshd.service + _SYSTEMD_UNIT=ssh.service + _COMM=sshd + _COMM=sshd-session\n"
	}
	for _, p := range []string{"/var/log/auth.log", "/var/log/secure", "/var/log/messages"} {
		if system.Exists(p) {
			return "backend = auto\nlogpath = " + p + "\n"
		}
	}
	return "backend = auto\nlogpath = /var/log/messages\n"
}

// Render builds jail.d/vpshield.local.
func Render(h *system.Host, c Config) string {
	var b strings.Builder
	b.WriteString("# Managed by vpshield - regenerated by the fail2ban wizard.\n")
	b.WriteString("# Put your own overrides in another *.local file.\n\n")
	b.WriteString("[DEFAULT]\n")
	fmt.Fprintf(&b, "bantime  = %s\nfindtime = %s\nmaxretry = %d\n", c.BanTime, c.FindTime, c.MaxRetry)
	if c.Increment {
		fmt.Fprintf(&b, "bantime.increment = true\nbantime.factor = 2\nbantime.maxtime = %s\n", c.MaxBanTime)
	}
	fmt.Fprintf(&b, "ignoreip = %s\n", strings.Join(c.IgnoreIP, " "))
	fmt.Fprintf(&b, "banaction = %s\nbanaction_allports = %s\n\n", c.BanAction, c.BanAllPorts)

	b.WriteString("[sshd]\nenabled = true\n")
	fmt.Fprintf(&b, "port = %d\n", c.SSHPort)
	if c.SSHMode != "" && c.SSHMode != "normal" {
		fmt.Fprintf(&b, "mode = %s\n", c.SSHMode)
	}
	fmt.Fprintf(&b, "maxretry = %d\n", c.SSHMaxRetry)
	b.WriteString(sshdLog(h))
	for _, j := range Catalog {
		for _, id := range c.Jails {
			if id == j.ID {
				b.WriteString("\n" + j.render(h, c))
			}
		}
	}
	return b.String()
}

func renderServer() string {
	return "# Managed by vpshield\n[Definition]\nlogtarget = " + LogFile + "\n"
}

// ValidateDuration accepts fail2ban time strings: 600, 10m, 1h, 1d, 1w, 4w.
func ValidateDuration(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return fmt.Errorf("required")
	}
	if _, err := strconv.Atoi(s); err == nil {
		return nil
	}
	n := strings.TrimRight(s, "smhdwy")
	unit := s[len(n):]
	if _, err := strconv.Atoi(n); err != nil || len(unit) != 1 {
		return fmt.Errorf("use e.g. 600, 10m, 1h, 1d, 1w")
	}
	return nil
}

// ParseIgnoreIP splits and validates a whitelist.
func ParseIgnoreIP(s string) ([]string, error) {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' }) {
		if net.ParseIP(f) == nil {
			if _, _, err := net.ParseCIDR(f); err != nil {
				return nil, fmt.Errorf("%q is not an IP or CIDR", f)
			}
		}
		out = append(out, f)
	}
	return out, nil
}

// BuildPlan installs fail2ban if needed, writes the config, tests and restarts.
func BuildPlan(h *system.Host, c Config) *plan.Plan {
	p := &plan.Plan{Title: "Configure fail2ban"}
	if !h.Has("fail2ban-client") {
		if h.Distro.Family == system.FamilyRHEL {
			p.Add(plan.Func("enable EPEL repository", "dnf install epel-release", func(h *system.Host) (string, error) { return h.EnsureEPEL() }))
		}
		p.Add(plan.Install(h, "fail2ban"))
	}
	ip := system.ClientIP()
	if ip != "" {
		found := false
		for _, x := range c.IgnoreIP {
			if x == ip {
				found = true
			}
		}
		if !found {
			p.Warn("your current IP %s is NOT in ignoreip: a few typos and you ban yourself", ip)
		}
	}
	p.Add(
		plan.File(ServerFile, renderServer(), 0o644),
		plan.Func("create "+LogFile, "touch "+LogFile, func(h *system.Host) (string, error) {
			return h.Shell("touch " + LogFile + " && chmod 640 " + LogFile)
		}),
		plan.File(JailFile, Render(h, c), 0o644),
	)
	for _, j := range c.Jails {
		if j == "portscan" {
			p.Add(plan.File(PortscanFilterFile, PortscanFilter, 0o644))
		}
	}
	p.Add(
		plan.Func("test configuration", "$ fail2ban-client -t", func(h *system.Host) (string, error) {
			out, err := h.Run("fail2ban-client", "-t")
			if err != nil && strings.Contains(strings.ToLower(out), "usage") {
				return "fail2ban too old for -t, skipped", nil
			}
			return out, err
		}),
		plan.EnableService("fail2ban"),
		plan.RestartService("fail2ban"),
	)
	p.RestoreHooks = append(p.RestoreHooks, []string{"fail2ban-client", "reload"})
	return p
}

// ---- runtime -------------------------------------------------------------

type JailInfo struct {
	Name                 string
	CurFailed, TotFailed int
	CurBanned, TotBanned int
	IPs                  []string
}

func Running(h *system.Host) bool {
	if !h.Has("fail2ban-client") {
		return false
	}
	out, err := h.Query("fail2ban-client", "ping")
	return err == nil && strings.Contains(out, "pong")
}

func Jails(h *system.Host) ([]string, error) {
	out, err := h.Query("fail2ban-client", "status")
	if err != nil {
		return nil, err
	}
	return ParseJailList(out), nil
}

func ParseJailList(out string) []string {
	for _, line := range strings.Split(out, "\n") {
		if _, v, ok := strings.Cut(line, "Jail list:"); ok {
			var jails []string
			for _, j := range strings.Split(v, ",") {
				if j = strings.TrimSpace(j); j != "" {
					jails = append(jails, j)
				}
			}
			return jails
		}
	}
	return nil
}

func JailStatus(h *system.Host, jail string) (JailInfo, error) {
	out, err := h.Query("fail2ban-client", "status", jail)
	if err != nil {
		return JailInfo{Name: jail}, err
	}
	return ParseJailStatus(jail, out), nil
}

func ParseJailStatus(jail, out string) JailInfo {
	ji := JailInfo{Name: jail}
	num := func(v string) int { n, _ := strconv.Atoi(strings.TrimSpace(v)); return n }
	for _, line := range strings.Split(out, "\n") {
		switch {
		case strings.Contains(line, "Currently failed:"):
			ji.CurFailed = num(after(line, "Currently failed:"))
		case strings.Contains(line, "Total failed:"):
			ji.TotFailed = num(after(line, "Total failed:"))
		case strings.Contains(line, "Currently banned:"):
			ji.CurBanned = num(after(line, "Currently banned:"))
		case strings.Contains(line, "Total banned:"):
			ji.TotBanned = num(after(line, "Total banned:"))
		case strings.Contains(line, "Banned IP list:"):
			ji.IPs = strings.Fields(after(line, "Banned IP list:"))
		}
	}
	return ji
}

func after(s, sep string) string {
	_, v, _ := strings.Cut(s, sep)
	return v
}

func AllStatus(h *system.Host) ([]JailInfo, error) {
	jails, err := Jails(h)
	if err != nil {
		return nil, err
	}
	var out []JailInfo
	for _, j := range jails {
		ji, _ := JailStatus(h, j)
		out = append(out, ji)
	}
	return out, nil
}

func Unban(h *system.Host, jail, ip string) (string, error) {
	return h.Run("fail2ban-client", "set", jail, "unbanip", ip)
}

func Ban(h *system.Host, jail, ip string) (string, error) {
	if net.ParseIP(ip) == nil {
		return "", fmt.Errorf("invalid IP %q", ip)
	}
	return h.Run("fail2ban-client", "set", jail, "banip", ip)
}

func UnbanAll(h *system.Host) (string, error) {
	return h.Run("fail2ban-client", "unban", "--all")
}

// SetSSHPort rewrites only the sshd port line of our jail file (after an
// SSH port change) and reloads fail2ban.
func SetSSHPort(h *system.Host, port int) (string, error) {
	cur := system.ReadFile(JailFile)
	if cur == "" {
		return "no vpshield jail file, skipped", nil
	}
	lines := strings.Split(cur, "\n")
	inSSHD := false
	for i, l := range lines {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "[") {
			inSSHD = t == "[sshd]"
		}
		if inSSHD && strings.HasPrefix(t, "port") {
			lines[i] = "port = " + strconv.Itoa(port)
		}
	}
	if err := h.WriteFile(JailFile, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
		return "", err
	}
	if Running(h) {
		return h.Run("fail2ban-client", "reload")
	}
	return "updated", nil
}
