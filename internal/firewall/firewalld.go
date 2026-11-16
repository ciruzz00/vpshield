package firewall

import (
	"fmt"
	"strconv"
	"strings"

	"vpshield/internal/plan"
	"vpshield/internal/system"
)

type Firewalld struct{ h *system.Host }

func (f *Firewalld) Name() string             { return "firewalld" }
func (f *Firewalld) Installed() bool          { return f.h.Has("firewall-cmd") }
func (f *Firewalld) Fail2banAction() string   { return "firewallcmd-rich-rules" }
func (f *Firewalld) Fail2banAllPorts() string { return "firewallcmd-allports" }

func (f *Firewalld) Active() bool {
	if !f.Installed() {
		return false
	}
	out, _ := f.h.Query("firewall-cmd", "--state")
	return strings.TrimSpace(out) == "running"
}

func (f *Firewalld) zone() string {
	out, err := f.h.Query("firewall-cmd", "--get-default-zone")
	if err != nil || strings.TrimSpace(out) == "" {
		return "public"
	}
	return strings.TrimSpace(out)
}

func (f *Firewalld) InstallSteps() []plan.Step {
	if f.Installed() {
		return nil
	}
	return []plan.Step{plan.Install(f.h, "firewalld")}
}

func (f *Firewalld) EnableSteps(sshPort int) []plan.Step {
	spec := strconv.Itoa(sshPort) + "/tcp"
	return []plan.Step{
		plan.EnableService("firewalld"),
		f.cmd("allow SSH "+spec+" (anti-lockout)", "--permanent", "--add-port="+spec),
		f.cmd("reload", "--reload"),
	}
}

func (f *Firewalld) DisableSteps() []plan.Step {
	return []plan.Step{
		plan.Cmd("stop firewalld", "systemctl", "stop", "firewalld"),
		plan.Cmd("disable firewalld", "systemctl", "disable", "firewalld"),
	}
}

// cmd builds a firewall-cmd step bound to the default zone at run time.
func (f *Firewalld) cmd(title string, args ...string) plan.Step {
	return f.cmdOpt(title, false, args...)
}

func (f *Firewalld) cmdOpt(title string, optional bool, args ...string) plan.Step {
	return plan.Step{
		Title:    title,
		Detail:   "$ firewall-cmd --zone=<default> " + strings.Join(args, " "),
		Optional: optional,
		Run: func(h *system.Host) (string, error) {
			full := args
			if args[0] != "--reload" {
				full = append([]string{"--zone=" + f.zone()}, args...)
			}
			return h.Run("firewall-cmd", full...)
		},
	}
}

func richRule(family string, r system.PortRule, rate string) string {
	return fmt.Sprintf(`rule family="%s" port port="%d" protocol="%s" accept limit value="%s"`, family, r.Port, r.Proto, rate)
}

func (f *Firewalld) AllowSteps(r system.PortRule) []plan.Step {
	steps := f.RemoveSteps(r.Port, r.Proto)
	steps = steps[:len(steps)-1] // drop the trailing reload, we add our own
	spec := ruleKey(r.Port, r.Proto)
	if r.Limit {
		// firewalld rate limits are global per rule, not per source IP
		steps = append(steps,
			f.cmd("limit "+spec+" (ipv4)", "--permanent", "--add-rich-rule="+richRule("ipv4", r, "30/m")),
			f.cmd("limit "+spec+" (ipv6)", "--permanent", "--add-rich-rule="+richRule("ipv6", r, "30/m")),
		)
	} else {
		steps = append(steps, f.cmd("allow "+spec, "--permanent", "--add-port="+spec))
	}
	return append(steps, f.cmd("reload", "--reload"))
}

var serviceByPort = map[string]string{"22/tcp": "ssh", "80/tcp": "http", "443/tcp": "https"}

func (f *Firewalld) RemoveSteps(port int, proto string) []plan.Step {
	spec := ruleKey(port, proto)
	r := system.PortRule{Port: port, Proto: proto}
	steps := []plan.Step{
		f.cmdOpt("remove port "+spec, true, "--permanent", "--remove-port="+spec),
		f.cmdOpt("remove rate-limit "+spec+" (ipv4)", true, "--permanent", "--remove-rich-rule="+richRule("ipv4", r, "30/m")),
		f.cmdOpt("remove rate-limit "+spec+" (ipv6)", true, "--permanent", "--remove-rich-rule="+richRule("ipv6", r, "30/m")),
	}
	if svc, ok := serviceByPort[spec]; ok {
		steps = append(steps, f.cmdOpt("remove service "+svc, true, "--permanent", "--remove-service="+svc))
	}
	return append(steps, f.cmd("reload", "--reload"))
}

func (f *Firewalld) Status() string {
	if !f.Installed() {
		return "firewalld is not installed"
	}
	if !f.Active() {
		return "firewalld is installed but not running"
	}
	out, err := f.h.Query("firewall-cmd", "--list-all")
	if err != nil {
		return err.Error()
	}
	return out
}

func (f *Firewalld) Rules() ([]system.PortRule, error) {
	if !f.Active() {
		return nil, nil
	}
	z := "--zone=" + f.zone()
	ports, err := f.h.Query("firewall-cmd", z, "--list-ports")
	if err != nil {
		return nil, err
	}
	svcs, _ := f.h.Query("firewall-cmd", z, "--list-services")
	rich, _ := f.h.Query("firewall-cmd", z, "--list-rich-rules")
	return parseFirewalld(ports, svcs, rich), nil
}

func parseFirewalld(ports, svcs, rich string) []system.PortRule {
	seen := map[string]bool{}
	var out []system.PortRule
	add := func(r system.PortRule) {
		k := ruleKey(r.Port, r.Proto)
		if seen[k] {
			return
		}
		seen[k] = true
		out = append(out, r)
	}
	for _, spec := range strings.Fields(ports) {
		if p, proto, err := ParsePortSpec(spec); err == nil {
			add(system.PortRule{Port: p, Proto: proto})
		}
	}
	for spec, svc := range serviceByPort {
		for _, s := range strings.Fields(svcs) {
			if s == svc {
				p, proto, _ := ParsePortSpec(spec)
				add(system.PortRule{Port: p, Proto: proto, Comment: "service " + svc})
			}
		}
	}
	for _, line := range strings.Split(rich, "\n") {
		if !strings.Contains(line, "limit value") {
			continue
		}
		var port int
		var proto string
		if i := strings.Index(line, `port port="`); i >= 0 {
			rest := line[i+len(`port port="`):]
			port, _ = strconv.Atoi(rest[:strings.Index(rest, `"`)])
		}
		if i := strings.Index(line, `protocol="`); i >= 0 {
			rest := line[i+len(`protocol="`):]
			proto = rest[:strings.Index(rest, `"`)]
		}
		if port > 0 && proto != "" {
			add(system.PortRule{Port: port, Proto: proto, Limit: true})
		}
	}
	sortRules(out)
	return out
}

func (f *Firewalld) StateFiles() []string {
	files := []string{"/etc/firewalld/firewalld.conf"}
	if f.Installed() {
		files = append(files, "/etc/firewalld/zones/"+f.zone()+".xml")
	}
	return files
}

func (f *Firewalld) ReloadCmd() []string { return []string{"firewall-cmd", "--reload"} }
