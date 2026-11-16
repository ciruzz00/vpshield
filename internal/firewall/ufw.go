package firewall

import (
	"strconv"
	"strings"

	"vpshield/internal/plan"
	"vpshield/internal/system"
)

type UFW struct{ h *system.Host }

func (u *UFW) Name() string             { return "ufw" }
func (u *UFW) Installed() bool          { return u.h.Has("ufw") }
func (u *UFW) Fail2banAction() string   { return "ufw" }
func (u *UFW) Fail2banAllPorts() string { return "ufw" }

func (u *UFW) Active() bool {
	if !u.Installed() {
		return false
	}
	out, _ := u.h.Query("ufw", "status")
	return strings.Contains(out, "Status: active")
}

func (u *UFW) InstallSteps() []plan.Step {
	if u.Installed() {
		return nil
	}
	return []plan.Step{plan.Install(u.h, "ufw")}
}

func (u *UFW) EnableSteps(sshPort int) []plan.Step {
	ssh := strconv.Itoa(sshPort) + "/tcp"
	return []plan.Step{
		plan.Cmd("default deny incoming", "ufw", "default", "deny", "incoming"),
		plan.Cmd("default allow outgoing", "ufw", "default", "allow", "outgoing"),
		plan.Cmd("allow SSH "+ssh+" (anti-lockout)", "ufw", "allow", ssh, "comment", "vpshield ssh"),
		plan.Cmd("enable ufw", "ufw", "--force", "enable"),
	}
}

func (u *UFW) DisableSteps() []plan.Step {
	return []plan.Step{plan.Cmd("disable ufw", "ufw", "disable")}
}

func (u *UFW) AllowSteps(r system.PortRule) []plan.Step {
	spec := ruleKey(r.Port, r.Proto)
	comment := r.Comment
	if comment == "" {
		comment = "vpshield"
	}
	steps := u.RemoveSteps(r.Port, r.Proto) // replace any previous allow/limit
	if r.Limit {
		// ufw limit: deny a source that opens >= 6 connections in 30s
		steps = append(steps, plan.Cmd("limit "+spec, "ufw", "limit", spec, "comment", comment))
	} else {
		steps = append(steps, plan.Cmd("allow "+spec, "ufw", "allow", spec, "comment", comment))
	}
	return steps
}

func (u *UFW) RemoveSteps(port int, proto string) []plan.Step {
	spec := ruleKey(port, proto)
	p := strconv.Itoa(port)
	return []plan.Step{
		plan.OptCmd("remove allow "+spec, "ufw", "delete", "allow", spec),
		plan.OptCmd("remove limit "+spec, "ufw", "delete", "limit", spec),
		plan.OptCmd("remove allow "+p+" (any proto)", "ufw", "delete", "allow", p),
	}
}

func (u *UFW) Status() string {
	if !u.Installed() {
		return "ufw is not installed"
	}
	out, err := u.h.Query("ufw", "status", "verbose")
	if err != nil {
		return err.Error()
	}
	return out
}

func (u *UFW) Rules() ([]system.PortRule, error) {
	out, err := u.h.Query("ufw", "status")
	if err != nil {
		return nil, err
	}
	return parseUFW(out), nil
}

func parseUFW(out string) []system.PortRule {
	seen := map[string]bool{}
	var rules []system.PortRule
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "(v6)") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		action := strings.ToUpper(f[1])
		if action != "ALLOW" && action != "LIMIT" {
			continue
		}
		portS, proto, ok := strings.Cut(f[0], "/")
		if !ok {
			proto = "tcp"
		}
		p, err := strconv.Atoi(portS)
		if err != nil {
			continue // app profiles, ranges
		}
		k := ruleKey(p, proto)
		if seen[k] {
			continue
		}
		seen[k] = true
		r := system.PortRule{Port: p, Proto: proto, Limit: action == "LIMIT"}
		if _, c, ok := strings.Cut(line, "#"); ok {
			r.Comment = strings.TrimSpace(c)
		}
		rules = append(rules, r)
	}
	sortRules(rules)
	return rules
}

func (u *UFW) StateFiles() []string {
	return []string{"/etc/ufw/user.rules", "/etc/ufw/user6.rules", "/etc/ufw/ufw.conf", "/etc/default/ufw"}
}

func (u *UFW) ReloadCmd() []string { return []string{"ufw", "reload"} }
