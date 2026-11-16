// Package cron manages vpshield's own cron jobs and lists the system ones.
package cron

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"vpshield/internal/plan"
	"vpshield/internal/system"
)

const (
	cronDFile  = "/etc/cron.d/vpshield"
	alpineTab  = "/etc/crontabs/root"
	blockBegin = "# BEGIN vpshield (managed block, do not edit)"
	blockEnd   = "# END vpshield"
	marker     = "# vpshield:"
)

type Job struct {
	ID       string
	Schedule string
	Command  string
	Comment  string
}

// usesCronD: busybox crond (Alpine) has no /etc/cron.d and no user column.
func usesCronD(h *system.Host) bool { return h.Distro.Family != system.FamilyAlpine }

func Path(h *system.Host) string {
	if usesCronD(h) {
		return cronDFile
	}
	return alpineTab
}

// Load returns the jobs managed by vpshield.
func Load(h *system.Host) []Job {
	content := system.ReadFile(Path(h))
	if !usesCronD(h) {
		content = extractBlock(content)
	}
	return Parse(content, usesCronD(h))
}

func extractBlock(s string) string {
	i := strings.Index(s, blockBegin)
	j := strings.Index(s, blockEnd)
	if i < 0 || j < i {
		return ""
	}
	return s[i+len(blockBegin) : j]
}

// Parse reads "# vpshield:<id> <comment>" followed by the job line.
func Parse(content string, withUser bool) []Job {
	var jobs []Job
	var pending *Job
	for _, line := range strings.Split(content, "\n") {
		t := strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(t, marker); ok {
			id, comment, _ := strings.Cut(rest, " ")
			pending = &Job{ID: id, Comment: strings.TrimSpace(comment)}
			continue
		}
		if pending == nil || t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		sched, cmd := splitSchedule(t)
		if withUser {
			_, cmd, _ = strings.Cut(cmd, " ") // drop the user column
		}
		pending.Schedule, pending.Command = sched, strings.TrimSpace(cmd)
		jobs = append(jobs, *pending)
		pending = nil
	}
	return jobs
}

func splitSchedule(line string) (string, string) {
	f := strings.Fields(line)
	if len(f) > 0 && strings.HasPrefix(f[0], "@") {
		return f[0], strings.TrimSpace(strings.TrimPrefix(line, f[0]))
	}
	if len(f) < 6 {
		return line, ""
	}
	sched := strings.Join(f[:5], " ")
	rest := line
	for i := 0; i < 5; i++ {
		rest = strings.TrimSpace(rest)
		rest = rest[strings.IndexAny(rest, " \t"):]
	}
	return sched, strings.TrimSpace(rest)
}

// Render produces the managed content.
func Render(jobs []Job, withUser bool) string {
	var b strings.Builder
	if withUser {
		b.WriteString("# Managed by vpshield - use the TUI to edit.\n")
		b.WriteString("SHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n\n")
	}
	for _, j := range jobs {
		fmt.Fprintf(&b, "%s%s %s\n", marker, j.ID, j.Comment)
		if withUser {
			fmt.Fprintf(&b, "%s root %s\n", j.Schedule, j.Command)
		} else {
			fmt.Fprintf(&b, "%s %s\n", j.Schedule, j.Command)
		}
	}
	return b.String()
}

func renderFile(h *system.Host, jobs []Job) string {
	if usesCronD(h) {
		return Render(jobs, true)
	}
	cur := system.ReadFile(alpineTab)
	block := blockBegin + "\n" + Render(jobs, false) + blockEnd + "\n"
	i := strings.Index(cur, blockBegin)
	j := strings.Index(cur, blockEnd)
	if i >= 0 && j > i {
		return cur[:i] + block + strings.TrimLeft(cur[j+len(blockEnd):], "\n")
	}
	return strings.TrimRight(cur, "\n") + "\n\n" + block
}

var fieldRe = regexp.MustCompile(`^(\*|[0-9]+(-[0-9]+)?)(/[0-9]+)?(,(\*|[0-9]+(-[0-9]+)?)(/[0-9]+)?)*$`)
var names = regexp.MustCompile(`(?i)^[a-z]{3}(-[a-z]{3})?(,[a-z]{3}(-[a-z]{3})?)*$`)

// Validate checks a 5-field expression or an @macro.
func Validate(expr string) error {
	expr = strings.TrimSpace(expr)
	switch expr {
	case "@reboot", "@yearly", "@annually", "@monthly", "@weekly", "@daily", "@midnight", "@hourly":
		return nil
	}
	f := strings.Fields(expr)
	if len(f) != 5 {
		return fmt.Errorf("need 5 fields (min hour dom month dow) or @daily/@hourly/...")
	}
	limits := [][2]int{{0, 59}, {0, 23}, {1, 31}, {1, 12}, {0, 7}}
	labels := []string{"minute", "hour", "day of month", "month", "day of week"}
	for i, v := range f {
		if (i == 3 || i == 4) && names.MatchString(v) {
			continue
		}
		if !fieldRe.MatchString(v) {
			return fmt.Errorf("invalid %s field %q", labels[i], v)
		}
		for _, n := range regexp.MustCompile(`[0-9]+`).FindAllString(strings.Split(v, "/")[0], -1) {
			x, _ := strconv.Atoi(n)
			if x < limits[i][0] || x > limits[i][1] {
				return fmt.Errorf("%s %d out of range %d-%d", labels[i], x, limits[i][0], limits[i][1])
			}
		}
	}
	return nil
}

// Preset jobs offered by the wizard. %SELF% is replaced by the vpshield path.
type Preset struct {
	ID, Name, Schedule, Command string
	Available                   func(h *system.Host) bool
}

func always(*system.Host) bool { return true }

func Presets(h *system.Host) []Preset {
	reboot := "[ -f /var/run/reboot-required ] && /sbin/shutdown -r +5 'vpshield: reboot required'"
	if h.Distro.Family == system.FamilyRHEL {
		reboot = "needs-restarting -r >/dev/null || /sbin/shutdown -r +5 'vpshield: reboot required'"
	}
	return []Preset{
		{"audit", "Daily security audit report (saved in /var/log/vpshield)", "15 6 * * *", "%SELF% audit --save --quiet", always},
		{"prune-backups", "Delete vpshield snapshots older than 30 days", "30 5 * * 0", "%SELF% prune --days 30", always},
		{"reboot-required", "Weekly reboot only if updates require it", "30 4 * * 0", reboot,
			func(h *system.Host) bool {
				return h.Distro.Family == system.FamilyDebian || h.Distro.Family == system.FamilyRHEL
			}},
		{"certbot", "Renew Let's Encrypt certificates", "17 3 * * *", "certbot renew --quiet", func(h *system.Host) bool { return h.Has("certbot") }},
		{"docker-prune", "Weekly docker cleanup (dangling images, stopped containers)", "0 5 * * 0", "docker system prune -f >/dev/null", func(h *system.Host) bool { return h.Has("docker") }},
		{"f2b-unban-all", "Daily fail2ban unban all (only if you ban aggressively)", "0 0 * * *", "fail2ban-client unban --all >/dev/null", func(h *system.Host) bool { return h.Has("fail2ban-client") }},
	}
}

func Self() string {
	if p, err := os.Executable(); err == nil {
		if r, err := filepath.EvalSymlinks(p); err == nil {
			return r
		}
		return p
	}
	return "/usr/local/bin/vpshield"
}

// ensureDaemon installs/enables the cron daemon.
func ensureDaemon(h *system.Host) []plan.Step {
	steps := []plan.Step{plan.Func("create "+system.LogDir, "", func(h *system.Host) (string, error) {
		if h.DryRun {
			return "[dry-run]", nil
		}
		return "", os.MkdirAll(system.LogDir, 0o750)
	})}
	if h.Distro.Family != system.FamilyAlpine && !h.Has("crond") && !h.Has("cron") {
		steps = append(steps, plan.Install(h, "cron"))
	}
	svc := h.Distro.Service("cron")
	steps = append(steps, plan.Step{
		Title: "enable cron daemon (" + svc + ")", Optional: true,
		Run: func(h *system.Host) (string, error) {
			if h.ServiceActive(svc) {
				return "already running", nil
			}
			return h.ServiceEnableNow(svc)
		},
	})
	return steps
}

// SavePlan writes the full managed job list.
func SavePlan(h *system.Host, jobs []Job, title string) *plan.Plan {
	p := &plan.Plan{Title: title}
	p.Add(ensureDaemon(h)...)
	perm := os.FileMode(0o644)
	if !usesCronD(h) {
		perm = 0o600
	}
	p.Add(plan.File(Path(h), renderFile(h, jobs), perm))
	if !usesCronD(h) {
		// busybox crond re-reads crontabs on change, but a restart is harmless
		p.Add(plan.OptCmd("reload crond", "rc-service", "crond", "restart"))
	}
	return p
}

func NextID(jobs []Job, base string) string {
	id := base
	for i := 2; ; i++ {
		dup := false
		for _, j := range jobs {
			if j.ID == id {
				dup = true
			}
		}
		if !dup {
			return id
		}
		id = fmt.Sprintf("%s-%d", base, i)
	}
}

// EscapePercent: cron turns unescaped % into newlines.
func EscapePercent(cmd string) string {
	var b strings.Builder
	for i, r := range cmd {
		if r == '%' && (i == 0 || cmd[i-1] != '\\') {
			b.WriteString(`\%`)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// SystemListing dumps every crontab we can see (read only).
func SystemListing(h *system.Host) string {
	var b strings.Builder
	section := func(title, body string) {
		body = strings.TrimSpace(body)
		if body == "" {
			return
		}
		fmt.Fprintf(&b, "━━ %s\n%s\n\n", title, body)
	}
	section("/etc/crontab", stripComments(system.ReadFile("/etc/crontab")))
	files, _ := filepath.Glob("/etc/cron.d/*")
	for _, f := range files {
		section(f, stripComments(system.ReadFile(f)))
	}
	if out, err := h.Query("crontab", "-l"); err == nil {
		section("crontab -l (root)", stripComments(out))
	}
	if !usesCronD(h) {
		section(alpineTab, stripComments(system.ReadFile(alpineTab)))
	}
	if h.Distro.Init == system.InitSystemd {
		if out, err := h.Query("systemctl", "list-timers", "--no-pager"); err == nil {
			section("systemd timers", out)
		}
	}
	for _, d := range []string{"hourly", "daily", "weekly", "monthly"} {
		if ents, err := os.ReadDir("/etc/cron." + d); err == nil && len(ents) > 0 {
			var n []string
			for _, e := range ents {
				if !strings.HasPrefix(e.Name(), ".") {
					n = append(n, e.Name())
				}
			}
			section("/etc/cron."+d, strings.Join(n, "  "))
		}
	}
	if b.Len() == 0 {
		return "no cron jobs found"
	}
	return b.String()
}

func stripComments(s string) string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		t := strings.TrimSpace(l)
		if t == "" || (strings.HasPrefix(t, "#") && !strings.HasPrefix(t, marker)) {
			continue
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}
