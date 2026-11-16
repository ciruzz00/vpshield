// Package backup sends folders off the server with rclone: compressed
// archives with retention, or a mirror with versioned changes.
package backup

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"vpshield/internal/cron"
	"vpshield/internal/plan"
	"vpshield/internal/system"
)

var (
	JobsFile   = filepath.Join(system.ConfigDir, "backups.json")
	StatusFile = filepath.Join(system.StateDir, "backup-status.json")
)

const (
	ModeArchive = "archive" // dated .tar.gz per run, old ones deleted after KeepDays
	ModeSync    = "sync"    // mirror in <path>/current, changed/deleted files kept in <path>/versions/<date>
)

type Job struct {
	ID       string   `json:"id"`
	Sources  []string `json:"sources"`
	Remote   string   `json:"remote"` // rclone remote name, without ':'
	Path     string   `json:"path"`   // folder inside the remote (bucket/dir, /mnt/disk/dir ...)
	Mode     string   `json:"mode"`
	Excludes []string `json:"excludes,omitempty"`
	KeepDays int      `json:"keep_days"`
	PreCmd   string   `json:"pre_cmd,omitempty"` // e.g. a database dump before the copy
	BwLimit  string   `json:"bwlimit,omitempty"`
	Schedule string   `json:"schedule,omitempty"` // cron expression, "" = manual only
}

type Status struct {
	Time     time.Time `json:"time"`
	OK       bool      `json:"ok"`
	Duration string    `json:"duration"`
	Message  string    `json:"message"`
}

// Dest is the rclone destination of the job.
func (j Job) Dest() string { return j.Remote + ":" + strings.TrimRight(j.Path, "/") }

func (j Job) CronID() string { return "backup-" + j.ID }

func LogFile(id string) string { return filepath.Join(system.LogDir, "backup-"+id+".log") }

// ---- persistence -----------------------------------------------------------

func LoadJobs() []Job {
	var jobs []Job
	if b, err := os.ReadFile(JobsFile); err == nil {
		_ = json.Unmarshal(b, &jobs)
	}
	return jobs
}

func FindJob(id string) (Job, bool) {
	for _, j := range LoadJobs() {
		if j.ID == id {
			return j, true
		}
	}
	return Job{}, false
}

func LoadStatus() map[string]Status {
	m := map[string]Status{}
	if b, err := os.ReadFile(StatusFile); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	return m
}

func saveStatus(id string, s Status) {
	m := LoadStatus()
	m[id] = s
	b, _ := json.MarshalIndent(m, "", "  ")
	_ = os.MkdirAll(filepath.Dir(StatusFile), 0o755)
	_ = os.WriteFile(StatusFile, b, 0o644)
}

var idRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,30}$`)

func ValidID(id string, jobs []Job, editing string) error {
	if !idRe.MatchString(id) {
		return fmt.Errorf("lowercase letters, digits, - and _")
	}
	for _, j := range jobs {
		if j.ID == id && id != editing {
			return fmt.Errorf("job %s already exists", id)
		}
	}
	return nil
}

// ValidSources checks a list of absolute paths that exist.
func ValidSources(list []string) error {
	if len(list) == 0 {
		return fmt.Errorf("at least one folder")
	}
	for _, s := range list {
		if !filepath.IsAbs(s) {
			return fmt.Errorf("%s: use an absolute path", s)
		}
		if s == "/" {
			return fmt.Errorf("backing up / is not supported: pick the folders that matter")
		}
		if !system.Exists(s) {
			return fmt.Errorf("%s does not exist", s)
		}
	}
	return nil
}

func SplitList(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == '\n' || r == ' ' }) {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, filepath.Clean(f))
		}
	}
	return out
}

func SplitPatterns(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == '\n' }) {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// SavePlan writes the job list and the matching cron entries in one plan
// (so a rollback restores both).
func SavePlan(h *system.Host, jobs []Job, title string) *plan.Plan {
	sort.Slice(jobs, func(a, b int) bool { return jobs[a].ID < jobs[b].ID })
	// rebuild cron: keep non-backup jobs, add one per scheduled backup
	var cj []cron.Job
	for _, j := range cron.Load(h) {
		if !strings.HasPrefix(j.ID, "backup-") {
			cj = append(cj, j)
		}
	}
	for _, j := range jobs {
		if j.Schedule != "" {
			cj = append(cj, cron.Job{ID: j.CronID(), Schedule: j.Schedule, Command: cron.Self() + " backup run " + j.ID + " --quiet", Comment: "rclone backup " + j.ID})
		}
	}
	p := cron.SavePlan(h, cj, title)
	b, _ := json.MarshalIndent(jobs, "", "  ")
	p.Steps = append([]plan.Step{plan.File(JobsFile, string(b)+"\n", 0o600)}, p.Steps...)
	if !h.Has("rclone") {
		p.Steps = append(InstallSteps(h), p.Steps...)
	}
	return p
}

// ---- rclone ----------------------------------------------------------------

func InstallSteps(h *system.Host) []plan.Step {
	var s []plan.Step
	if h.Distro.Family == system.FamilyRHEL && h.Distro.ID != "fedora" {
		s = append(s, plan.Func("enable EPEL repository", "rclone lives in EPEL", func(h *system.Host) (string, error) { return h.EnsureEPEL() }))
	}
	s = append(s, plan.Install(h, "rclone"))
	if h.Distro.Family == system.FamilyAlpine {
		s = append(s, plan.Install(h, "tar")) // GNU tar: busybox lacks --ignore-failed-read
	}
	return s
}

func Version(h *system.Host) string {
	out, err := h.Query("rclone", "version")
	if err != nil {
		return ""
	}
	return firstLine(out)
}

func ConfigPath(h *system.Host) string {
	out, err := h.Query("rclone", "config", "file")
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

type Remote struct{ Name, Type string }

func ParseRemotes(out string) []Remote {
	var rs []Remote
	for _, l := range strings.Split(out, "\n") {
		name, typ, ok := strings.Cut(strings.TrimSpace(l), ":")
		if !ok || name == "" {
			continue
		}
		rs = append(rs, Remote{Name: name, Type: strings.TrimSpace(typ)})
	}
	return rs
}

func Remotes(h *system.Host) ([]Remote, error) {
	if !h.Has("rclone") {
		return nil, fmt.Errorf("rclone is not installed")
	}
	out, err := h.Query("rclone", "listremotes", "--long")
	if err != nil {
		return nil, err
	}
	return ParseRemotes(out), nil
}

var remoteNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,40}$`)

func ValidRemoteName(n string, existing []Remote) error {
	if !remoteNameRe.MatchString(n) {
		return fmt.Errorf("letters, digits, . _ -")
	}
	for _, r := range existing {
		if r.Name == n {
			return fmt.Errorf("remote %s already exists", n)
		}
	}
	return nil
}

// Param is one key of a remote definition; Secret values are hidden in the
// plan and in the logs (rclone obscures them in its config).
type Param struct {
	Key, Value string
	Secret     bool
}

// CreateRemotePlan adds a remote with "rclone config create".
func CreateRemotePlan(h *system.Host, name, typ string, params []Param) *plan.Plan {
	p := &plan.Plan{Title: "Add rclone remote " + name}
	if !h.Has("rclone") {
		p.Add(InstallSteps(h)...)
	}
	args := []string{"config", "create", name, typ}
	shown := []string{"rclone", "config", "create", name, typ}
	var secrets []string
	for _, pr := range params {
		if pr.Value == "" {
			continue
		}
		args = append(args, pr.Key, pr.Value)
		v := pr.Value
		if pr.Secret {
			v = "****"
			secrets = append(secrets, pr.Value)
		}
		shown = append(shown, pr.Key, v)
	}
	display := system.CmdString(shown[0], shown[1:]...)
	p.Add(plan.Func("create remote "+name+" ("+typ+")", "$ "+display, func(h *system.Host) (string, error) {
		return h.RunMasked(display, secrets, 2*time.Minute, "rclone", args...)
	}))
	p.Add(plan.Step{Title: "test connection to " + name + ":", Optional: true, Run: func(h *system.Host) (string, error) {
		if h.DryRun {
			return "[dry-run] skipped", nil
		}
		return TestRemote(h, name)
	}})
	p.Warn("credentials are stored (obscured, not encrypted) in rclone.conf, readable by root only")
	return p
}

func DeleteRemotePlan(h *system.Host, name string) *plan.Plan {
	p := &plan.Plan{Title: "Delete rclone remote " + name}
	for _, j := range LoadJobs() {
		if j.Remote == name {
			p.Warn("job %s uses this remote and will fail until you edit it", j.ID)
		}
	}
	p.Add(plan.Cmd("delete remote "+name, "rclone", "config", "delete", name))
	return p
}

// TestRemote lists the top level of a remote.
func TestRemote(h *system.Host, name string) (string, error) {
	out, err := h.Query("rclone", "lsf", name+":", "--max-depth", "1", "--contimeout", "15s", "--timeout", "30s", "--retries", "1")
	if err != nil {
		return "", fmt.Errorf("cannot reach %s: %s", name, lastLine(out, err))
	}
	n := 0
	if s := strings.TrimSpace(out); s != "" {
		n = len(strings.Split(s, "\n"))
	}
	return fmt.Sprintf("%s: reachable, %d entries at top level", name, n), nil
}

func Browse(h *system.Host, target string) (string, error) {
	out, err := h.Query("rclone", "lsf", target, "--max-depth", "1", "--format", "tsp", "--separator", "  ", "--contimeout", "15s")
	if err != nil {
		return "", fmt.Errorf("%s", lastLine(out, err))
	}
	return out, nil
}

// ---- running ---------------------------------------------------------------

func commonFlags(j Job) []string {
	f := []string{"--stats-one-line", "--stats", "1m", "--stats-log-level", "NOTICE", "--retries", "3"}
	if j.BwLimit != "" {
		f = append(f, "--bwlimit", j.BwLimit)
	}
	return f
}

// ArchiveName is <host>-<job>-YYYYmmdd-HHMMSS.tar.gz.
func ArchiveName(host, id string, t time.Time) string {
	return fmt.Sprintf("%s-%s-%s.tar.gz", host, id, t.Format("20060102-150405"))
}

func archivePattern(id string) string { return "*-" + id + "-*.tar.gz" }

// TarArgs builds the tar command line writing the archive to stdout.
func TarArgs(j Job) []string {
	args := []string{"-czf", "-", "--ignore-failed-read"}
	for _, e := range j.Excludes {
		args = append(args, "--exclude="+e)
	}
	args = append(args, "-C", "/")
	for _, s := range j.Sources {
		args = append(args, strings.TrimPrefix(filepath.Clean(s), "/"))
	}
	return args
}

// SyncArgs returns one rclone sync per source.
func SyncArgs(j Job, t time.Time) [][]string {
	var out [][]string
	for _, s := range j.Sources {
		rel := strings.TrimPrefix(filepath.Clean(s), "/")
		args := []string{"sync", s, j.Dest() + "/current/" + rel,
			"--backup-dir", j.Dest() + "/versions/" + t.Format("2006-01-02_150405") + "/" + rel}
		if st, err := os.Stat(s); err == nil && !st.IsDir() {
			// a single file: copy it into its parent folder
			args = []string{"copyto", s, j.Dest() + "/current/" + rel,
				"--backup-dir", j.Dest() + "/versions/" + t.Format("2006-01-02_150405") + "/" + filepath.Dir(rel)}
		}
		for _, e := range j.Excludes {
			args = append(args, "--exclude", e)
		}
		out = append(out, append(args, commonFlags(j)...))
	}
	return out
}

// PruneArgs deletes what is older than KeepDays.
func PruneArgs(j Job) [][]string {
	if j.KeepDays <= 0 {
		return nil
	}
	age := fmt.Sprintf("%dd", j.KeepDays)
	if j.Mode == ModeArchive {
		return [][]string{{"delete", j.Dest(), "--min-age", age, "--max-depth", "1", "--include", archivePattern(j.ID)}}
	}
	return [][]string{
		{"delete", j.Dest() + "/versions", "--min-age", age},
		{"rmdirs", j.Dest() + "/versions", "--leave-root"},
	}
}

// Run executes a job now, appending to its log file and recording status.
func Run(h *system.Host, j Job) (string, error) {
	start := time.Now()
	if h.DryRun {
		var b strings.Builder
		b.WriteString("[dry-run] would run:\n")
		if j.PreCmd != "" {
			b.WriteString("  sh -c " + system.CmdString(j.PreCmd) + "\n")
		}
		if j.Mode == ModeArchive {
			b.WriteString("  tar " + system.CmdString("", TarArgs(j)...) + " | rclone rcat " + j.Dest() + "/" + ArchiveName(system.Hostname(), j.ID, start) + "\n")
		} else {
			for _, a := range SyncArgs(j, start) {
				b.WriteString("  " + system.CmdString("rclone", a...) + "\n")
			}
		}
		for _, a := range PruneArgs(j) {
			b.WriteString("  " + system.CmdString("rclone", a...) + "\n")
		}
		return b.String(), nil
	}
	_ = os.MkdirAll(system.LogDir, 0o750)
	logf, err := os.OpenFile(LogFile(j.ID), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return "", err
	}
	defer logf.Close()
	fmt.Fprintf(logf, "\n==== %s  backup %s (%s) → %s\n", start.Format(time.RFC3339), j.ID, j.Mode, j.Dest())

	msg, err := run(j, logf, start)
	st := Status{Time: start, OK: err == nil, Duration: time.Since(start).Round(time.Second).String(), Message: msg}
	if err != nil {
		st.Message = err.Error()
		fmt.Fprintf(logf, "FAILED: %v\n", err)
	} else {
		fmt.Fprintf(logf, "OK: %s (%s)\n", msg, st.Duration)
	}
	saveStatus(j.ID, st)
	return msg + " in " + st.Duration, err
}

func run(j Job, logw io.Writer, start time.Time) (string, error) {
	if !hasRclone() {
		return "", fmt.Errorf("rclone is not installed")
	}
	if j.PreCmd != "" {
		fmt.Fprintf(logw, "$ sh -c %s\n", system.CmdString(j.PreCmd))
		if err := pipeRun(logw, time.Hour, nil, "/bin/sh", "-c", j.PreCmd); err != nil {
			return "", fmt.Errorf("pre-backup command failed: %w", err)
		}
	}
	var summary string
	if j.Mode == ModeArchive {
		name := ArchiveName(system.Hostname(), j.ID, start)
		n, err := streamArchive(j, name, logw)
		if err != nil {
			return "", err
		}
		summary = fmt.Sprintf("uploaded %s (%s)", name, humanBytes(n))
	} else {
		for _, a := range SyncArgs(j, start) {
			fmt.Fprintf(logw, "$ %s\n", system.CmdString("rclone", a...))
			if err := pipeRun(logw, 12*time.Hour, nil, "rclone", a...); err != nil {
				return "", fmt.Errorf("rclone %s: %w", a[0], err)
			}
		}
		summary = fmt.Sprintf("synced %d source(s)", len(j.Sources))
	}
	for _, a := range PruneArgs(j) {
		fmt.Fprintf(logw, "$ %s\n", system.CmdString("rclone", a...))
		if err := pipeRun(logw, time.Hour, nil, "rclone", a...); err != nil {
			fmt.Fprintf(logw, "warning: prune failed: %v\n", err) // the backup itself is fine
		}
	}
	return summary, nil
}

func hasRclone() bool {
	_, err := exec.LookPath("rclone")
	return err == nil
}

// streamArchive pipes tar into "rclone rcat": no local disk space needed.
func streamArchive(j Job, name string, logw io.Writer) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Hour)
	defer cancel()
	tar := exec.CommandContext(ctx, "tar", TarArgs(j)...)
	tar.Stderr = logw
	rargs := append([]string{"rcat", j.Dest() + "/" + name}, commonFlags(j)...)
	rc := exec.CommandContext(ctx, "rclone", rargs...)
	rc.Stdout, rc.Stderr = logw, logw
	tarOut, err := tar.StdoutPipe()
	if err != nil {
		return 0, err
	}
	rcIn, err := rc.StdinPipe()
	if err != nil {
		return 0, err
	}
	fmt.Fprintf(logw, "$ tar %s | rclone %s\n", system.CmdString("", TarArgs(j)...), system.CmdString("", rargs...))
	if err := rc.Start(); err != nil {
		return 0, err
	}
	if err := tar.Start(); err != nil {
		rcIn.Close()
		rc.Wait()
		return 0, err
	}
	n, copyErr := io.Copy(rcIn, tarOut)
	rcIn.Close()
	tarErr := tar.Wait()
	rcErr := rc.Wait()
	// GNU tar exits 1 when files changed while being read: archive is usable
	if ee, ok := tarErr.(*exec.ExitError); ok && ee.ExitCode() == 1 {
		fmt.Fprintln(logw, "warning: some files changed while being archived")
		tarErr = nil
	}
	switch {
	case tarErr != nil:
		return n, fmt.Errorf("tar: %w", tarErr)
	case rcErr != nil:
		return n, fmt.Errorf("rclone rcat: %w", rcErr)
	case copyErr != nil:
		return n, copyErr
	}
	return n, nil
}

func pipeRun(logw io.Writer, t time.Duration, stdin io.Reader, name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), t)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout, cmd.Stderr, cmd.Stdin = logw, logw, stdin
	return cmd.Run()
}

// ---- restore ---------------------------------------------------------------

// Archives lists the archives of a job, newest first.
func Archives(h *system.Host, j Job) ([]string, error) {
	out, err := h.Query("rclone", "lsf", j.Dest(), "--max-depth", "1", "--files-only", "--include", archivePattern(j.ID))
	if err != nil {
		return nil, fmt.Errorf("%s", lastLine(out, err))
	}
	var list []string
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			list = append(list, l)
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(list)))
	return list, nil
}

// RestorePlan downloads an archive (or the mirror) into target.
func RestorePlan(h *system.Host, j Job, archive, target string) *plan.Plan {
	p := &plan.Plan{Title: "Restore " + j.ID + " into " + target}
	if target == "/" {
		p.Warn("restoring into / OVERWRITES the live files with the backup copy")
	}
	p.Add(plan.Func("create "+target, "", func(h *system.Host) (string, error) {
		if h.DryRun {
			return "[dry-run] mkdir -p " + target, nil
		}
		return "", os.MkdirAll(target, 0o700)
	}))
	if j.Mode == ModeArchive {
		src := j.Dest() + "/" + archive
		p.Add(plan.Func("download and extract "+archive, "$ rclone cat "+src+" | tar -xzf - -C "+target, func(h *system.Host) (string, error) {
			if h.DryRun {
				return "[dry-run] rclone cat " + src + " | tar -xzf - -C " + target, nil
			}
			return extract(src, target)
		}))
	} else {
		args := []string{"copy", j.Dest() + "/current", target}
		p.Add(plan.Step{Title: "download mirror", Detail: "$ " + system.CmdString("rclone", args...), Run: func(h *system.Host) (string, error) {
			return h.RunTimeout(12*time.Hour, "rclone", args...)
		}})
	}
	return p
}

func extract(src, target string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Hour)
	defer cancel()
	var errBuf strings.Builder
	rc := exec.CommandContext(ctx, "rclone", "cat", src)
	tar := exec.CommandContext(ctx, "tar", "-xzf", "-", "-C", target)
	rc.Stderr, tar.Stderr = &errBuf, &errBuf
	pipe, err := rc.StdoutPipe()
	if err != nil {
		return "", err
	}
	tar.Stdin = pipe
	if err := rc.Start(); err != nil {
		return "", err
	}
	if err := tar.Run(); err != nil {
		rc.Process.Kill()
		rc.Wait()
		return errBuf.String(), fmt.Errorf("tar: %w: %s", err, strings.TrimSpace(errBuf.String()))
	}
	if err := rc.Wait(); err != nil {
		return errBuf.String(), fmt.Errorf("rclone cat: %w: %s", err, strings.TrimSpace(errBuf.String()))
	}
	return "extracted into " + target, nil
}

// ---- helpers ---------------------------------------------------------------

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "\n"); i >= 0 {
		return s[:i]
	}
	return s
}

func lastLine(out string, err error) string {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if l := strings.TrimSpace(lines[i]); l != "" {
			return l
		}
	}
	return err.Error()
}
