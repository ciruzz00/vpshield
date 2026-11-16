package system

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	ConfigDir = "/etc/vpshield"
	StateDir  = "/var/lib/vpshield"
	LogDir    = "/var/log/vpshield"
)

// Host is the single entry point for anything that touches the machine.
// Every mutating call goes through it so that dry-run and backups are
// enforced in one place.
type Host struct {
	Distro Distro
	DryRun bool

	mu       sync.Mutex
	snap     *Snapshot
	logLines []string
}

func NewHost(dryRun bool) *Host {
	return &Host{Distro: DetectDistro(), DryRun: dryRun}
}

// IsRoot reports whether we run with uid 0.
func IsRoot() bool { return os.Geteuid() == 0 }

func (h *Host) logf(format string, a ...any) {
	h.mu.Lock()
	defer h.mu.Unlock()
	line := time.Now().Format("15:04:05 ") + fmt.Sprintf(format, a...)
	h.logLines = append(h.logLines, line)
	if len(h.logLines) > 500 {
		h.logLines = h.logLines[len(h.logLines)-500:]
	}
	if !h.DryRun {
		_ = os.MkdirAll(LogDir, 0o750)
		if f, err := os.OpenFile(filepath.Join(LogDir, "vpshield.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640); err == nil {
			fmt.Fprintln(f, time.Now().Format("2006-01-02 ")+line)
			f.Close()
		}
	}
}

// Log returns the in-memory action log.
func (h *Host) Log() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.logLines...)
}

// Has reports whether a binary is in PATH (or in the usual sbin dirs).
func (h *Host) Has(bin string) bool {
	if _, err := exec.LookPath(bin); err == nil {
		return true
	}
	for _, d := range []string{"/usr/sbin", "/sbin", "/usr/local/sbin"} {
		if _, err := os.Stat(filepath.Join(d, bin)); err == nil {
			return true
		}
	}
	return false
}

func resolveBin(bin string) string {
	if strings.Contains(bin, "/") {
		return bin
	}
	if p, err := exec.LookPath(bin); err == nil {
		return p
	}
	for _, d := range []string{"/usr/sbin", "/sbin", "/usr/local/sbin"} {
		p := filepath.Join(d, bin)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return bin
}

func exe(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, resolveBin(name), args...)
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive", "LC_ALL=C")
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	out := strings.TrimRight(buf.String(), "\n")
	if ctx.Err() == context.DeadlineExceeded {
		return out, fmt.Errorf("%s: timeout after %s", name, timeout)
	}
	if err != nil {
		if out != "" {
			return out, fmt.Errorf("%s: %w: %s", name, err, lastLines(out, 3))
		}
		return out, fmt.Errorf("%s: %w", name, err)
	}
	return out, nil
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}

// Query runs a read-only command. It runs even in dry-run mode.
func (h *Host) Query(name string, args ...string) (string, error) {
	return exe(60*time.Second, name, args...)
}

// Run runs a mutating command. In dry-run it only records it.
func (h *Host) Run(name string, args ...string) (string, error) {
	return h.RunTimeout(5*time.Minute, name, args...)
}

func (h *Host) RunTimeout(t time.Duration, name string, args ...string) (string, error) {
	line := CmdString(name, args...)
	if h.DryRun {
		h.logf("[dry-run] %s", line)
		return "[dry-run] " + line, nil
	}
	h.logf("$ %s", line)
	out, err := exe(t, name, args...)
	if err != nil {
		h.logf("  error: %v", err)
	}
	return out, err
}

// RunInput runs a mutating command feeding stdin. The input is never logged
// (used for passwords: chpasswd).
func (h *Host) RunInput(stdin string, name string, args ...string) (string, error) {
	line := CmdString(name, args...) + " <<< (hidden input)"
	if h.DryRun {
		h.logf("[dry-run] %s", line)
		return "[dry-run] " + line, nil
	}
	h.logf("$ %s", line)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, resolveBin(name), args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	s := strings.TrimRight(string(out), "\n")
	if err != nil {
		h.logf("  error: %v", err)
		return s, fmt.Errorf("%s: %w: %s", name, err, lastLines(s, 3))
	}
	return s, nil
}

// RunMasked runs a mutating command whose arguments contain secrets: only
// display is logged, and the secrets are scrubbed from the output.
func (h *Host) RunMasked(display string, secrets []string, timeout time.Duration, name string, args ...string) (string, error) {
	if h.DryRun {
		h.logf("[dry-run] %s", display)
		return "[dry-run] " + display, nil
	}
	h.logf("$ %s", display)
	out, err := exe(timeout, name, args...)
	if err != nil {
		h.logf("  error: %s failed", name)
		// the error may echo arguments: do not propagate them
		return "", fmt.Errorf("%s failed: %s", display, lastLines(mask(out, secrets), 3))
	}
	return mask(out, secrets), nil
}

func mask(s string, secrets []string) string {
	for _, x := range secrets {
		if x != "" {
			s = strings.ReplaceAll(s, x, "****")
		}
	}
	return s
}

// Shell runs a mutating /bin/sh -c snippet.
func (h *Host) Shell(script string) (string, error) {
	return h.Run("/bin/sh", "-c", script)
}

// CmdString renders a command line for display.
func CmdString(name string, args ...string) string {
	parts := []string{name}
	for _, a := range args {
		if a == "" || strings.ContainsAny(a, " \t\"'$&|;<>*?()[]{}") {
			parts = append(parts, "'"+strings.ReplaceAll(a, "'", `'\''`)+"'")
		} else {
			parts = append(parts, a)
		}
	}
	return strings.Join(parts, " ")
}

// ReadFile reads a file, returning "" if it does not exist.
func ReadFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

func Exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// WriteFile backs up the current file into the active snapshot and then
// writes atomically (tmp + rename), preserving the old mode when perm is 0.
func (h *Host) WriteFile(path string, data []byte, perm os.FileMode) error {
	if h.DryRun {
		h.logf("[dry-run] write %s (%d bytes)", path, len(data))
		return nil
	}
	if err := h.Backup(path); err != nil {
		return fmt.Errorf("backup %s: %w", path, err)
	}
	if perm == 0 {
		perm = 0o644
		if st, err := os.Stat(path); err == nil {
			perm = st.Mode().Perm()
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	// A symlinked target (e.g. /etc/resolv.conf -> stub) is replaced by a real file.
	if st, err := os.Lstat(path); err == nil && st.Mode()&os.ModeSymlink != 0 {
		if err := os.Remove(path); err != nil {
			return err
		}
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".vpshield-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	h.logf("wrote %s", path)
	return nil
}

// RemoveFile backs up and removes a file.
func (h *Host) RemoveFile(path string) error {
	if !Exists(path) {
		return nil
	}
	if h.DryRun {
		h.logf("[dry-run] rm %s", path)
		return nil
	}
	if err := h.Backup(path); err != nil {
		return err
	}
	h.logf("removed %s", path)
	return os.Remove(path)
}

// ---- packages & services ------------------------------------------------

// Install installs the packages behind a logical name, skipping nothing
// smartly: package managers are idempotent anyway.
func (h *Host) Install(logical string) (string, error) {
	pkgs := h.Distro.Packages(logical)
	if len(pkgs) == 0 {
		return "nothing to install", nil
	}
	return h.InstallPkgs(pkgs...)
}

func (h *Host) InstallPkgs(pkgs ...string) (string, error) {
	switch h.Distro.Family {
	case FamilyDebian:
		if out, err := h.RunTimeout(10*time.Minute, "apt-get", append([]string{"install", "-y", "--no-install-recommends"}, pkgs...)...); err == nil {
			return out, nil
		}
		// stale package lists are the usual cause on fresh VPS images
		if _, err := h.RunTimeout(10*time.Minute, "apt-get", "update"); err != nil {
			return "", err
		}
		return h.RunTimeout(10*time.Minute, "apt-get", append([]string{"install", "-y", "--no-install-recommends"}, pkgs...)...)
	case FamilyRHEL:
		return h.RunTimeout(10*time.Minute, "dnf", append([]string{"install", "-y"}, pkgs...)...)
	case FamilyAlpine:
		return h.RunTimeout(10*time.Minute, "apk", append([]string{"add", "--no-cache"}, pkgs...)...)
	case FamilyArch:
		return h.RunTimeout(10*time.Minute, "pacman", append([]string{"-S", "--noconfirm", "--needed"}, pkgs...)...)
	}
	return "", errors.New("unsupported distribution: install manually: " + strings.Join(pkgs, " "))
}

// EnsureEPEL enables EPEL on RHEL clones (fail2ban lives there).
func (h *Host) EnsureEPEL() (string, error) {
	if h.Distro.Family != FamilyRHEL || h.Distro.ID == "fedora" {
		return "not needed", nil
	}
	if out, _ := h.Query("rpm", "-q", "epel-release"); strings.HasPrefix(out, "epel-release") {
		return "already enabled", nil
	}
	if out, err := h.Run("dnf", "install", "-y", "epel-release"); err == nil {
		return out, nil
	}
	url := fmt.Sprintf("https://dl.fedoraproject.org/pub/epel/epel-release-latest-%s.noarch.rpm", h.Distro.MajorVersion())
	return h.Run("dnf", "install", "-y", url)
}

func (h *Host) ServiceEnableNow(svc string) (string, error) {
	if h.DryRun {
		h.logf("[dry-run] service %s enable --now", svc)
		return "[dry-run] service " + svc + " enable --now", nil
	}
	switch h.Distro.Init {
	case InitSystemd:
		return h.Run("systemctl", "enable", "--now", svc)
	case InitOpenRC:
		if _, err := h.Run("rc-update", "add", svc, "default"); err != nil {
			return "", err
		}
		return h.Run("rc-service", svc, "start")
	}
	return "", errors.New("unknown init system")
}

func (h *Host) ServiceRestart(svc string) (string, error) {
	if h.DryRun {
		h.logf("[dry-run] service %s restart", svc)
		return "[dry-run] service " + svc + " restart", nil
	}
	switch h.Distro.Init {
	case InitSystemd:
		return h.Run("systemctl", "restart", svc)
	case InitOpenRC:
		return h.Run("rc-service", svc, "restart")
	}
	if h.Has("service") {
		return h.Run("service", svc, "restart")
	}
	return "", errors.New("unknown init system")
}

func (h *Host) ServiceReload(svc string) (string, error) {
	if h.DryRun {
		h.logf("[dry-run] service %s reload", svc)
		return "[dry-run] service " + svc + " reload", nil
	}
	switch h.Distro.Init {
	case InitSystemd:
		return h.Run("systemctl", "reload-or-restart", svc)
	case InitOpenRC:
		return h.Run("rc-service", svc, "reload")
	}
	if h.Has("service") {
		return h.Run("service", svc, "reload")
	}
	return "", errors.New("unknown init system")
}

func (h *Host) ServiceActive(svc string) bool {
	switch h.Distro.Init {
	case InitSystemd:
		out, _ := h.Query("systemctl", "is-active", svc)
		return strings.TrimSpace(out) == "active"
	case InitOpenRC:
		out, _ := h.Query("rc-service", svc, "status")
		return strings.Contains(out, "started")
	}
	return false
}

func (h *Host) ServiceEnabled(svc string) bool {
	switch h.Distro.Init {
	case InitSystemd:
		out, _ := h.Query("systemctl", "is-enabled", svc)
		return strings.TrimSpace(out) == "enabled"
	case InitOpenRC:
		out, _ := h.Query("rc-update", "show", "default")
		for _, l := range strings.Split(out, "\n") {
			if strings.TrimSpace(strings.SplitN(l, "|", 2)[0]) == svc {
				return true
			}
		}
	}
	return false
}

// Hostname is best effort.
func Hostname() string {
	h, _ := os.Hostname()
	return h
}
