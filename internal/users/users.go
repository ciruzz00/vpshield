// Package users covers the "inside" of the server: login accounts, sudo
// rights, root password and sudo policy.
package users

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"vpshield/internal/plan"
	"vpshield/internal/system"
)

const (
	SudoDefaultsFile = "/etc/sudoers.d/00-vpshield-defaults"
	SudoGroupFile    = "/etc/sudoers.d/10-vpshield-admins"
	SudoLog          = "/var/log/sudo.log"
)

// account database files touched by useradd/usermod/passwd: snapshotted so a
// failed plan or a rollback puts them back.
var accountFiles = []string{"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow"}

type Account struct {
	Name     string
	UID, GID int
	Home     string
	Shell    string
	Groups   []string
	Sudo     bool   // can become root through sudo
	NoPasswd bool   // sudo without password
	Password string // set | locked | empty | none | ? (shadow unreadable)
	Keys     int    // authorized_keys entries
}

// CanLogin reports whether the shell allows interactive logins.
func (a Account) CanLogin() bool {
	s := a.Shell
	return s != "" && !strings.HasSuffix(s, "nologin") && !strings.HasSuffix(s, "/false") && s != "/bin/sync"
}

// Human: root or a regular (non system) account that can log in.
func (a Account) Human() bool {
	return a.CanLogin() && (a.UID == 0 || (a.UID >= uidMin() && a.UID != 65534))
}

func uidMin() int {
	for _, l := range strings.Split(system.ReadFile("/etc/login.defs"), "\n") {
		f := strings.Fields(l)
		if len(f) == 2 && f[0] == "UID_MIN" {
			if n, err := strconv.Atoi(f[1]); err == nil {
				return n
			}
		}
	}
	return 1000
}

// AdminGroup is the group that grants sudo on this distro.
func AdminGroup(h *system.Host) string {
	if h.Distro.Family == system.FamilyDebian {
		return "sudo"
	}
	return "wheel"
}

// ---- parsing ---------------------------------------------------------------

func ParsePasswd(s string) []Account {
	var out []Account
	for _, l := range strings.Split(s, "\n") {
		p := strings.Split(l, ":")
		if len(p) < 7 || strings.HasPrefix(l, "#") {
			continue
		}
		uid, _ := strconv.Atoi(p[2])
		gid, _ := strconv.Atoi(p[3])
		out = append(out, Account{Name: p[0], UID: uid, GID: gid, Home: p[5], Shell: p[6], Password: "?"})
	}
	return out
}

// ParseGroup returns user -> groups (secondary memberships plus primary).
func ParseGroup(s string, accts []Account) map[string][]string {
	byGID := map[int]string{}
	m := map[string][]string{}
	for _, l := range strings.Split(s, "\n") {
		p := strings.Split(l, ":")
		if len(p) < 4 {
			continue
		}
		gid, _ := strconv.Atoi(p[2])
		byGID[gid] = p[0]
		for _, u := range strings.Split(p[3], ",") {
			if u = strings.TrimSpace(u); u != "" {
				m[u] = append(m[u], p[0])
			}
		}
	}
	for _, a := range accts {
		if g, ok := byGID[a.GID]; ok && !contains(m[a.Name], g) {
			m[a.Name] = append([]string{g}, m[a.Name]...)
		}
	}
	return m
}

// ParseShadow returns user -> set | locked | empty | none.
func ParseShadow(s string) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(s, "\n") {
		p := strings.Split(l, ":")
		if len(p) < 2 {
			continue
		}
		pw := p[1]
		switch {
		case pw == "":
			m[p[0]] = "empty"
		case pw == "*" || pw == "!*" || pw == "!!" || pw == "!":
			m[p[0]] = "none"
		case strings.HasPrefix(pw, "!"):
			m[p[0]] = "locked"
		default:
			m[p[0]] = "set"
		}
	}
	return m
}

// SudoRule is one enabled user specification line of sudoers.
type SudoRule struct {
	Who      string // user or %group
	NoPasswd bool
	All      bool // grants ALL commands
	File     string
}

// ParseSudoers extracts user specifications ("who host=(runas) cmds").
// Aliases and Defaults are skipped: good enough to answer "who is admin".
func ParseSudoers(content, file string) []SudoRule {
	var out []SudoRule
	// join backslash continuations
	content = strings.ReplaceAll(content, "\\\n", " ")
	for _, l := range strings.Split(content, "\n") {
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "@") {
			continue
		}
		f := strings.Fields(t)
		switch f[0] {
		case "Defaults", "Cmnd_Alias", "User_Alias", "Host_Alias", "Runas_Alias":
			continue
		}
		if strings.HasPrefix(f[0], "Defaults") || !strings.Contains(t, "=") {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(t, f[0]))
		out = append(out, SudoRule{
			Who:      f[0],
			NoPasswd: strings.Contains(rest, "NOPASSWD"),
			All:      strings.HasSuffix(strings.TrimSpace(rest), "ALL"),
			File:     file,
		})
	}
	return out
}

// sudoersFiles: /etc/sudoers plus the drop-ins sudo actually reads (it skips
// names containing a dot or ending in ~).
func sudoersFiles() []string {
	files := []string{"/etc/sudoers"}
	ents, _ := os.ReadDir("/etc/sudoers.d")
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() || strings.Contains(n, ".") || strings.HasSuffix(n, "~") {
			continue
		}
		files = append(files, filepath.Join("/etc/sudoers.d", n))
	}
	return files
}

func SudoRules() []SudoRule {
	var out []SudoRule
	for _, f := range sudoersFiles() {
		out = append(out, ParseSudoers(system.ReadFile(f), f)...)
	}
	return out
}

func countKeys(home string) int {
	n := 0
	for _, f := range []string{"authorized_keys", "authorized_keys2"} {
		for _, l := range strings.Split(system.ReadFile(filepath.Join(home, ".ssh", f)), "\n") {
			if t := strings.TrimSpace(l); t != "" && !strings.HasPrefix(t, "#") {
				n++
			}
		}
	}
	return n
}

// List returns every account, with sudo rights and password state resolved
// (password state needs root).
func List() []Account {
	accts := ParsePasswd(system.ReadFile("/etc/passwd"))
	groups := ParseGroup(system.ReadFile("/etc/group"), accts)
	shadow := ParseShadow(system.ReadFile("/etc/shadow"))
	rules := SudoRules()
	for i := range accts {
		a := &accts[i]
		a.Groups = groups[a.Name]
		if pw, ok := shadow[a.Name]; ok {
			a.Password = pw
		}
		if a.CanLogin() {
			a.Keys = countKeys(a.Home)
		}
		for _, r := range rules {
			if r.Who == a.Name || (strings.HasPrefix(r.Who, "%") && contains(a.Groups, r.Who[1:])) {
				if r.All {
					a.Sudo = true
				}
				if r.NoPasswd && r.All {
					a.NoPasswd = true
				}
			}
		}
	}
	return accts
}

// Summary answers the questions the dashboard and the audit care about.
type Summary struct {
	Humans   []Account // root + regular login accounts
	Admins   []string  // non-root accounts with sudo
	OnlyRoot bool      // nobody but root can log in
	NoPasswd []string  // accounts with passwordless sudo
}

func Summarize(accts []Account) Summary {
	var s Summary
	for _, a := range accts {
		if !a.Human() {
			continue
		}
		s.Humans = append(s.Humans, a)
		if a.UID != 0 && a.Sudo {
			s.Admins = append(s.Admins, a.Name)
		}
		if a.UID != 0 && a.NoPasswd {
			s.NoPasswd = append(s.NoPasswd, a.Name)
		}
	}
	s.OnlyRoot = len(s.Humans) <= 1
	for _, a := range s.Humans {
		if a.UID != 0 {
			s.OnlyRoot = false
		}
	}
	sort.Strings(s.Admins)
	return s
}

// ---- plans -----------------------------------------------------------------

var nameRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,30}$`)

func ValidName(n string) error {
	if !nameRe.MatchString(n) {
		return fmt.Errorf("lowercase letters, digits, - and _, starting with a letter")
	}
	switch n {
	case "root", "admin", "daemon", "bin", "sys", "nobody", "sudo", "wheel":
		return fmt.Errorf("reserved name")
	}
	if _, err := user.Lookup(n); err == nil {
		return fmt.Errorf("user %s already exists", n)
	}
	return nil
}

type AdminOptions struct {
	Name         string
	Password     string // required unless NoPasswd
	NoPasswd     bool   // sudo without password (key-only accounts)
	CopyRootKeys bool
	Key          string // optional extra public key
}

func loginShell() string {
	for _, s := range []string{"/bin/bash", "/bin/ash", "/bin/sh"} {
		if system.Exists(s) {
			return s
		}
	}
	return "/bin/sh"
}

func groupRuleEnabled(group string) bool {
	for _, r := range SudoRules() {
		if r.Who == "%"+group && r.All {
			return true
		}
	}
	return false
}

func visudoCheck() plan.Step {
	return plan.Func("validate sudoers (visudo -c)", "$ visudo -c", func(h *system.Host) (string, error) {
		out, err := h.Run("visudo", "-c")
		if err != nil {
			return out, fmt.Errorf("sudoers invalid, the change is rolled back: %w", err)
		}
		return "sudoers OK", nil
	})
}

// CreateAdminPlan adds a personal account with sudo and SSH keys: the safe
// replacement for logging in as root.
func CreateAdminPlan(h *system.Host, o AdminOptions) *plan.Plan {
	p := &plan.Plan{Title: "Create admin user " + o.Name}
	p.Backups = append(p.Backups, accountFiles...)
	group := AdminGroup(h)
	needGroupRule := !groupRuleEnabled(group)
	if !h.Has("sudo") {
		p.Add(plan.Install(h, "sudo"))
	}
	if needGroupRule {
		p.Add(plan.File(SudoGroupFile, fmt.Sprintf("# Managed by vpshield\n%%%s ALL=(ALL:ALL) ALL\n", group), 0o440))
	}
	if o.NoPasswd {
		p.Add(plan.File("/etc/sudoers.d/20-vpshield-"+o.Name, fmt.Sprintf("# Managed by vpshield\n%s ALL=(ALL:ALL) NOPASSWD: ALL\n", o.Name), 0o440))
		p.Warn("%s can run sudo WITHOUT a password: whoever steals that SSH key is root", o.Name)
	}
	shell := loginShell()
	if h.Has("useradd") {
		p.Add(plan.Cmd("create user "+o.Name, "useradd", "-m", "-s", shell, "-G", group, o.Name))
	} else { // busybox (Alpine)
		p.Add(
			plan.Cmd("create user "+o.Name, "adduser", "-D", "-s", shell, o.Name),
			plan.Cmd("add "+o.Name+" to "+group, "addgroup", o.Name, group),
		)
	}
	if o.Password != "" {
		pw := o.Password
		p.Add(plan.Func("set password for "+o.Name, "$ chpasswd  (password hidden)", func(h *system.Host) (string, error) {
			return h.RunInput(o.Name+":"+pw+"\n", "chpasswd")
		}))
	} else if !o.NoPasswd {
		p.Warn("no password set: %s will not be able to use sudo", o.Name)
	}
	var keys []string
	if o.CopyRootKeys {
		for _, l := range strings.Split(system.ReadFile("/root/.ssh/authorized_keys"), "\n") {
			if t := strings.TrimSpace(l); t != "" && !strings.HasPrefix(t, "#") {
				keys = append(keys, t)
			}
		}
	}
	if k := strings.TrimSpace(o.Key); k != "" {
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		p.Warn("no SSH key for %s: you will log in with the password until you add one", o.Name)
	}
	for _, k := range keys {
		k := k
		p.Add(plan.Func("authorize key for "+o.Name, truncate(k, 60), func(h *system.Host) (string, error) {
			return AddAuthorizedKey(h, o.Name, k)
		}))
	}
	if needGroupRule || o.NoPasswd {
		p.Add(visudoCheck())
	}
	p.Warn("before disabling root login: open a NEW terminal, run  ssh %s@<this server>  and  sudo -v", o.Name)
	return p
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// AddAuthorizedKey appends a key to the user's authorized_keys with the
// right ownership and modes.
func AddAuthorizedKey(h *system.Host, username, key string) (string, error) {
	f := strings.Fields(key)
	if len(f) < 2 {
		return "", fmt.Errorf("invalid key")
	}
	if h.DryRun {
		return "[dry-run] append key to ~" + username + "/.ssh/authorized_keys", nil
	}
	u, err := user.Lookup(username)
	if err != nil {
		return "", err
	}
	dir := filepath.Join(u.HomeDir, ".ssh")
	file := filepath.Join(dir, "authorized_keys")
	cur := system.ReadFile(file)
	if strings.Contains(cur, f[0]+" "+f[1]) {
		return "key already present", nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	content := cur
	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	content += key + "\n"
	if err := h.WriteFile(file, []byte(content), 0o600); err != nil {
		return "", err
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	_ = os.Chown(dir, uid, gid)
	_ = os.Chmod(dir, 0o700)
	_ = os.Chown(file, uid, gid)
	return "key added to " + file, nil
}

// LockPlan locks or unlocks an account password (SSH keys keep working
// unless the account is also expired).
func LockPlan(h *system.Host, name string, lock bool) *plan.Plan {
	verb, flag := "Unlock", "-u"
	if lock {
		verb, flag = "Lock", "-l"
	}
	p := &plan.Plan{Title: verb + " password of " + name}
	p.Backups = append(p.Backups, accountFiles...)
	if lock && name == "root" {
		s := Summarize(List())
		ok := false
		for _, a := range s.Humans {
			if a.UID != 0 && a.Sudo && (a.Password == "set" || a.NoPasswd) {
				ok = true
			}
		}
		if !ok {
			p.Warn("NO other account can use sudo: after locking root you may have no way to become root (only via SSH key as root)")
		}
		p.Warn("root keeps SSH key login if PermitRootLogin allows it: set it to 'no' in SSH › Hardening to close it too")
	}
	p.Add(plan.Cmd(strings.ToLower(verb)+" "+name, "passwd", flag, name))
	return p
}

// SudoDefault is a hardening line for sudoers.
type SudoDefault struct {
	ID, Line, Desc string
}

var SudoDefaults = []SudoDefault{
	{"use_pty", "Defaults use_pty", "run commands in a pseudo-terminal (blocks TTY hijacking from background jobs)"},
	{"logfile", `Defaults logfile="` + SudoLog + `"`, "log every sudo command to " + SudoLog},
	{"timeout", "Defaults timestamp_timeout=5", "ask the password again after 5 minutes"},
	{"tries", "Defaults passwd_tries=3", "3 password attempts"},
	{"lecture", "Defaults lecture=always", "show the warning lecture at every sudo"},
}

// CurrentSudoDefaults returns the ids already present in our file.
func CurrentSudoDefaults() []string {
	cur := system.ReadFile(SudoDefaultsFile)
	var ids []string
	for _, d := range SudoDefaults {
		if strings.Contains(cur, d.Line) {
			ids = append(ids, d.ID)
		}
	}
	return ids
}

func SudoHardenPlan(h *system.Host, ids []string) *plan.Plan {
	p := &plan.Plan{Title: "Harden sudo"}
	if !h.Has("sudo") {
		p.Add(plan.Install(h, "sudo"))
	}
	var b strings.Builder
	b.WriteString("# Managed by vpshield - sudo policy\n")
	for _, d := range SudoDefaults {
		if contains(ids, d.ID) {
			b.WriteString(d.Line + "\n")
		}
	}
	if len(ids) == 0 {
		p.Add(plan.Func("remove "+SudoDefaultsFile, "", func(h *system.Host) (string, error) {
			return "removed", h.RemoveFile(SudoDefaultsFile)
		}))
	} else {
		p.Add(plan.File(SudoDefaultsFile, b.String(), 0o440))
	}
	p.Add(visudoCheck())
	return p
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
