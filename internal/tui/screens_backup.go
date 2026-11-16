package tui

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"

	"vpshield/internal/backup"
	"vpshield/internal/cron"
	"vpshield/internal/plan"
	"vpshield/internal/system"
)

func backupMenu(c *ctx) Screen {
	items := []menuItem{
		{label: "Backup jobs", desc: "run now, edit, logs, restore", action: func() tea.Cmd { return push(backupJobs(c)) }},
		{label: "New backup job", desc: "folders → remote, archive or mirror, schedule, retention", action: func() tea.Cmd { return newJobCmd(c) }},
		{label: "Remotes", desc: "rclone destinations: test, browse, delete", action: func() tea.Cmd { return push(remotesTable(c)) }},
		{label: "Add remote", desc: "S3 / R2 / Wasabi, Backblaze B2, SFTP, WebDAV, Google Drive, Dropbox, disk, encryption", action: func() tea.Cmd { return remoteFormCmd(c) }},
	}
	if !c.h.Has("rclone") {
		items = append([]menuItem{{label: "Install rclone", desc: "from the distro repositories", action: func() tea.Cmd {
			p := &plan.Plan{Title: "Install rclone"}
			p.Add(backup.InstallSteps(c.h)...)
			return push(newPlan(c, p, nil))
		}}}, items...)
	}
	m := newMenu(c, "Remote backups", items...)
	m.header = func() string { return backupHeader(c) }
	return m
}

func backupHeader(c *ctx) string {
	var lines []string
	if v := backup.Version(c.h); v != "" {
		lines = append(lines, sOK.Render("● ")+sText.Render(v)+sMuted.Render("   config: "+backup.ConfigPath(c.h)))
	} else {
		lines = append(lines, sCrit.Render("● rclone not installed")+sMuted.Render("  (1. Install rclone)"))
	}
	jobs := backup.LoadJobs()
	st := backup.LoadStatus()
	if len(jobs) == 0 {
		lines = append(lines, sWarn.Render("no backup jobs: if this disk dies, the data is gone"))
	}
	for _, j := range jobs {
		lines = append(lines, "  "+jobStatusLine(j, st[j.ID]))
	}
	lines = append(lines, sMuted.Render("Snapshots in 'Backups & rollback' only undo vpshield changes: they are not data backups."))
	return sBox.Render(strings.Join(lines, "\n"))
}

func jobStatusLine(j backup.Job, s backup.Status) string {
	sched := j.Schedule
	if sched == "" {
		sched = "manual"
	}
	head := sText.Render(fmt.Sprintf("%-14s", j.ID)) + sMuted.Render(fmt.Sprintf(" %-7s %-14s → %s", j.Mode, sched, j.Dest()))
	if s.Time.IsZero() {
		return dot(false) + " " + head + sWarn.Render("  never run")
	}
	ago := time.Since(s.Time).Round(time.Minute).String()
	if s.OK {
		return dot(true) + " " + head + sOK.Render("  ok "+ago+" ago")
	}
	return dot(false) + " " + head + sCrit.Render("  FAILED "+ago+" ago")
}

// backupDash is the one-line summary for the home screen.
func backupDash() (bool, string) {
	jobs := backup.LoadJobs()
	if len(jobs) == 0 {
		return false, "none configured"
	}
	st := backup.LoadStatus()
	var last time.Time
	failed := 0
	for _, j := range jobs {
		s := st[j.ID]
		if s.Time.IsZero() || !s.OK {
			failed++
		}
		if s.Time.After(last) {
			last = s.Time
		}
	}
	if failed > 0 {
		return false, fmt.Sprintf("%d jobs, %d failing/never run", len(jobs), failed)
	}
	return true, fmt.Sprintf("%d jobs, last %s ago", len(jobs), time.Since(last).Round(time.Minute))
}

// ---- remotes ---------------------------------------------------------------

func remotesTable(c *ctx) Screen {
	cols := []table.Column{{Title: "Remote", Width: 20}, {Title: "Type", Width: 14}, {Title: "Used by", Width: 30}}
	loader := func() ([]table.Row, error) {
		rs, err := backup.Remotes(c.h)
		if err != nil {
			return nil, err
		}
		jobs := backup.LoadJobs()
		var rows []table.Row
		for _, r := range rs {
			var used []string
			for _, j := range jobs {
				if j.Remote == r.Name {
					used = append(used, j.ID)
				}
			}
			rows = append(rows, table.Row{r.Name, r.Type, strings.Join(used, ", ")})
		}
		return rows, nil
	}
	return newTable(c, "Remotes", cols, loader,
		tableKey{key: "a", help: "add", fn: func(table.Row) tea.Cmd { return remoteFormCmd(c) }},
		tableKey{key: "t", help: "test", needRow: true, fn: func(row table.Row) tea.Cmd {
			return action(func() (string, error) { return backup.TestRemote(c.h, row[0]) })
		}},
		tableKey{key: "enter", help: "browse", needRow: true, fn: func(row table.Row) tea.Cmd {
			return push(newText(c, row[0]+":", func() string {
				out, err := backup.Browse(c.h, row[0]+":")
				if err != nil {
					return sCrit.Render("✗ " + err.Error())
				}
				if strings.TrimSpace(out) == "" {
					return sMuted.Render("(empty)")
				}
				return sMuted.Render("type  size  path") + "\n" + out
			}))
		}},
		tableKey{key: "d", help: "delete", needRow: true, fn: func(row table.Row) tea.Cmd {
			return push(newPlan(c, backup.DeleteRemotePlan(c.h, row[0]), nil))
		}},
	)
}

func remoteFormCmd(c *ctx) tea.Cmd {
	if !c.h.Has("rclone") {
		return action(func() (string, error) {
			return "", fmt.Errorf("install rclone first (Remote backups › Install rclone)")
		})
	}
	return push(remoteForm(c))
}

func remoteForm(c *ctx) Screen {
	existing, _ := backup.Remotes(c.h)
	var name string
	typ := "s3"
	v := map[string]*string{}
	val := func(k string) *string {
		if v[k] == nil {
			s := ""
			v[k] = &s
		}
		return v[k]
	}
	*val("provider") = "Cloudflare"
	*val("sftp_auth") = "key"
	*val("key_file") = "/root/.ssh/id_ed25519"
	*val("port") = "22"
	*val("vendor") = "nextcloud"
	var cryptBase string
	var baseOpts []huh.Option[string]
	for _, r := range existing {
		if r.Type != "crypt" {
			baseOpts = append(baseOpts, huh.NewOption(r.Name+"  ("+r.Type+")", r.Name))
		}
	}
	if len(baseOpts) > 0 {
		cryptBase = baseOpts[0].Value
	} else {
		baseOpts = []huh.Option[string]{huh.NewOption("(add a normal remote first)", "")}
	}
	required := func(s string) error {
		if strings.TrimSpace(s) == "" {
			return fmt.Errorf("required")
		}
		return nil
	}
	is := func(types ...string) func() bool {
		return func() bool {
			for _, t := range types {
				if typ == t {
					return false
				}
			}
			return true
		}
	}
	s3NeedsEndpoint := func() bool { p := *val("provider"); return p != "AWS" && p != "Wasabi" }

	return newForm(c, "Add remote", func() tea.Cmd {
		g := func(k string) string { return strings.TrimSpace(*val(k)) }
		var params []backup.Param
		rtype := typ
		switch typ {
		case "s3":
			params = []backup.Param{{Key: "provider", Value: g("provider")}, {Key: "access_key_id", Value: g("access_key_id")},
				{Key: "secret_access_key", Value: g("secret_access_key"), Secret: true}, {Key: "region", Value: g("region")},
				{Key: "endpoint", Value: g("endpoint")}, {Key: "env_auth", Value: "false"}}
			if g("provider") == "AWS" || g("provider") == "Wasabi" {
				params = append(params, backup.Param{Key: "acl", Value: "private"})
			}
		case "b2":
			params = []backup.Param{{Key: "account", Value: g("account")}, {Key: "key", Value: g("key"), Secret: true}, {Key: "hard_delete", Value: "true"}}
		case "sftp":
			params = []backup.Param{{Key: "host", Value: g("host")}, {Key: "user", Value: g("user")}, {Key: "port", Value: g("port")}}
			if g("sftp_auth") == "key" {
				params = append(params, backup.Param{Key: "key_file", Value: g("key_file")})
			} else {
				params = append(params, backup.Param{Key: "pass", Value: *val("pass"), Secret: true})
			}
		case "webdav":
			params = []backup.Param{{Key: "url", Value: g("url")}, {Key: "vendor", Value: g("vendor")}, {Key: "user", Value: g("user")},
				{Key: "pass", Value: *val("pass"), Secret: true}}
		case "drive":
			params = []backup.Param{{Key: "scope", Value: "drive"}, {Key: "token", Value: g("token"), Secret: true}}
		case "dropbox":
			params = []backup.Param{{Key: "token", Value: g("token"), Secret: true}}
		case "local":
			params = nil
		case "crypt":
			params = []backup.Param{{Key: "remote", Value: cryptBase + ":" + strings.Trim(g("crypt_path"), "/")},
				{Key: "password", Value: *val("crypt_pw"), Secret: true}, {Key: "filename_encryption", Value: "standard"}}
			if *val("crypt_pw2") != "" {
				params = append(params, backup.Param{Key: "password2", Value: *val("crypt_pw2"), Secret: true})
			}
		}
		p := backup.CreateRemotePlan(c.h, strings.TrimSpace(name), rtype, params)
		if typ == "crypt" {
			p.Warn("WRITE DOWN the encryption password(s) somewhere safe off this server: without them the backups cannot be decrypted")
		}
		return replace(newPlan(c, p, nil))
	},
		huh.NewGroup(
			huh.NewInput().Title("Remote name").Description("short name used in jobs, e.g. b2, r2, nas").Value(&name).
				Validate(func(s string) error { return backup.ValidRemoteName(strings.TrimSpace(s), existing) }),
			huh.NewSelect[string]().Title("Type").Options(
				huh.NewOption("S3 compatible: Cloudflare R2, AWS, Wasabi, MinIO, Scaleway...", "s3"),
				huh.NewOption("Backblaze B2", "b2"),
				huh.NewOption("SFTP: another server / NAS over SSH", "sftp"),
				huh.NewOption("WebDAV: Nextcloud, ownCloud...", "webdav"),
				huh.NewOption("Google Drive (token from your PC)", "drive"),
				huh.NewOption("Dropbox (token from your PC)", "dropbox"),
				huh.NewOption("Local disk / mounted volume", "local"),
				huh.NewOption("Encryption layer over another remote (crypt)", "crypt"),
			).Value(&typ),
		),
		// S3
		huh.NewGroup(
			huh.NewSelect[string]().Title("Provider").Options(
				huh.NewOption("Cloudflare R2", "Cloudflare"), huh.NewOption("AWS S3", "AWS"), huh.NewOption("Wasabi", "Wasabi"),
				huh.NewOption("MinIO", "Minio"), huh.NewOption("Scaleway", "Scaleway"), huh.NewOption("Other S3 compatible", "Other"),
			).Value(val("provider")),
			huh.NewInput().Title("Access key ID").Value(val("access_key_id")).Validate(required),
			huh.NewInput().Title("Secret access key").EchoMode(huh.EchoModePassword).Value(val("secret_access_key")).Validate(required),
			huh.NewInput().Title("Region").Description("AWS/Wasabi: e.g. eu-central-1 · R2: auto · empty = default").Value(val("region")),
			huh.NewInput().Title("Endpoint").Description("R2: https://<account id>.r2.cloudflarestorage.com · empty for AWS").Value(val("endpoint")).
				Validate(func(s string) error {
					if typ == "s3" && s3NeedsEndpoint() && strings.TrimSpace(s) == "" {
						return fmt.Errorf("this provider needs an endpoint")
					}
					return nil
				}),
		).WithHideFunc(is("s3")),
		// B2
		huh.NewGroup(
			huh.NewInput().Title("Application key ID").Value(val("account")).Validate(required),
			huh.NewInput().Title("Application key").EchoMode(huh.EchoModePassword).Value(val("key")).Validate(required),
			huh.NewNote().Description("Create a key restricted to one bucket in the B2 console."),
		).WithHideFunc(is("b2")),
		// SFTP
		huh.NewGroup(
			huh.NewInput().Title("Host").Value(val("host")).Validate(required),
			huh.NewInput().Title("Port").Value(val("port")).Validate(func(s string) error {
				if n, err := strconv.Atoi(s); err != nil || n < 1 || n > 65535 {
					return fmt.Errorf("1-65535")
				}
				return nil
			}),
			huh.NewInput().Title("User").Value(val("user")).Validate(required),
			huh.NewSelect[string]().Title("Authentication").Options(
				huh.NewOption("SSH key file on this server (recommended)", "key"), huh.NewOption("password", "password"),
			).Value(val("sftp_auth")),
		).WithHideFunc(is("sftp")),
		huh.NewGroup(
			huh.NewInput().Title("Private key file").Description("its public key must be in authorized_keys on the target").Value(val("key_file")).
				Validate(func(s string) error {
					if !system.Exists(strings.TrimSpace(s)) {
						return fmt.Errorf("file not found (create one with ssh-keygen -t ed25519)")
					}
					return nil
				}),
		).WithHideFunc(func() bool { return typ != "sftp" || *val("sftp_auth") != "key" }),
		// WebDAV
		huh.NewGroup(
			huh.NewInput().Title("URL").Description("Nextcloud: https://cloud.example.com/remote.php/dav/files/<user>/").Value(val("url")).Validate(required),
			huh.NewSelect[string]().Title("Vendor").Options(
				huh.NewOption("Nextcloud", "nextcloud"), huh.NewOption("ownCloud", "owncloud"), huh.NewOption("other", "other"),
			).Value(val("vendor")),
			huh.NewInput().Title("User").Value(val("user")).Validate(required),
		).WithHideFunc(is("webdav")),
		huh.NewGroup(
			huh.NewInput().Title("Password").Description("for Nextcloud use an app password").EchoMode(huh.EchoModePassword).Value(val("pass")).Validate(required),
		).WithHideFunc(func() bool { return !(typ == "webdav" || (typ == "sftp" && *val("sftp_auth") == "password")) }),
		// OAuth
		huh.NewGroup(
			huh.NewNote().Title("Token from your computer").Description(
				"This server has no browser. On YOUR computer install rclone and run:\n    rclone authorize \"drive\"     (or \"dropbox\")\nthen paste the JSON it prints ({\"access_token\": ...})."),
			huh.NewText().Title("Token JSON").Lines(4).CharLimit(0).Value(val("token")).Validate(func(s string) error {
				s = strings.TrimSpace(s)
				if !strings.HasPrefix(s, "{") || !strings.Contains(s, "access_token") {
					return fmt.Errorf("paste the {...} JSON printed by rclone authorize")
				}
				return nil
			}),
		).WithHideFunc(is("drive", "dropbox")),
		// local
		huh.NewGroup(
			huh.NewNote().Title("Local disk").Description("The job path will be an absolute folder, e.g. /mnt/backup.\nA second disk protects from mistakes, not from losing the server."),
		).WithHideFunc(is("local")),
		// crypt
		huh.NewGroup(
			huh.NewNote().Title("Client-side encryption").Description("Files and names are encrypted on this server before upload; the provider sees only noise."),
			huh.NewSelect[string]().Title("Store encrypted data in").Options(baseOpts...).Value(&cryptBase).Validate(required),
			huh.NewInput().Title("Folder inside it").Description("e.g. bucket/vps-encrypted").Value(val("crypt_path")),
			huh.NewInput().Title("Encryption password").Description("at least 12 characters, keep a copy OFF this server").
				EchoMode(huh.EchoModePassword).Value(val("crypt_pw")).Validate(func(s string) error {
				if typ == "crypt" && len(s) < 12 {
					return fmt.Errorf("at least 12 characters")
				}
				return nil
			}),
			huh.NewInput().Title("Salt password (optional)").Description("a second secret, also needed to restore").
				EchoMode(huh.EchoModePassword).Value(val("crypt_pw2")),
		).WithHideFunc(is("crypt")),
	)
}

// ---- jobs ------------------------------------------------------------------

func backupJobs(c *ctx) Screen {
	cols := []table.Column{{Title: "Job", Width: 14}, {Title: "Mode", Width: 8}, {Title: "Schedule", Width: 14}, {Title: "Last run", Width: 22}, {Title: "Sources → destination", Width: 30}}
	loader := func() ([]table.Row, error) {
		st := backup.LoadStatus()
		var rows []table.Row
		for _, j := range backup.LoadJobs() {
			last := "never"
			if s := st[j.ID]; !s.Time.IsZero() {
				last = map[bool]string{true: "ok ", false: "FAILED "}[s.OK] + s.Time.Format("01-02 15:04")
			}
			sched := j.Schedule
			if sched == "" {
				sched = "manual"
			}
			rows = append(rows, table.Row{j.ID, j.Mode, sched, last, strings.Join(j.Sources, " ") + " → " + j.Dest()})
		}
		return rows, nil
	}
	find := func(id string) (backup.Job, bool) { return backup.FindJob(id) }
	return newTable(c, "Backup jobs", cols, loader,
		tableKey{key: "enter", help: "run now", needRow: true, fn: func(row table.Row) tea.Cmd {
			j, ok := find(row[0])
			if !ok {
				return nil
			}
			p := &plan.Plan{Title: "Run backup " + j.ID}
			p.Add(plan.Func("back up "+strings.Join(j.Sources, " ")+" → "+j.Dest(), "mode "+j.Mode+", log "+backup.LogFile(j.ID),
				func(h *system.Host) (string, error) { return backup.Run(h, j) }))
			return push(newPlan(c, p, nil))
		}},
		tableKey{key: "a", help: "add", fn: func(table.Row) tea.Cmd { return newJobCmd(c) }},
		tableKey{key: "e", help: "edit", needRow: true, fn: func(row table.Row) tea.Cmd {
			if j, ok := find(row[0]); ok {
				return jobFormCmd(c, &j)
			}
			return nil
		}},
		tableKey{key: "l", help: "log", needRow: true, fn: func(row table.Row) tea.Cmd {
			return push(newText(c, "log "+row[0], func() string { return tail(backup.LogFile(row[0]), 300) }))
		}},
		tableKey{key: "x", help: "restore", needRow: true, fn: func(row table.Row) tea.Cmd {
			if j, ok := find(row[0]); ok {
				return restoreCmd(c, j)
			}
			return nil
		}},
		tableKey{key: "d", help: "delete", needRow: true, fn: func(row table.Row) tea.Cmd {
			var keep []backup.Job
			for _, j := range backup.LoadJobs() {
				if j.ID != row[0] {
					keep = append(keep, j)
				}
			}
			p := backup.SavePlan(c.h, keep, "Delete backup job "+row[0])
			p.Warn("only the job definition and its schedule are removed: data already on the remote stays there")
			return push(newPlan(c, p, nil))
		}},
	)
}

func newJobCmd(c *ctx) tea.Cmd { return jobFormCmd(c, nil) }

func jobFormCmd(c *ctx, j *backup.Job) tea.Cmd {
	if !c.h.Has("rclone") {
		return action(func() (string, error) {
			return "", fmt.Errorf("install rclone first (Remote backups › Install rclone)")
		})
	}
	rs, err := backup.Remotes(c.h)
	if err != nil {
		return action(func() (string, error) { return "", err })
	}
	if len(rs) == 0 {
		return action(func() (string, error) { return "", fmt.Errorf("no remotes yet: add one first (Add remote)") })
	}
	return push(jobForm(c, j, rs))
}

var scheduleOpts = []huh.Option[string]{
	huh.NewOption("every day at 02:30 (recommended)", "30 2 * * *"),
	huh.NewOption("every 6 hours", "15 */6 * * *"),
	huh.NewOption("every hour", "0 * * * *"),
	huh.NewOption("every Sunday at 03:00", "0 3 * * 0"),
	huh.NewOption("manual only", ""),
	huh.NewOption("custom expression", "custom"),
}

func jobForm(c *ctx, existing *backup.Job, rs []backup.Remote) Screen {
	jobs := backup.LoadJobs()
	j := backup.Job{Mode: backup.ModeArchive, KeepDays: 14, Schedule: "30 2 * * *", Remote: rs[0].Name, Path: "vpshield/" + system.Hostname()}
	editing := ""
	if existing != nil {
		j = *existing
		editing = j.ID
	}
	sources := strings.Join(j.Sources, "\n")
	excludes := strings.Join(j.Excludes, "\n")
	if existing == nil {
		sources = defaultSources()
		excludes = "*.log\n*/cache/*\nnode_modules"
	}
	sched := j.Schedule
	custom := ""
	known := false
	for _, o := range scheduleOpts {
		if o.Value == sched {
			known = true
		}
	}
	if !known {
		custom, sched = j.Schedule, "custom"
	}
	keep := strconv.Itoa(j.KeepDays)
	var remoteOpts []huh.Option[string]
	for _, r := range rs {
		remoteOpts = append(remoteOpts, huh.NewOption(r.Name+"  ("+r.Type+")", r.Name))
	}
	title := "New backup job"
	if existing != nil {
		title = "Edit backup job " + j.ID
	}
	return newForm(c, title, func() tea.Cmd {
		j.ID = strings.TrimSpace(j.ID)
		j.Sources = backup.SplitList(sources)
		j.Excludes = backup.SplitPatterns(excludes)
		j.Path = strings.TrimSpace(j.Path)
		j.PreCmd = strings.TrimSpace(j.PreCmd)
		j.BwLimit = strings.TrimSpace(j.BwLimit)
		j.KeepDays, _ = strconv.Atoi(keep)
		switch sched {
		case "custom":
			j.Schedule = strings.TrimSpace(custom)
		default:
			j.Schedule = sched
		}
		var out []backup.Job
		for _, x := range jobs {
			if x.ID != editing {
				out = append(out, x)
			}
		}
		out = append(out, j)
		p := backup.SavePlan(c.h, out, title)
		if j.Schedule == "" {
			p.Warn("manual only: nothing runs until you press enter on the job")
		}
		if remoteType(rs, j.Remote) != "crypt" {
			p.Warn("backups are NOT encrypted on %s: add a crypt remote over it if the data is sensitive", j.Remote)
		}
		return replace(newPlan(c, p, nil))
	},
		huh.NewGroup(
			huh.NewInput().Title("Job name").Description("e.g. www, db, configs").Value(&j.ID).
				Validate(func(s string) error { return backup.ValidID(strings.TrimSpace(s), jobs, editing) }),
			huh.NewText().Title("Folders to back up").Description("absolute paths, one per line").Lines(5).CharLimit(0).Value(&sources).
				Validate(func(s string) error { return backup.ValidSources(backup.SplitList(s)) }),
			huh.NewText().Title("Exclude patterns").Description("rclone/tar globs, one per line").Lines(3).CharLimit(0).Value(&excludes),
		),
		huh.NewGroup(
			huh.NewSelect[string]().Title("Destination remote").Options(remoteOpts...).Value(&j.Remote),
			huh.NewInput().Title("Folder on the remote").Description("S3/B2: bucket/folder · local: /mnt/backup/folder").Value(&j.Path).Validate(func(s string) error {
				if remoteType(rs, j.Remote) == "s3" || remoteType(rs, j.Remote) == "b2" {
					if strings.TrimSpace(strings.Trim(s, "/")) == "" {
						return fmt.Errorf("S3/B2 need at least a bucket name")
					}
				}
				return nil
			}),
			huh.NewSelect[string]().Title("Mode").Options(
				huh.NewOption("archive: one dated .tar.gz per run (simple, point-in-time restores)", backup.ModeArchive),
				huh.NewOption("mirror: sync folders, changed/deleted files kept in versions/ (big folders)", backup.ModeSync),
			).Value(&j.Mode),
			huh.NewSelect[string]().Title("Keep old backups for").Options(withCurrent(keep,
				huh.NewOption("7 days", "7"), huh.NewOption("14 days (recommended)", "14"), huh.NewOption("30 days", "30"),
				huh.NewOption("90 days", "90"), huh.NewOption("forever", "0"),
			)...).Value(&keep),
		),
		huh.NewGroup(
			huh.NewSelect[string]().Title("When").Options(scheduleOpts...).Value(&sched),
			huh.NewInput().Title("Before the backup, run (optional)").
				Description("e.g. mysqldump --all-databases > /var/backups/db.sql  (include that folder above)").Value(&j.PreCmd),
			huh.NewInput().Title("Bandwidth limit (optional)").Description("e.g. 10M = 10 MiB/s, empty = unlimited").Value(&j.BwLimit),
		),
		huh.NewGroup(
			huh.NewInput().Title("Cron expression").Description("min hour day month weekday").Value(&custom).Validate(cron.Validate),
		).WithHideFunc(func() bool { return sched != "custom" }),
	)
}

func remoteType(rs []backup.Remote, name string) string {
	for _, r := range rs {
		if r.Name == name {
			return r.Type
		}
	}
	return ""
}

// defaultSources suggests the folders that usually matter on a VPS.
func defaultSources() string {
	var out []string
	for _, p := range []string{"/etc", "/var/www", "/srv", "/home", "/root", "/opt", "/var/backups"} {
		if system.Exists(p) {
			out = append(out, p)
		}
	}
	return strings.Join(out, "\n")
}

// ---- restore ---------------------------------------------------------------

func restoreCmd(c *ctx, j backup.Job) tea.Cmd {
	if j.Mode != backup.ModeArchive {
		return push(restoreForm(c, j, nil))
	}
	// listing the remote can take a few seconds: do it off the UI goroutine
	return func() tea.Msg {
		list, err := backup.Archives(c.h, j)
		if err != nil {
			return actionDoneMsg{err: err}
		}
		if len(list) == 0 {
			return actionDoneMsg{err: fmt.Errorf("no archives of %s found on %s", j.ID, j.Dest())}
		}
		return pushMsg{restoreForm(c, j, list)}
	}
}

func restoreForm(c *ctx, j backup.Job, archives []string) Screen {
	target := "/root/restore-" + j.ID + "-" + time.Now().Format("20060102-1504")
	var archive string
	var opts []huh.Option[string]
	for _, a := range archives {
		opts = append(opts, huh.NewOption(a, a))
	}
	if len(archives) > 0 {
		archive = archives[0]
	}
	groups := []*huh.Group{}
	if j.Mode == backup.ModeArchive {
		groups = append(groups, huh.NewGroup(
			huh.NewSelect[string]().Title("Archive").Description("newest first").Options(opts...).Value(&archive).Height(10),
		))
	}
	groups = append(groups, huh.NewGroup(
		huh.NewNote().Title("Restore "+j.ID).Description("Files are restored with their full path under the target folder.\nCompare them, then copy back what you need. Restoring into / overwrites live files."),
		huh.NewInput().Title("Target folder").Value(&target).Validate(func(s string) error {
			if !strings.HasPrefix(strings.TrimSpace(s), "/") {
				return fmt.Errorf("absolute path")
			}
			return nil
		}),
	))
	return newForm(c, "Restore "+j.ID, func() tea.Cmd {
		return replace(newPlan(c, backup.RestorePlan(c.h, j, archive, strings.TrimSpace(target)), nil))
	}, groups...)
}
