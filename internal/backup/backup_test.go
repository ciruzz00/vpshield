package backup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseRemotes(t *testing.T) {
	r := ParseRemotes("b2:          b2\nsecret:      crypt\n\n")
	if len(r) != 2 || r[0].Name != "b2" || r[1].Type != "crypt" {
		t.Fatalf("%+v", r)
	}
}

func TestArgs(t *testing.T) {
	ts := time.Date(2026, 11, 16, 3, 0, 0, 0, time.UTC)
	j := Job{ID: "www", Sources: []string{"/var/www/", "/etc/nginx"}, Remote: "b2", Path: "bucket/vps/", Mode: ModeArchive,
		Excludes: []string{"*.log"}, KeepDays: 14, BwLimit: "10M"}
	if j.Dest() != "b2:bucket/vps" {
		t.Fatal(j.Dest())
	}
	tar := strings.Join(TarArgs(j), " ")
	if tar != "-czf - --ignore-failed-read --exclude=*.log -C / var/www etc/nginx" {
		t.Fatal(tar)
	}
	if n := ArchiveName("host", "www", ts); n != "host-www-20261116-030000.tar.gz" {
		t.Fatal(n)
	}
	pr := PruneArgs(j)
	if len(pr) != 1 || strings.Join(pr[0], " ") != "delete b2:bucket/vps --min-age 14d --max-depth 1 --include *-www-*.tar.gz" {
		t.Fatal(pr)
	}

	dir := t.TempDir()
	file := filepath.Join(dir, "db.sql")
	os.WriteFile(file, []byte("x"), 0o600)
	j.Mode, j.Sources = ModeSync, []string{dir, file}
	sa := SyncArgs(j, ts)
	rel := strings.TrimPrefix(dir, "/")
	if sa[0][0] != "sync" || sa[0][2] != "b2:bucket/vps/current/"+rel || sa[0][4] != "b2:bucket/vps/versions/2026-11-16_030000/"+rel {
		t.Fatal(sa[0])
	}
	if sa[1][0] != "copyto" || !strings.Contains(strings.Join(sa[1], " "), "--bwlimit 10M") {
		t.Fatal(sa[1])
	}
	if len(PruneArgs(j)) != 2 {
		t.Fatal("sync prune")
	}
	j.KeepDays = 0
	if PruneArgs(j) != nil {
		t.Fatal("keep forever must not prune")
	}
}

func TestValidate(t *testing.T) {
	if ValidSources([]string{"/"}) == nil || ValidSources([]string{"rel/path"}) == nil || ValidSources(nil) == nil {
		t.Fatal("bad sources accepted")
	}
	if err := ValidSources([]string{t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	if ValidID("Bad ID", nil, "") == nil || ValidID("a", []Job{{ID: "a"}}, "") == nil || ValidID("a", []Job{{ID: "a"}}, "a") != nil {
		t.Fatal("id validation")
	}
	if got := SplitList("/a, /b\n/c/"); strings.Join(got, "|") != "/a|/b|/c" {
		t.Fatal(got)
	}
}
