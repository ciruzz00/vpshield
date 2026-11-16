package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"vpshield/internal/backup"
	"vpshield/internal/system"
)

func testCtx() *ctx {
	h := &system.Host{DryRun: true, Distro: system.Distro{Name: "Debian 12", Family: system.FamilyDebian, Init: system.InitSystemd}}
	return &ctx{h: h, st: &system.State{}, width: 100, height: 28}
}

// render drives a screen like the App does: size, init, view.
func render(t *testing.T, name string, s Screen) string {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("%s panicked: %v", name, r)
		}
	}()
	m, _ := s.Update(tea.WindowSizeMsg{Width: 100, Height: 28})
	m.(Screen).Init()
	v := m.View()
	if strings.TrimSpace(v) == "" {
		t.Fatalf("%s rendered nothing", name)
	}
	return v
}

// Only screens that read files: the fail2ban/SSH/firewall screens query
// firewall-cmd, sshd -T... which on a desktop trigger a polkit password
// prompt when the tests run as a normal user.
func TestNewScreensRender(t *testing.T) {
	c := testCtx()
	rs := []backup.Remote{{Name: "r2", Type: "s3"}, {Name: "enc", Type: "crypt"}}
	j := backup.Job{ID: "www", Sources: []string{"/etc"}, Remote: "r2", Path: "b/vps", Mode: backup.ModeArchive, KeepDays: 14, Schedule: "5 4 * * *"}
	screens := map[string]Screen{
		"users menu":    usersMenu(c),
		"users table":   usersTable(c),
		"admin form":    adminUserForm(c),
		"sudo form":     sudoForm(c),
		"backup menu":   backupMenu(c),
		"remote form":   remoteForm(c),
		"job form new":  jobForm(c, nil, rs),
		"job form edit": jobForm(c, &j, rs),
		"restore form":  restoreForm(c, j, []string{"h-www-20261116-030000.tar.gz"}),
	}
	for name, s := range screens {
		render(t, name, s)
	}
	if v := render(t, "users menu", usersMenu(c)); !strings.Contains(v, "Create admin user") {
		t.Fatal(v)
	}
}

func TestMenuScrolls(t *testing.T) {
	c := testCtx()
	c.height = 10
	h := newHome(c)
	v := h.View()
	if !strings.Contains(v, "↓ more") {
		t.Fatalf("expected scroll marker:\n%s", v)
	}
	for i := 0; i < 14; i++ {
		h.Update(tea.KeyMsg{Type: tea.KeyDown})
	}
	v = h.View()
	if !strings.Contains(v, "Quit") || !strings.Contains(v, "↑ more") {
		t.Fatalf("cursor at bottom not visible:\n%s", v)
	}
}
