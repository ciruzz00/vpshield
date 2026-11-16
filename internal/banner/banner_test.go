package banner

import (
	"strings"
	"testing"

	"vpshield/internal/system"
)

func TestRenderSSH(t *testing.T) {
	deb := RenderSSH(Config{SSHVersion: true, PreLogin: true}, system.FamilyDebian)
	if !strings.Contains(deb, "DebianBanner no") || !strings.Contains(deb, "Banner "+SSHBanner) {
		t.Fatal(deb)
	}
	rh := RenderSSH(Config{SSHVersion: true}, system.FamilyRHEL)
	if strings.Contains(rh, "DebianBanner") || !strings.Contains(rh, "VersionAddendum none") || !strings.Contains(rh, "Banner none") {
		t.Fatal(rh)
	}
}
