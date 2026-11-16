package updates

import (
	"strings"
	"testing"
)

func TestSetIni(t *testing.T) {
	in := "[commands]\n# upgrade_type = default\napply_updates = no\n\n[emitters]\nemit_via = stdio\n"
	out := SetIni(in, "commands", "upgrade_type", "security")
	out = SetIni(out, "commands", "apply_updates", "yes")
	out = SetIni(out, "commands", "reboot", "when-needed")
	out = SetIni(out, "base", "debuglevel", "1")
	for _, w := range []string{"upgrade_type = security", "apply_updates = yes", "reboot = when-needed\n\n[emitters]", "[base]\ndebuglevel = 1"} {
		if !strings.Contains(out, w) {
			t.Errorf("missing %q in\n%s", w, out)
		}
	}
}
