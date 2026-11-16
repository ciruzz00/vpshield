package dns

import (
	"strings"
	"testing"
)

func TestFQDN(t *testing.T) {
	for in, want := range map[string]string{"@": "example.org", "": "example.org", "www": "www.example.org", "a.example.org": "a.example.org", "vps.": "vps.example.org"} {
		if got := FQDN(in, "example.org"); got != want {
			t.Errorf("%q: %s", in, got)
		}
	}
}

func TestValidateContent(t *testing.T) {
	if ValidateContent("A", "203.0.113.5") != nil || ValidateContent("A", "2001:db8::1") == nil || ValidateContent("AAAA", "2001:db8::1") != nil || ValidateContent("CNAME", "a b") == nil {
		t.Fatal("validation")
	}
}

func TestRenderResolved(t *testing.T) {
	p, _ := ProviderByID("quad9")
	f, _ := ProviderByID("cloudflare")
	out := RenderResolved(ResolverConfig{Primary: p, Fallback: &f, DoT: "opportunistic", DNSSEC: "allow-downgrade", IPv6: false})
	if !strings.Contains(out, "DNS=9.9.9.9#dns.quad9.net 149.112.112.112#dns.quad9.net\n") || strings.Contains(out, "2620:") {
		t.Fatal(out)
	}
	rc := RenderResolvConf(ResolverConfig{Primary: p, Fallback: &f, IPv6: true})
	if strings.Count(rc, "nameserver") != 3 {
		t.Fatal(rc)
	}
}
