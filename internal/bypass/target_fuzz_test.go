package bypass

import (
	"net/url"
	"strings"
	"testing"
)

func FuzzNormalizeTarget(f *testing.F) {
	for _, seed := range []struct{ kind, value string }{
		{KindDomain, "example.com"},
		{KindURL, "https://example.com/path?probe=1"},
		{KindURL, "https://user:password@public.example.com/"},
		{KindURL, "https://127.0.0.1/"},
		{KindURL, "http://example.com/"},
	} {
		f.Add(seed.kind, seed.value)
	}
	f.Fuzz(func(t *testing.T, kind, value string) {
		normalized, err := NormalizeTarget(kind, value)
		if err != nil {
			return
		}
		parsed, parseErr := url.Parse(normalized)
		if parseErr != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || parsed.Opaque != "" {
			t.Fatalf("successful normalization returned unsafe URL %q", normalized)
		}
		if parsed.Path == "" || strings.TrimSpace(normalized) != normalized {
			t.Fatalf("successful normalization returned non-canonical URL %q", normalized)
		}
		again, againErr := NormalizeTarget(KindURL, normalized)
		if againErr != nil || again != normalized {
			t.Fatalf("normalization is not idempotent: %q -> %q, %v", normalized, again, againErr)
		}
	})
}
