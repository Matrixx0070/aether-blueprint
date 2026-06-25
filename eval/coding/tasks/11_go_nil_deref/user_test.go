package gonildered

import (
	"strings"
	"testing"
)

func strPtr(s string) *string { return &s }

func TestSummaryLineFullUser(t *testing.T) {
	u := &User{
		ID:      1,
		Name:    "alice",
		Email:   strPtr("alice@example.com"),
		Profile: &Profile{Bio: "engineer", Website: "alice.dev"},
	}
	s := u.SummaryLine()
	if !strings.Contains(s, "alice") || !strings.Contains(s, "alice@example.com") {
		t.Fatalf("missing name/email in: %q", s)
	}
}

func TestSummaryLineNoEmail(t *testing.T) {
	u := &User{ID: 2, Name: "bob", Profile: &Profile{Bio: "musician"}}
	// Must NOT panic.
	s := u.SummaryLine()
	if !strings.Contains(s, "bob") || !strings.Contains(s, "musician") {
		t.Fatalf("missing required substrings on nil-email user: %q", s)
	}
}

func TestSummaryLineNoProfile(t *testing.T) {
	u := &User{ID: 3, Name: "carol", Email: strPtr("c@x.io")}
	// Must NOT panic.
	s := u.SummaryLine()
	if !strings.Contains(s, "carol") {
		t.Fatalf("missing name on nil-profile user: %q", s)
	}
}

func TestCountEmailDomainsSkipsNil(t *testing.T) {
	users := []*User{
		{Name: "a", Email: strPtr("a@x.com")},
		{Name: "b"}, // nil email — must not panic, must be skipped
		{Name: "c", Email: strPtr("c@y.com")},
		{Name: "d", Email: strPtr("d@x.com")},
	}
	got := CountEmailDomains(users)
	if got != 2 {
		t.Fatalf("CountEmailDomains = %d, expected 2", got)
	}
}
