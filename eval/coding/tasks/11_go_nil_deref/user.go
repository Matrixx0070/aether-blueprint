package gonildered

import "fmt"

// User represents an account record. Some fields are optional and may be nil.
type User struct {
	ID      int
	Name    string
	Email   *string // optional — may be nil for accounts pending verification
	Profile *Profile
}

type Profile struct {
	Bio     string
	Website string
}

// SummaryLine returns a one-line summary like "alice <a@example.com> — bio…".
// BUG: dereferences Email and Profile without nil-checking them, panicking
// at runtime on optional users.
func (u *User) SummaryLine() string {
	return fmt.Sprintf("%s <%s> — %s",
		u.Name,
		*u.Email,
		u.Profile.Bio,
	)
}

// CountEmailDomains returns the count of unique email domains across users.
// BUG: skips users without an email by panicking instead of skipping.
func CountEmailDomains(users []*User) int {
	domains := make(map[string]struct{})
	for _, u := range users {
		// BUG: *u.Email panics for u.Email == nil
		email := *u.Email
		at := -1
		for i, c := range email {
			if c == '@' {
				at = i
				break
			}
		}
		if at < 0 {
			continue
		}
		domains[email[at+1:]] = struct{}{}
	}
	return len(domains)
}
