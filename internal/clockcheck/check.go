package clockcheck

import (
	"fmt"
	"time"

	"github.com/varavelio/zen-idp/internal/clock"
)

// minimum is the earliest instant at which a Zen IdP v1 deployment can
// legitimately run; every real deployment observes a later instant.
var minimum = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

// maximum is the latest instant at which a Zen IdP v1 deployment can
// legitimately run; every real deployment observes an earlier instant.
var maximum = time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)

// Check verifies that now is a plausible system instant for operating Zen
// IdP. It rejects instants before minimum and after maximum with an error
// that reports the observed instant, the violated bound, and the corrective
// action, so that startup can fail safely before any state is touched.
func Check(now time.Time) error {
	switch {
	case now.Before(minimum):
		return fmt.Errorf(
			"clock check: system time %s is earlier than the plausible minimum %s; synchronize the system clock and restart",
			clock.Format(now),
			clock.Format(minimum),
		)
	case now.After(maximum):
		return fmt.Errorf(
			"clock check: system time %s is later than the plausible maximum %s; synchronize the system clock and restart",
			clock.Format(now),
			clock.Format(maximum),
		)
	default:
		return nil
	}
}
