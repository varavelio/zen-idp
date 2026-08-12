package audit

// Category identifies the kind of security-relevant action an event
// describes. The constants are the v1 event vocabulary; the value is stored
// verbatim in the category column.
type Category string

// Category constants for the v1 event vocabulary.
const (
	// CategoryAdminAuthentication records administrator authentication.
	CategoryAdminAuthentication Category = "admin_authentication"
	// CategoryEnrollmentTokenCreated records enrollment-token creation.
	CategoryEnrollmentTokenCreated Category = "enrollment_token_created"
	// CategoryEnrollmentTokenConsumed records enrollment-token consumption.
	CategoryEnrollmentTokenConsumed Category = "enrollment_token_consumed"
	// CategoryLockChanged records an administrative lock change.
	CategoryLockChanged Category = "lock_change"
	// CategoryPanicAction records a user panic action.
	CategoryPanicAction Category = "panic_action"
	// CategorySessionRevoked records a session revocation.
	CategorySessionRevoked Category = "session_revoked"
	// CategoryRateLimit records a rate-limit event.
	CategoryRateLimit Category = "rate_limit"
)
