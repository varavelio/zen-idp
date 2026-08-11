// Package ratelimit enforces per-key attempt limits over fixed windows with
// SQLite-backed atomic counters.
//
// A Limiter is constructed with the maximum number of failed attempts
// tolerated within one window. It distinguishes two operations: Allow
// reports whether a key may still attempt (it never consumes the budget),
// and RecordFailure counts a failed attempt. Callers check Allow before
// expensive work, such as credential verification, and record the failure
// only after the work actually failed. Reset clears a key's counter after a
// successful outcome, and PurgeExpired removes counters whose window has
// ended so the counter table stays bounded.
//
// Counters live in the rate_limit_counters table and are updated by a single
// atomic upsert, so concurrent failures can never be double-counted. Windows
// are fixed: they start at the first recorded failure and end at
// reset_at, after which the counter restarts from one. The package never
// observes network addresses or forwarded headers; keys are the only input.
//
// Keys are opaque caller-chosen strings. Distinct rate-limit domains MUST
// use disjoint key namespaces so their counters never collide; the
// conventional form is prefix:identifier, for example "login:alice" or
// "admin-login". Identifiers that must not be stored verbatim SHOULD be
// represented by a deterministic keyed digest before they reach the limiter.
// Keys are bounded to maxKeyLength bytes to keep stored counters small.
package ratelimit
