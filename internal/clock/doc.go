// Package clock defines the canonical timestamp format of Zen IdP's SQLite
// state store: UTC RFC 3339 with second precision, no fractional seconds,
// and no offsets (for example "2026-08-10T12:00:00Z").
//
// The fixed shape of this format guarantees that lexicographic string order
// equals chronological order, a property the state store queries rely on.
//
// Every timestamp written to or read from the state database must be
// produced or consumed through this package, and SQL queries must compare
// timestamps only against values formatted here, never against SQLite's
// own date functions.
package clock
