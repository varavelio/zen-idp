// Package cli parses Zen IdP command-line invocations.
//
// It owns the entire user-facing command surface: the commands, the
// flags, help requests, and usage errors. Callers receive a typed
// Invocation and never touch raw arguments.
package cli
