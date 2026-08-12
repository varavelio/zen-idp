// Package ui renders the HTML pages served by Zen IdP with NodX and holds the
// embedded static assets (compiled stylesheet in build/, vendored fonts and
// client-side scripts in vendor/) served at literal URL paths.
//
// Pages are plain NodX trees built from the active UI configuration; the
// package exposes the shared document shell and the embedded asset tree so the
// HTTP layer can stay thin.
package ui
