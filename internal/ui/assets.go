package ui

import (
	"embed"
	"io/fs"
)

// static embeds every vendored and compiled asset shipped with the binary.
//
//go:embed static
var static embed.FS

// Assets returns the embedded static asset tree, rooted at the static
// directory. Callers serve it under a URL prefix of their choice.
func Assets() fs.FS {
	sub, err := fs.Sub(static, "static")
	if err != nil {
		// The static subtree is part of the package; a missing subtree is a
		// build-time error that cannot happen at runtime.
		panic("ui: embedded static subtree is missing")
	}
	return sub
}
