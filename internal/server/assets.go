package server

import (
	"io/fs"
	"net/http"
)

// assetCacheControl is the public cache policy applied to static assets.
// Assets are embedded in the binary and only change between releases, so a
// bounded one-hour public cache is safe.
const assetCacheControl = "public, max-age=3600"

// serveAssets serves the given embedded static asset tree at literal URL
// paths that mirror the tree's layout (for example /build/app.css), with a
// public cache policy.
func (server *Server) serveAssets(files fs.FS) handler {
	fileServer := http.FileServer(http.FS(files))
	return func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Cache-Control", assetCacheControl)
		fileServer.ServeHTTP(w, r)
		return nil
	}
}
