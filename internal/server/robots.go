package server

import (
	"io"
	"net/http"
)

// robotsTXT is the crawler exclusion file served at /robots.txt. Every
// page of Zen IdP is private, so the file denies crawling of the entire
// origin; the rendered pages reinforce the directive with a matching
// meta tag.
const robotsTXT = "User-agent: *\nDisallow: /\n"

// serveRobotsTXT writes the crawler exclusion file with its exact
// contents.
func serveRobotsTXT(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, err := io.WriteString(w, robotsTXT)
	return err
}
