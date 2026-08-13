package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/varavelio/zen-idp/internal/config"
	"github.com/varavelio/zen-idp/internal/csrf"
	"github.com/varavelio/zen-idp/internal/onetoken"
	"github.com/varavelio/zen-idp/internal/qr"
	"github.com/varavelio/zen-idp/internal/totp"
	"github.com/varavelio/zen-idp/internal/ui"
)

// enrollPath is the user-facing enrollment interaction where a user redeems
// a one-use enrollment token and reveals their TOTP shared secret.
const enrollPath = "/enroll"

// enrollTokenParam is the name of the form field and query parameter that
// carries the enrollment token.
const enrollTokenParam = "token"

// enrollDeniedMessage is the single, indistinguishable failure message
// shown for every rejected enrollment redemption, whether the token is
// malformed, unknown, consumed, expired, stale by revision, or bound to a
// removed or expired user.
const enrollDeniedMessage = "This enrollment link is invalid or has expired."

// enrollmentIssuerFallback is the service name embedded in enrollment
// otpauth URIs when the configuration declares no display name.
const enrollmentIssuerFallback = "Zen IdP"

// EnrollmentConsumer redeems one-use enrollment tokens exactly once at the
// reveal point, satisfied by onetoken.Store.
type EnrollmentConsumer interface {
	ConsumeEnrollment(context.Context, string, time.Time) (onetoken.Enrollment, error)
}

// TOTPSecretDeriver derives the deterministic TOTP shared secret of an
// enrolled subject at a given revision, satisfied by the root-secret
// derivation wired in the command layer.
type TOTPSecretDeriver interface {
	DeriveTOTPSecret(subject string, revision uint64) (string, error)
}

// EnrollDependencies carries the injected pieces of the user enrollment
// interaction.
type EnrollDependencies struct {
	// Consume redeems one-use enrollment tokens.
	Consume EnrollmentConsumer
	// Deriver derives the TOTP shared secret of the enrolled subject.
	Deriver TOTPSecretDeriver
	// CSRF protects the enrollment form submission from cross-site
	// request forgery.
	CSRF CSRFGuard
	// Users lists every configured user, the only subjects enrollment
	// tokens may be redeemed for.
	Users []config.User
	// UI holds the presentation settings shown on enrollment pages.
	UI config.UI
}

// enrollForm renders the enrollment interaction: it invites the user to
// reveal their TOTP enrollment QR code. The token carried by the shared
// link is embedded in the form as a hidden field; without a link token the
// form asks the user to paste the token delivered by the operator instead.
// The page never consumes the token: redemption happens only on the
// protected form submission, at the point that reveals the enrollment
// material.
func (server *Server) enrollForm(w http.ResponseWriter, r *http.Request) error {
	token, err := server.enroll.CSRF.Token(w, r)
	if err != nil {
		return fmt.Errorf("get CSRF token: %w", err)
	}
	return server.renderEnrollPage(w, r.URL.Query().Get(enrollTokenParam), token, "")
}

// processEnroll handles the enrollment form submission: it verifies the
// anti-forgery token, redeems the submitted one-use enrollment token at
// the security-sensitive reveal point, checks the redeemed bindings against
// the current configuration, derives the deterministic TOTP shared secret,
// and renders the enrollment QR code. Every denial re-renders the form with
// the same generic message, never revealing which check failed.
func (server *Server) processEnroll(w http.ResponseWriter, r *http.Request) error {
	if err := server.enroll.CSRF.Verify(r); err != nil {
		if errors.Is(err, csrf.ErrInvalidToken) {
			return writeForbiddenPage(w)
		}
		return fmt.Errorf("verify CSRF token: %w", err)
	}
	if err := r.ParseForm(); err != nil {
		return fmt.Errorf("parse enrollment form: %w", err)
	}

	now := time.Now()
	enrollment, err := server.enroll.Consume.ConsumeEnrollment(
		r.Context(),
		r.PostFormValue(enrollTokenParam),
		now,
	)
	if err != nil {
		if errors.Is(err, onetoken.ErrMalformedToken) ||
			errors.Is(err, onetoken.ErrInvalidToken) ||
			errors.Is(err, onetoken.ErrExpiredToken) {
			return server.renderEnrollPageFailure(w, r, enrollDeniedMessage)
		}
		return fmt.Errorf("consume enrollment token: %w", err)
	}

	user, ok := server.resolveEnrollUser(enrollment.Subject)
	if !ok || !server.userEnrollable(user, enrollment.TOTPRev, now) {
		return server.renderEnrollPageFailure(w, r, enrollDeniedMessage)
	}

	secret, err := server.enroll.Deriver.DeriveTOTPSecret(user.Subject, user.TOTPRevision)
	if err != nil {
		return fmt.Errorf("derive TOTP secret: %w", err)
	}
	otpauthURI := totp.OTPAuthURI(secret, user.Subject, server.enrollmentIssuerName())
	qrDataURI, err := qr.Encode(otpauthURI)
	if err != nil {
		return fmt.Errorf("encode enrollment QR code: %w", err)
	}

	return server.renderEnrollmentReadyPage(
		w,
		user.Subject,
		otpauthURI,
		secret,
		qrDataURI,
	)
}

// renderEnrollPage writes the enrollment form carrying the given URL token,
// anti-forgery token, and optional denial message. The page must never be
// cached because it carries an enrollment credential.
func (server *Server) renderEnrollPage(
	w http.ResponseWriter,
	token, csrfToken, failure string,
) error {
	html, err := ui.EnrollPage(server.enroll.UI, token, csrfToken, failure).RenderString()
	if err != nil {
		return fmt.Errorf("render enroll page: %w", err)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, err = io.WriteString(w, html)
	return err
}

// renderEnrollPageFailure re-renders the enrollment form with the given
// generic denial message and a fresh anti-forgery token, dropping the
// submitted credential so it never reappears in the response.
func (server *Server) renderEnrollPageFailure(
	w http.ResponseWriter,
	r *http.Request,
	failure string,
) error {
	token, err := server.enroll.CSRF.Token(w, r)
	if err != nil {
		return fmt.Errorf("get CSRF token: %w", err)
	}
	return server.renderEnrollPage(w, "", token, failure)
}

// renderEnrollmentReadyPage writes the one-time reveal of the enrolled TOTP
// secret: the QR code, the otpauth URI, and the manual entry code. The page
// must never be cached.
func (server *Server) renderEnrollmentReadyPage(
	w http.ResponseWriter,
	subject, otpauthURI, secret, qrDataURI string,
) error {
	html, err := ui.EnrollmentReadyPage(
		server.enroll.UI,
		subject,
		otpauthURI,
		secret,
		qrDataURI,
	).RenderString()
	if err != nil {
		return fmt.Errorf("render enrollment ready page: %w", err)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, err = io.WriteString(w, html)
	return err
}

// resolveEnrollUser returns the configured user declared with exactly the
// given subject. Configuration validation guarantees that subjects are
// unique, so the first match is the only match.
func (server *Server) resolveEnrollUser(subject string) (config.User, bool) {
	for _, user := range server.enroll.Users {
		if user.Subject == subject {
			return user, true
		}
	}
	return config.User{}, false
}

// userEnrollable reports whether the configured user may complete an
// enrollment bound to the given revision: the user must still be current
// (not expired) and at the exact TOTP revision recorded on the token.
func (server *Server) userEnrollable(user config.User, revision uint64, now time.Time) bool {
	if !user.ExpiresAt.IsZero() && !user.ExpiresAt.After(now) {
		return false
	}
	return user.TOTPRevision == revision
}

// enrollmentIssuerName returns the service name embedded in enrollment
// otpauth URIs, falling back to the product name when the configuration
// declares no display name.
func (server *Server) enrollmentIssuerName() string {
	if server.enroll.UI.Name != "" {
		return server.enroll.UI.Name
	}
	return enrollmentIssuerFallback
}

// enrollmentURL returns the shareable enrollment link that carries the
// given enrollment token, derived from the configured issuer.
func (server *Server) enrollmentURL(token string) string {
	return server.issuer + enrollPath + "?" + url.Values{
		enrollTokenParam: {token},
	}.Encode()
}
