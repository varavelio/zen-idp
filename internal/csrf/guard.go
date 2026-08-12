package csrf

import (
	"crypto/subtle"
	"errors"
	"net/http"
)

// FieldName is the name of the hidden form field that must echo the
// anti-forgery token.
const FieldName = "csrf_token"

// ErrInvalidToken is returned when a request fails the anti-forgery check:
// its cookie or form field is missing, malformed, or does not match.
var ErrInvalidToken = errors.New("invalid CSRF token")

// Guard issues and verifies the anti-forgery tokens that protect the
// state-changing forms of one browser origin.
type Guard struct {
	// cookieName is the name of the browser cookie that carries the token.
	cookieName string
	// secure marks the cookie Secure; it must be true in production
	// deployments.
	secure bool
}

// NewGuard returns a Guard that stores its token in a cookie with the given
// name, marking it Secure when secure is true. It returns an error when
// cookieName is empty.
func NewGuard(cookieName string, secure bool) (*Guard, error) {
	if cookieName == "" {
		return nil, errors.New("csrf cookie name must not be empty")
	}
	return &Guard{cookieName: cookieName, secure: secure}, nil
}

// Token returns the anti-forgery token of the request: the value of the
// guard's cookie when present and well-formed, or a freshly generated token
// stored in a new cookie on the response. Handlers render the returned value
// into every state-changing form so the browser echoes it back on
// submission.
func (guard *Guard) Token(w http.ResponseWriter, r *http.Request) (string, error) {
	if cookie, err := r.Cookie(guard.cookieName); err == nil && validToken(cookie.Value) {
		return cookie.Value, nil
	}
	token, err := generateToken()
	if err != nil {
		return "", err
	}
	http.SetCookie(w, guard.cookie(token))
	return token, nil
}

// Verify checks that the request carries the anti-forgery token both in the
// guard's cookie and in the FieldName form field, and that the two values
// match. It returns ErrInvalidToken when the token is missing, malformed,
// or mismatched. The token must travel in the request body: query
// parameters are ignored.
func (guard *Guard) Verify(r *http.Request) error {
	cookie, err := r.Cookie(guard.cookieName)
	if err != nil || !validToken(cookie.Value) {
		return ErrInvalidToken
	}
	field := r.PostFormValue(FieldName)
	if !validToken(field) {
		return ErrInvalidToken
	}
	if subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(field)) != 1 {
		return ErrInvalidToken
	}
	return nil
}

// cookie returns the browser cookie that carries the given token.
func (guard *Guard) cookie(token string) *http.Cookie {
	return &http.Cookie{
		Name:     guard.cookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   guard.secure,
		SameSite: http.SameSiteLaxMode,
	}
}
