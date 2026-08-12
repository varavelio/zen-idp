// Package token issues the RS256-signed ID and access tokens that the OIDC
// token endpoint hands to relying parties.
//
// # Scope
//
// An Issuer builds the claims of both token kinds from the issuer origin,
// the active parsed configuration, and the issuance instant, and signs them
// with the deterministic signing identity:
//
//   - ID tokens carry iss, sub, aud, iat, exp, the request nonce when
//     present, and every current custom claim of the user. Internal user
//     fields and claim keys beginning with idp_ are never emitted.
//   - Access tokens are thin: the user payload is limited to sub and exp,
//     plus the JWT metadata iss, a /userinfo-specific aud, iat, and an
//     optional jti binding the token to its originating session record.
//     Custom claims are never included.
//
// Both token kinds expire 900 seconds after issuance; the lifetime is a
// fixed protocol constant and is not configurable. The access token
// audience is the issuer origin followed by /userinfo, the dedicated
// audience of the /userinfo endpoint.
//
// Issuance requires the subject to still be declared, unexpired, and
// unlocked at the issuance instant; any other state yields ErrDenied.
// Signing and lock checking are injected as consumer-side interfaces
// satisfied by jwt.Signer and lock.Locks.
package token
