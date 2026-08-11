package server

import (
	"encoding/json"
	"net/http"

	"github.com/varavelio/zen-idp/internal/jwk"
)

// jwksDocument is the JSON Web Key Set response body.
type jwksDocument struct {
	Keys []jwk.PublicJWK `json:"keys"`
}

// jwks serves the public RSA signing identity as a JSON Web Key Set.
func (server *Server) jwks(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(jwksDocument{
		Keys: []jwk.PublicJWK{
			server.publicJWK,
		},
	})
}
