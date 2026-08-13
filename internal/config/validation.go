package config

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	zencrypto "github.com/varavelio/zen-idp/internal/crypto"
	"gopkg.in/yaml.v3"
)

func rejectExplicitNulls(contents []byte) error {
	var document yaml.Node
	if err := yaml.Unmarshal(contents, &document); err != nil {
		return fmt.Errorf("decode configuration: %w", err)
	}
	if len(document.Content) == 0 || document.Content[0].Kind != yaml.MappingNode {
		return nil
	}

	root := document.Content[0]
	for index := 0; index < len(root.Content); index += 2 {
		key := root.Content[index].Value
		value := root.Content[index+1]
		switch key {
		case "config", "clients":
			if null := firstNull(value); null != nil {
				return fmt.Errorf(
					"decode configuration: value at line %d must not be null",
					null.Line,
				)
			}
		case "users":
			if value.Tag == "!!null" {
				return fmt.Errorf(
					"decode configuration: value at line %d must not be null",
					value.Line,
				)
			}
		}
	}
	return nil
}

func firstNull(node *yaml.Node) *yaml.Node {
	return firstNullNode(node, make(map[*yaml.Node]struct{}))
}

func firstNullNode(node *yaml.Node, visited map[*yaml.Node]struct{}) *yaml.Node {
	if _, seen := visited[node]; seen {
		return nil
	}
	visited[node] = struct{}{}
	if node.Tag == "!!null" {
		return node
	}
	if node.Kind == yaml.AliasNode && node.Alias != nil {
		return firstNullNode(node.Alias, visited)
	}
	for _, child := range node.Content {
		if null := firstNullNode(child, visited); null != nil {
			return null
		}
	}
	return nil
}

func validateDocument(document configurationDocument) error {
	ui := document.Settings.UI
	if ui.Name.Set && strings.TrimSpace(string(ui.Name.Value)) == "" {
		return fmt.Errorf("validate configuration: config.ui.name must not be blank")
	}
	if ui.LogoURL.Set && string(ui.LogoURL.Value) == "" {
		return fmt.Errorf("validate configuration: config.ui.logo_url must not be empty")
	}
	if ui.FaviconURL.Set && string(ui.FaviconURL.Value) == "" {
		return fmt.Errorf("validate configuration: config.ui.favicon_url must not be empty")
	}

	security := document.Settings.Security
	if err := validateOptionalInteger(
		"config.security.rate_limits.max_user_login_attempts",
		security.RateLimits.MaxUserLoginAttempts,
		maximumUserLoginAttempts,
	); err != nil {
		return err
	}
	if err := validateOptionalInteger(
		"config.security.rate_limits.user_login_attempts_window_seconds",
		security.RateLimits.UserLoginAttemptsWindowSeconds,
		int(maximumUserLoginAttemptsWindow/time.Second),
	); err != nil {
		return err
	}
	if err := validateOptionalInteger(
		"config.security.rate_limits.max_client_auth_attempts",
		security.RateLimits.MaxClientAuthAttempts,
		maximumClientAuthAttempts,
	); err != nil {
		return err
	}
	if err := validateOptionalInteger(
		"config.security.rate_limits.client_auth_attempts_window_seconds",
		security.RateLimits.ClientAuthAttemptsWindowSeconds,
		int(maximumClientAuthAttemptsWindow/time.Second),
	); err != nil {
		return err
	}
	if err := validateOptionalInteger(
		"config.security.session.max_age_hours",
		security.Session.MaxAgeHours,
		int(maximumSessionMaxAge/time.Hour),
	); err != nil {
		return err
	}

	maintenance := document.Settings.Maintenance
	if err := validateOptionalIntegerRange(
		"config.maintenance.cleanup_interval_seconds",
		maintenance.CleanupIntervalSeconds,
		int(minimumCleanupInterval/time.Second),
		int(maximumCleanupInterval/time.Second),
	); err != nil {
		return err
	}
	if err := validateOptionalIntegerRange(
		"config.maintenance.audit_retention_hours",
		maintenance.AuditRetentionHours,
		0,
		int(maximumAuditRetention/time.Hour),
	); err != nil {
		return err
	}

	for index, client := range document.Clients {
		if client.SecretHash.Set && strings.TrimSpace(string(client.SecretHash.Value)) == "" {
			return fmt.Errorf(
				"validate configuration: clients[%d].secret_hash must not be empty when provided",
				index,
			)
		}
	}
	return nil
}

func validateOptionalInteger(path string, value optionalInt, maximum int) error {
	return validateOptionalIntegerRange(path, value, 1, maximum)
}

func validateOptionalIntegerRange(
	path string,
	value optionalInt,
	minimum, maximum int,
) error {
	if !value.Set {
		return nil
	}
	if int(value.Value) < minimum || int(value.Value) > maximum {
		return fmt.Errorf(
			"validate configuration: %s must be between %d and %d",
			path,
			minimum,
			maximum,
		)
	}
	return nil
}

func validateIssuerURL(value string) error {
	parsed, err := url.Parse(value)
	if err != nil {
		return fmt.Errorf("must be an absolute URL: %w", err)
	}
	if parsed.User != nil || strings.ContainsAny(value, "?#") {
		return fmt.Errorf("must not contain userinfo, a query, or a fragment")
	}
	if parsed.Host == "" || parsed.Opaque != "" {
		return fmt.Errorf("must be an absolute URL")
	}

	switch strings.ToLower(parsed.Scheme) {
	case "https":
		return nil
	case "http":
		if isLocalHost(parsed.Hostname()) {
			return nil
		}
	}
	return fmt.Errorf("must use HTTPS, except for HTTP on localhost or a loopback IP")
}

func validateUI(ui UI) error {
	if ui.Name != "" && strings.TrimSpace(ui.Name) == "" {
		return fmt.Errorf("validate configuration: config.ui.name must not be blank")
	}
	if err := validateHTTPSURL(ui.LogoURL); err != nil {
		return fmt.Errorf("validate configuration: config.ui.logo_url: %w", err)
	}
	if err := validateHTTPSURL(ui.FaviconURL); err != nil {
		return fmt.Errorf("validate configuration: config.ui.favicon_url: %w", err)
	}
	return nil
}

func validateHTTPSURL(value string) error {
	if value == "" {
		return nil
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return fmt.Errorf("must be an absolute HTTPS URL: %w", err)
	}
	if !strings.EqualFold(parsed.Scheme, "https") || parsed.Host == "" ||
		parsed.Opaque != "" || parsed.User != nil {
		return fmt.Errorf("must be an absolute HTTPS URL without userinfo")
	}
	return nil
}

func validateArgon2idHash(value string) error {
	return zencrypto.ValidateCredentialHash(value)
}

func validateRedirectURIs(client Client) error {
	seen := make(map[string]struct{}, len(client.RedirectURIs))
	for index, rawURI := range client.RedirectURIs {
		if strings.TrimSpace(rawURI) == "" {
			return fmt.Errorf(
				"validate configuration: client %q redirect_uris[%d] must not be empty",
				client.ID,
				index,
			)
		}
		if _, duplicate := seen[rawURI]; duplicate {
			return fmt.Errorf(
				"validate configuration: client %q redirect URI %q is duplicated",
				client.ID,
				rawURI,
			)
		}
		seen[rawURI] = struct{}{}
		if err := validateRedirectURI(rawURI, client.SecretHash == ""); err != nil {
			return fmt.Errorf(
				"validate configuration: client %q redirect_uris[%d]: %w",
				client.ID,
				index,
				err,
			)
		}
	}
	return nil
}

func validateRedirectURI(value string, publicClient bool) error {
	if strings.ContainsAny(value, "*#") {
		return fmt.Errorf("must not contain a wildcard or fragment")
	}
	parsed, err := url.Parse(value)
	if err != nil || !parsed.IsAbs() || parsed.Scheme == "" {
		return fmt.Errorf("must be an absolute URI")
	}

	switch strings.ToLower(parsed.Scheme) {
	case "https":
		if parsed.Host == "" || parsed.Opaque != "" {
			return fmt.Errorf("HTTPS redirect URI must include a host")
		}
	case "http":
		if parsed.Host == "" || parsed.Opaque != "" || !isLocalHost(parsed.Hostname()) {
			return fmt.Errorf("HTTP redirect URI is allowed only on localhost or a loopback IP")
		}
	default:
		if !publicClient {
			return fmt.Errorf("confidential clients must use HTTPS or local-development HTTP")
		}
		if !strings.Contains(parsed.Scheme, ".") {
			return fmt.Errorf("native private-use scheme must use reverse-domain notation")
		}
	}
	return nil
}

func isLocalHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
