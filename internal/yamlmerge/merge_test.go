package yamlmerge

import (
	"testing"

	"github.com/TwiN/deepmerge"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestMerge(t *testing.T) {
	t.Run("deeply combines mappings and appends sequences", func(t *testing.T) {
		merged, err := Merge(
			[]byte(`
config:
  issuer: https://auth.example.com
  security:
    admin_password_hash: admin-hash
users:
  - first
`),
			[]byte(`
config:
  ui:
    name: Example Auth
  security:
    rate_limits:
      max_attempts: 5
users:
  - second
clients:
  - id: grafana
`),
			[]byte(`
config:
  security:
    rate_limits:
      window_seconds: 300
users:
  - third
`),
		)
		require.NoError(t, err)

		var document map[string]any
		require.NoError(t, yaml.Unmarshal(merged, &document))
		require.Equal(t, []any{"first", "second", "third"}, document["users"])
		require.Equal(t, []any{map[string]any{"id": "grafana"}}, document["clients"])

		configuration := document["config"].(map[string]any)
		require.Equal(t, "https://auth.example.com", configuration["issuer"])
		require.Equal(t, map[string]any{"name": "Example Auth"}, configuration["ui"])
		require.Equal(t, map[string]any{
			"admin_password_hash": "admin-hash",
			"rate_limits": map[string]any{
				"max_attempts":   5,
				"window_seconds": 300,
			},
		}, configuration["security"])
	})

	t.Run("returns valid canonical YAML for one document", func(t *testing.T) {
		merged, err := Merge([]byte("users: [first]\n"))
		require.NoError(t, err)

		var document map[string]any
		require.NoError(t, yaml.Unmarshal(merged, &document))
		require.Equal(t, map[string]any{"users": []any{"first"}}, document)
	})

	t.Run("returns the exact merged YAML document", func(t *testing.T) {
		merged, err := Merge(
			[]byte(`
config:
  issuer: https://auth.example.com
  security:
    admin_password_hash: admin-hash
users:
  - first
`),
			[]byte(`
config:
  ui:
    name: Example Auth
  security:
    rate_limits:
      max_attempts: 5
users:
  - second
clients:
  - id: grafana
`),
			[]byte(`
config:
  security:
    rate_limits:
      window_seconds: 300
users:
  - third
`),
		)
		require.NoError(t, err)

		require.Equal(t, `clients:
    - id: grafana
config:
    issuer: https://auth.example.com
    security:
        admin_password_hash: admin-hash
        rate_limits:
            max_attempts: 5
            window_seconds: 300
    ui:
        name: Example Auth
users:
    - first
    - second
    - third
`, string(merged))
	})

	t.Run("rejects repeated primitive values", func(t *testing.T) {
		merged, err := Merge(
			[]byte("config:\n  issuer: https://first.example.com\n"),
			[]byte("config:\n  issuer: https://second.example.com\n"),
		)

		require.Nil(t, merged)
		require.ErrorIs(t, err, deepmerge.ErrKeyWithPrimitiveValueDefinedMoreThanOnce)
		require.ErrorContains(t, err, "document 1")
	})

	t.Run("reports the malformed document index", func(t *testing.T) {
		merged, err := Merge(
			[]byte("users: [first]\n"),
			[]byte("users: [broken\n"),
		)

		require.Nil(t, merged)
		require.ErrorContains(t, err, "document 1")
	})
}

func TestMergeErrors(t *testing.T) {
	merged, err := Merge()

	require.Nil(t, merged)
	require.ErrorIs(t, err, ErrNoDocuments)
}
