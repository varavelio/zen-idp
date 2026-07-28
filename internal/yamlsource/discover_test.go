package yamlsource

import (
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/require"
)

func TestDiscover(t *testing.T) {
	filesystem := fstest.MapFS{
		"config/zen-idp.yaml":           {Data: []byte("config: main\n")},
		"config/users/engineering.YAML": {Data: []byte("users: [engineering]\n")},
		"config/users/marketing.yml":    {Data: []byte("users: [marketing]\n")},
		"config/clients/grafana.yaml":   {Data: []byte("clients: [grafana]\n")},
		"config/clients/notes.txt":      {Data: []byte("ignored")},
		"outside.yaml":                  {Data: []byte("outside: true\n")},
	}

	t.Run("reads one literal file without its siblings", func(t *testing.T) {
		files, err := Discover(filesystem, "config/zen-idp.yaml")
		require.NoError(t, err)

		require.Equal(t, []File{{
			Path:    "config/zen-idp.yaml",
			Content: []byte("config: main\n"),
		}}, files)
	})

	t.Run("reads the immediate YAML files in a directory", func(t *testing.T) {
		files, err := Discover(filesystem, "config/users")
		require.NoError(t, err)

		require.Equal(t, []string{
			"config/users/engineering.YAML",
			"config/users/marketing.yml",
		}, filePaths(files))
	})

	t.Run("evaluates doublestar glob patterns", func(t *testing.T) {
		files, err := Discover(filesystem, "config/**/m*.yml")
		require.NoError(t, err)

		require.Equal(t, []string{"config/users/marketing.yml"}, filePaths(files))
	})

	t.Run("reads a directory matched by a glob", func(t *testing.T) {
		files, err := Discover(filesystem, "config/u*")
		require.NoError(t, err)

		require.Equal(t, []string{
			"config/users/engineering.YAML",
			"config/users/marketing.yml",
		}, filePaths(files))
	})

	t.Run("does not descend into a selected directory", func(t *testing.T) {
		nestedFilesystem := fstest.MapFS{
			"foo/1.yaml":         {Data: []byte("level: 1\n")},
			"foo/bar/2.yaml":     {Data: []byte("level: 2\n")},
			"foo/bar/baz/3.yaml": {Data: []byte("level: 3\n")},
		}

		files, err := Discover(nestedFilesystem, "foo")
		require.NoError(t, err)

		require.Equal(t, []string{"foo/1.yaml"}, filePaths(files))
	})

	t.Run("descends into directories when requested by a glob", func(t *testing.T) {
		nestedFilesystem := fstest.MapFS{
			"foo/1.yaml":         {Data: []byte("level: 1\n")},
			"foo/bar/2.yaml":     {Data: []byte("level: 2\n")},
			"foo/bar/baz/3.yaml": {Data: []byte("level: 3\n")},
		}

		files, err := Discover(nestedFilesystem, "foo/**/*.yaml")
		require.NoError(t, err)

		require.Equal(t, []string{
			"foo/1.yaml",
			"foo/bar/2.yaml",
			"foo/bar/baz/3.yaml",
		}, filePaths(files))
	})

	t.Run("combines selectors without duplicate files", func(t *testing.T) {
		files, err := Discover(
			filesystem,
			"config/**/*.yaml",
			"config/users",
			"config/zen-idp.yaml",
		)
		require.NoError(t, err)

		require.Equal(t, []string{
			"config/clients/grafana.yaml",
			"config/users/engineering.YAML",
			"config/users/marketing.yml",
			"config/zen-idp.yaml",
		}, filePaths(files))
	})
}

func TestDiscoverErrors(t *testing.T) {
	tests := map[string]struct {
		filesystem fstest.MapFS
		selectors  []string
		target     error
		errorText  string
		nilFS      bool
	}{
		"nil filesystem": {
			selectors: []string{"config.yaml"},
			errorText: "filesystem is nil",
			nilFS:     true,
		},
		"no selectors": {
			filesystem: fstest.MapFS{},
			target:     ErrNoSelectors,
			errorText:  "no YAML selectors provided",
		},
		"empty selector": {
			filesystem: fstest.MapFS{},
			selectors:  []string{""},
			errorText:  "selector is empty",
		},
		"missing literal path": {
			filesystem: fstest.MapFS{},
			selectors:  []string{"missing.yaml"},
			errorText:  "inspect YAML selector",
		},
		"invalid glob": {
			filesystem: fstest.MapFS{},
			selectors:  []string{"config/[.yaml"},
			errorText:  "invalid glob pattern",
		},
		"glob without matches": {
			filesystem: fstest.MapFS{},
			selectors:  []string{"config/**/*.yaml"},
			target:     ErrNoFiles,
			errorText:  "no YAML files found",
		},
		"directory without YAML files": {
			filesystem: fstest.MapFS{"config/readme.txt": {Data: []byte("text")}},
			selectors:  []string{"config"},
			target:     ErrNoFiles,
			errorText:  "no YAML files found",
		},
		"literal non-YAML file": {
			filesystem: fstest.MapFS{"config.json": {Data: []byte("{}")}},
			selectors:  []string{"config.json"},
			target:     ErrNoFiles,
			errorText:  "no YAML files found",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var filesystem fs.FS = test.filesystem
			if test.nilFS {
				filesystem = nil
			}

			files, err := Discover(filesystem, test.selectors...)

			require.Nil(t, files)
			require.ErrorContains(t, err, test.errorText)
			if test.target != nil {
				require.ErrorIs(t, err, test.target)
			}
		})
	}
}

func filePaths(files []File) []string {
	paths := make([]string, 0, len(files))
	for _, file := range files {
		paths = append(paths, file.Path)
	}
	return paths
}
