package yamlsource

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDiscover(t *testing.T) {
	t.Run("reads one relative file from the working directory", func(t *testing.T) {
		root := t.TempDir()
		filePath := filepath.Join(root, "config", "zen-idp.yaml")
		writeTestFile(t, filePath, "config: main\n")
		t.Chdir(root)

		files, err := Discover(filepath.Join("config", "zen-idp.yaml"))
		require.NoError(t, err)
		require.Equal(t, []File{{Path: filePath, Content: []byte("config: main\n")}}, files)
	})

	t.Run("reads immediate YAML files in deterministic order", func(t *testing.T) {
		root := t.TempDir()
		writeTestFile(t, filepath.Join(root, "marketing.yml"), "team: marketing\n")
		writeTestFile(t, filepath.Join(root, "engineering.YAML"), "team: engineering\n")
		writeTestFile(t, filepath.Join(root, "notes.txt"), "ignored\n")
		writeTestFile(t, filepath.Join(root, "nested", "ignored.yaml"), "ignored: true\n")

		files, err := Discover(root)
		require.NoError(t, err)
		require.Equal(t, []string{
			filepath.Join(root, "engineering.YAML"),
			filepath.Join(root, "marketing.yml"),
		}, filePaths(files))
	})

	t.Run("evaluates a recursive doublestar glob", func(t *testing.T) {
		root := t.TempDir()
		writeTestFile(t, filepath.Join(root, "1.yaml"), "level: 1\n")
		writeTestFile(t, filepath.Join(root, "bar", "2.yaml"), "level: 2\n")
		writeTestFile(t, filepath.Join(root, "bar", "baz", "3.yaml"), "level: 3\n")

		files, err := Discover(filepath.Join(root, "**", "*.yaml"))
		require.NoError(t, err)
		require.Equal(t, []string{
			filepath.Join(root, "1.yaml"),
			filepath.Join(root, "bar", "2.yaml"),
			filepath.Join(root, "bar", "baz", "3.yaml"),
		}, filePaths(files))
	})

	t.Run("does not expand directories matched by a glob", func(t *testing.T) {
		root := t.TempDir()
		writeTestFile(t, filepath.Join(root, "users", "user.yaml"), "user: one\n")

		files, err := Discover(filepath.Join(root, "u*"))

		require.Nil(t, files)
		require.ErrorContains(t, err, "no YAML files found")
	})

	t.Run("accepts exact and globbed symlinks to YAML files", func(t *testing.T) {
		root := t.TempDir()
		target := filepath.Join(root, "targets", "instance.yaml")
		exactAlias := filepath.Join(root, "current")
		globAlias := filepath.Join(root, "selected", "instance")
		writeTestFile(t, target, "config: instance\n")
		require.NoError(t, os.MkdirAll(filepath.Dir(globAlias), 0o700))
		require.NoError(t, os.Symlink(target, exactAlias))
		require.NoError(t, os.Symlink(target, globAlias))

		exactFiles, err := Discover(exactAlias)
		require.NoError(t, err)
		require.Equal(t, []string{exactAlias}, filePaths(exactFiles))

		globFiles, err := Discover(filepath.Join(root, "selected", "*"))
		require.NoError(t, err)
		require.Equal(t, []string{globAlias}, filePaths(globFiles))
	})

	t.Run("includes symlinked regular YAML children", func(t *testing.T) {
		root := t.TempDir()
		target := filepath.Join(root, "targets", "source.txt")
		alias := filepath.Join(root, "config", "source.yaml")
		writeTestFile(t, target, "config: symlink\n")
		require.NoError(t, os.MkdirAll(filepath.Dir(alias), 0o700))
		require.NoError(t, os.Symlink(target, alias))

		files, err := Discover(filepath.Dir(alias))
		require.NoError(t, err)
		require.Equal(t, []string{alias}, filePaths(files))
	})

	t.Run("deduplicates aliases by resolved source identity", func(t *testing.T) {
		root := t.TempDir()
		target := filepath.Join(root, "targets", "users.yaml")
		firstAlias := filepath.Join(root, "config", "first.yaml")
		secondAlias := filepath.Join(root, "config", "second.yaml")
		writeTestFile(t, target, "users: []\n")
		require.NoError(t, os.MkdirAll(filepath.Dir(firstAlias), 0o700))
		require.NoError(t, os.Symlink(target, firstAlias))
		require.NoError(t, os.Symlink(target, secondAlias))

		files, err := Discover(filepath.Dir(firstAlias))
		require.NoError(t, err)
		require.Equal(t, []string{firstAlias}, filePaths(files))
	})

	t.Run("rejects an exact YAML alias to a non-YAML target", func(t *testing.T) {
		root := t.TempDir()
		target := filepath.Join(root, "instance.txt")
		alias := filepath.Join(root, "current.yaml")
		writeTestFile(t, target, "config: instance\n")
		require.NoError(t, os.Symlink(target, alias))

		files, err := Discover(alias)

		require.Nil(t, files)
		require.ErrorContains(t, err, "no YAML files found")
	})

	tests := map[string]struct {
		prepare   func(t *testing.T) string
		errorText string
	}{
		"empty selector": {
			prepare:   func(*testing.T) string { return "" },
			errorText: "selector is empty",
		},
		"missing exact path": {
			prepare: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "missing.yaml")
			},
			errorText: "inspect YAML selector",
		},
		"invalid glob": {
			prepare: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "[.yaml")
			},
			errorText: "evaluate YAML glob",
		},
		"glob without matches": {
			prepare: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "**", "*.yaml")
			},
			errorText: "no YAML files found",
		},
		"directory without YAML files": {
			prepare: func(t *testing.T) string {
				root := t.TempDir()
				writeTestFile(t, filepath.Join(root, "readme.txt"), "text\n")
				return root
			},
			errorText: "no YAML files found",
		},
		"exact non-YAML file": {
			prepare: func(t *testing.T) string {
				filePath := filepath.Join(t.TempDir(), "config.json")
				writeTestFile(t, filePath, "{}\n")
				return filePath
			},
			errorText: "no YAML files found",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			files, err := Discover(test.prepare(t))

			require.Nil(t, files)
			require.ErrorContains(t, err, test.errorText)
		})
	}
}

func writeTestFile(t *testing.T, filePath, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(filePath), 0o700))
	require.NoError(t, os.WriteFile(filePath, []byte(content), 0o600))
}

func filePaths(files []File) []string {
	paths := make([]string, 0, len(files))
	for _, file := range files {
		paths = append(paths, file.Path)
	}
	return paths
}
