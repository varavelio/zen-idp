package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestArchiveName(t *testing.T) {
	t.Run("names every release target", func(t *testing.T) {
		for _, buildTarget := range releaseTargets {
			expected := projectName + "_" + buildTarget.OS + "_" + buildTarget.Arch + "." + archiveFormat(
				buildTarget.OS,
			)
			require.Equal(t, expected, archiveName(buildTarget))
		}
	})
}

func TestArchiveFormat(t *testing.T) {
	t.Run("uses zip only for windows", func(t *testing.T) {
		require.Equal(t, "zip", archiveFormat("windows"))
		require.Equal(t, "tar.gz", archiveFormat("linux"))
		require.Equal(t, "tar.gz", archiveFormat("darwin"))
	})
}

func TestBinaryName(t *testing.T) {
	t.Run("adds the exe suffix only for windows", func(t *testing.T) {
		require.Equal(t, "zen-idp.exe", binaryName("windows"))
		require.Equal(t, "zen-idp", binaryName("linux"))
		require.Equal(t, "zen-idp", binaryName("darwin"))
	})
}

func TestNormalizeVersion(t *testing.T) {
	t.Run("strips tag prefixes and whitespace", func(t *testing.T) {
		require.Equal(t, "1.2.3", normalizeVersion("v1.2.3"))
		require.Equal(t, "1.2.3", normalizeVersion("  V1.2.3  "))
		require.Equal(t, "1.2.3", normalizeVersion("refs/tags/v1.2.3"))
		require.Equal(t, "1.2.3", normalizeVersion("1.2.3"))
		require.Equal(t, "0.1.0-alpha.6", normalizeVersion("v0.1.0-alpha.6"))
		require.Empty(t, normalizeVersion("  "))
	})
}

func TestTagLike(t *testing.T) {
	t.Run("accepts only values that start with v", func(t *testing.T) {
		require.Equal(t, "v1.2.3", tagLike("v1.2.3"))
		require.Equal(t, "v1.2.3", tagLike(" v1.2.3 "))
		require.Empty(t, tagLike("1.2.3"))
		require.Empty(t, tagLike("main"))
	})
}

func TestFirstNonEmpty(t *testing.T) {
	t.Run("returns the first trimmed non-empty value", func(t *testing.T) {
		require.Equal(t, "a", firstNonEmpty("", " a ", "b"))
		require.Equal(t, "b", firstNonEmpty("", "", "b"))
		require.Empty(t, firstNonEmpty("", " "))
	})
}

func TestDetectVersion(t *testing.T) {
	t.Run("prefers the explicit environment version", func(t *testing.T) {
		t.Setenv("ZEN_IDP_VERSION", " v0.2.1 ")
		require.Equal(t, "0.2.1", detectVersion(context.Background(), "."))
	})

	t.Run("accepts a tag-like reference name", func(t *testing.T) {
		t.Setenv("ZEN_IDP_VERSION", "")
		t.Setenv("GITHUB_REF_NAME", "v0.3.0")
		require.Equal(t, "0.3.0", detectVersion(context.Background(), "."))
	})

	t.Run("falls back to a dev version outside git", func(t *testing.T) {
		t.Setenv("ZEN_IDP_VERSION", "")
		t.Setenv("GITHUB_REF_NAME", "main")
		require.NotEmpty(t, detectVersion(context.Background(), "."))
	})
}

func TestFindProjectRoot(t *testing.T) {
	t.Run("locates the repository root from any depth", func(t *testing.T) {
		root, err := findProjectRoot()
		require.NoError(t, err)
		_, err = os.Stat(filepath.Join(root, "go.mod"))
		require.NoError(t, err)
		_, err = os.Stat(filepath.Join(root, "Taskfile.yml"))
		require.NoError(t, err)
	})

	t.Run("fails outside a project", func(t *testing.T) {
		previous, err := os.Getwd()
		require.NoError(t, err)
		t.Cleanup(func() {
			_ = os.Chdir(previous)
		})
		require.NoError(t, os.Chdir(t.TempDir()))
		_, err = findProjectRoot()
		require.Error(t, err)
	})
}

func TestFileSHA256(t *testing.T) {
	t.Run("hashes the exact file bytes", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "content.txt")
		require.NoError(t, os.WriteFile(path, []byte("zen-idp\n"), 0o644))

		checksum, err := fileSHA256(path)
		require.NoError(t, err)
		require.Equal(
			t,
			"9b1b5d78efdec84cdc4be3df29573b715b01d5122b69e30447c0f349aff4b4f9",
			checksum,
		)
	})
}

func TestWriteChecksums(t *testing.T) {
	t.Run("writes every file except the checksums file itself", func(t *testing.T) {
		distDir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(distDir, "b.txt"), []byte("b"), 0o644))
		require.NoError(t, os.WriteFile(filepath.Join(distDir, "a.txt"), []byte("a"), 0o644))
		require.NoError(t, os.Mkdir(filepath.Join(distDir, "nested"), 0o755))
		require.NoError(t, writeChecksums(distDir))

		content, err := os.ReadFile(filepath.Join(distDir, checksumFileName))
		require.NoError(t, err)

		lines := strings.Split(strings.TrimSpace(string(content)), "\n")
		require.Len(t, lines, 2)

		hashA := "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
		hashB := "3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d"
		require.Equal(t, hashA+"  a.txt", lines[0])
		require.Equal(t, hashB+"  b.txt", lines[1])
	})
}

func TestWriteManifest(t *testing.T) {
	t.Run("writes the complete release inventory", func(t *testing.T) {
		distDir := t.TempDir()
		artifacts := []releaseArtifact{
			{
				Arch:   "amd64",
				Format: "tar.gz",
				Name:   "zen-idp_linux_amd64.tar.gz",
				OS:     "linux",
				SHA256: "abc",
			},
		}
		require.NoError(t, writeManifest(distDir, "0.1.0", artifacts))

		content, err := os.ReadFile(filepath.Join(distDir, manifestFileName))
		require.NoError(t, err)

		var manifest releaseManifest
		require.NoError(t, json.Unmarshal(content, &manifest))
		require.Equal(t, "zen-idp", manifest.Project)
		require.Equal(t, "varavelio/zen-idp", manifest.Repo)
		require.Equal(t, "0.1.0", manifest.Version)
		require.Equal(t, artifacts, manifest.Artifacts)
		require.True(t, strings.HasSuffix(string(content), "\n"))
	})
}

func TestCreateArchives(t *testing.T) {
	setupFiles := func(t *testing.T) map[string]string {
		t.Helper()
		sourceDir := t.TempDir()
		binary := filepath.Join(sourceDir, binaryName("linux"))
		readme := filepath.Join(sourceDir, "README.md")
		require.NoError(t, os.WriteFile(binary, []byte("binary"), 0o755))
		require.NoError(t, os.WriteFile(readme, []byte("readme"), 0o644))

		return map[string]string{binary: binaryName("linux"), readme: "README.md"}
	}

	t.Run("packs the given files into tar.gz", func(t *testing.T) {
		archivePath := filepath.Join(t.TempDir(), archiveName(target{OS: "linux", Arch: "amd64"}))
		files := setupFiles(t)
		require.NoError(t, createTarGz(archivePath, files))

		archiveFile, err := os.Open(archivePath)
		require.NoError(t, err)
		defer func() {
			_ = archiveFile.Close()
		}()

		gzipReader, err := gzip.NewReader(archiveFile)
		require.NoError(t, err)
		tarReader := tar.NewReader(gzipReader)

		names := []string{}
		for {
			header, err := tarReader.Next()
			if err != nil {
				break
			}
			names = append(names, header.Name)
		}
		require.ElementsMatch(t, []string{"zen-idp", "README.md"}, names)
	})

	t.Run("packs the given files into zip", func(t *testing.T) {
		archivePath := filepath.Join(t.TempDir(), "archive.zip")
		files := setupFiles(t)
		require.NoError(t, createZip(archivePath, files))

		archive, err := zip.OpenReader(archivePath)
		require.NoError(t, err)
		defer func() {
			_ = archive.Close()
		}()

		names := []string{}
		for _, file := range archive.File {
			names = append(names, file.Name)
		}
		require.ElementsMatch(t, []string{"zen-idp", "README.md"}, names)
	})
}

func TestArchiveFiles(t *testing.T) {
	t.Run("keeps only files that exist in the repository", func(t *testing.T) {
		root := t.TempDir()
		binary := filepath.Join(root, "zen-idp")
		require.NoError(t, os.WriteFile(binary, []byte("binary"), 0o755))

		files := archiveFiles(root, binary, "linux")
		require.Equal(t, map[string]string{binary: "zen-idp"}, files)
	})
}
