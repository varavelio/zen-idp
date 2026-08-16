// Command release builds the Zen IdP release artifacts.
//
// It cross-compiles the Zen IdP executable for every supported platform,
// packages each binary with the project readme and license into a single
// archive, and writes those archives, a JSON manifest describing them, and
// their SHA-256 checksums into the dist directory. The release workflow
// uploads the resulting files to the GitHub release that triggered it.
package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

const (
	checksumFileName = "checksums.txt"
	commandPackage   = "./cmd/zen-idp"
	distDirName      = "dist"
	manifestFileName = "manifest.json"
	projectName      = "zen-idp"
	projectRepo      = "varavelio/zen-idp"
)

// releaseTargets lists every platform a release ships binaries for.
var releaseTargets = []target{
	{OS: "linux", Arch: "amd64"},
	{OS: "linux", Arch: "arm64"},
	{OS: "darwin", Arch: "amd64"},
	{OS: "darwin", Arch: "arm64"},
	{OS: "windows", Arch: "amd64"},
	{OS: "windows", Arch: "arm64"},
}

// target is one GOOS/GOARCH pair to cross-compile.
type target struct {
	Arch string
	OS   string
}

// releaseArtifact describes one release archive in the manifest.
type releaseArtifact struct {
	Arch   string `json:"arch"`
	Format string `json:"format"`
	Name   string `json:"name"`
	OS     string `json:"os"`
	SHA256 string `json:"sha256"`
}

// releaseManifest is the machine-readable inventory of a release.
type releaseManifest struct {
	Artifacts []releaseArtifact `json:"artifacts"`
	Project   string            `json:"project"`
	Repo      string            `json:"repo"`
	Version   string            `json:"version"`
}

// main runs the release builder and owns process exit behavior.
func main() {
	if err := run(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "release build failed: %s\n", err)
		os.Exit(1)
	}
}

// run builds every release archive and writes the manifest and checksums.
func run(ctx context.Context) error {
	root, err := findProjectRoot()
	if err != nil {
		return err
	}
	version := detectVersion(ctx, root)
	distDir := filepath.Join(root, distDirName)

	fmt.Printf("Project root: %s\n", root)
	fmt.Printf("Release version: %s\n", version)

	if err := os.RemoveAll(distDir); err != nil {
		return fmt.Errorf("clean dist directory: %w", err)
	}
	if err := os.MkdirAll(distDir, 0o755); err != nil {
		return fmt.Errorf("create dist directory: %w", err)
	}

	artifacts := make([]releaseArtifact, 0, len(releaseTargets))
	for _, buildTarget := range releaseTargets {
		artifact, err := buildArchive(ctx, root, distDir, buildTarget)
		if err != nil {
			return err
		}
		artifacts = append(artifacts, artifact)
	}
	if err := writeManifest(distDir, version, artifacts); err != nil {
		return err
	}
	if err := writeChecksums(distDir); err != nil {
		return err
	}

	fmt.Printf("Release artifacts written to %s\n", distDir)
	return nil
}

// findProjectRoot returns the repository root by walking up from the cwd.
func findProjectRoot() (string, error) {
	directory, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("get working directory: %w", err)
	}

	for {
		_, hasGoMod := os.Stat(filepath.Join(directory, "go.mod"))
		_, hasTaskfile := os.Stat(filepath.Join(directory, "Taskfile.yml"))
		if hasGoMod == nil && hasTaskfile == nil {
			return directory, nil
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			return "", fmt.Errorf("project root not found")
		}
		directory = parent
	}
}

// detectVersion determines the release version from the environment or git.
//
// The release workflow sets ZEN_IDP_VERSION explicitly; the fallbacks keep
// local runs working without any configuration.
func detectVersion(ctx context.Context, root string) string {
	return normalizeVersion(firstNonEmpty(
		os.Getenv("ZEN_IDP_VERSION"),
		tagLike(os.Getenv("GITHUB_REF_NAME")),
		gitOutput(ctx, root, "describe", "--tags", "--abbrev=0"),
		"0.0.0-dev",
	))
}

// buildArchive cross-compiles one target and archives its binary.
func buildArchive(
	ctx context.Context,
	root, distDir string,
	buildTarget target,
) (releaseArtifact, error) {
	fmt.Printf("Building %s/%s...\n", buildTarget.OS, buildTarget.Arch)
	tempDir, err := os.MkdirTemp(distDir, ".build-*")
	if err != nil {
		return releaseArtifact{}, fmt.Errorf("create temporary build directory: %w", err)
	}
	defer func() {
		_ = os.RemoveAll(tempDir)
	}()

	rawBinary := filepath.Join(tempDir, binaryName(buildTarget.OS))
	command := exec.CommandContext(
		ctx,
		"go",
		"build",
		"-trimpath",
		"-ldflags",
		"-s -w",
		"-o",
		rawBinary,
		commandPackage,
	)
	command.Dir = root
	command.Env = append(os.Environ(),
		"CGO_ENABLED=0",
		"GOOS="+buildTarget.OS,
		"GOARCH="+buildTarget.Arch,
	)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		return releaseArtifact{}, fmt.Errorf(
			"build %s/%s: %w",
			buildTarget.OS,
			buildTarget.Arch,
			err,
		)
	}

	format := archiveFormat(buildTarget.OS)
	archivePath := filepath.Join(distDir, archiveName(buildTarget))
	files := archiveFiles(root, rawBinary, buildTarget.OS)
	if format == "zip" {
		err = createZip(archivePath, files)
	} else {
		err = createTarGz(archivePath, files)
	}
	if err != nil {
		return releaseArtifact{}, fmt.Errorf(
			"archive %s/%s: %w",
			buildTarget.OS,
			buildTarget.Arch,
			err,
		)
	}

	checksum, err := fileSHA256(archivePath)
	if err != nil {
		return releaseArtifact{}, err
	}

	return releaseArtifact{
		Arch:   buildTarget.Arch,
		Format: format,
		Name:   filepath.Base(archivePath),
		OS:     buildTarget.OS,
		SHA256: checksum,
	}, nil
}

// archiveFiles returns source files mapped to archive-relative names.
func archiveFiles(root, rawBinary, goos string) map[string]string {
	files := map[string]string{rawBinary: binaryName(goos)}
	for _, name := range []string{"README.md", "LICENSE"} {
		path := filepath.Join(root, name)
		if _, err := os.Stat(path); err == nil {
			files[path] = name
		}
	}

	return files
}

// writeManifest writes the release inventory to dist/manifest.json.
func writeManifest(distDir, version string, artifacts []releaseArtifact) error {
	manifest := releaseManifest{
		Artifacts: artifacts,
		Project:   projectName,
		Repo:      projectRepo,
		Version:   version,
	}
	content, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal release manifest: %w", err)
	}
	content = append(content, '\n')
	if err := os.WriteFile(filepath.Join(distDir, manifestFileName), content, 0o644); err != nil {
		return fmt.Errorf("write release manifest: %w", err)
	}

	return nil
}

// writeChecksums writes SHA-256 checksums for every file in dist/ except
// checksums.txt itself.
func writeChecksums(distDir string) error {
	entries, err := os.ReadDir(distDir)
	if err != nil {
		return fmt.Errorf("read dist directory: %w", err)
	}

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || entry.Name() == checksumFileName {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)

	checksumPath := filepath.Join(distDir, checksumFileName)
	checksumFile, err := os.Create(checksumPath)
	if err != nil {
		return fmt.Errorf("create checksums file: %w", err)
	}
	defer func() {
		_ = checksumFile.Close()
	}()

	for _, name := range names {
		hash, err := fileSHA256(filepath.Join(distDir, name))
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(checksumFile, "%s  %s\n", hash, name); err != nil {
			return fmt.Errorf("write checksum for %s: %w", name, err)
		}
	}

	return nil
}

// createZip writes a zip archive from source paths to archive names.
func createZip(target string, files map[string]string) error {
	archiveFile, err := os.Create(target)
	if err != nil {
		return fmt.Errorf("create zip archive: %w", err)
	}
	defer func() {
		_ = archiveFile.Close()
	}()

	archive := zip.NewWriter(archiveFile)
	defer func() {
		_ = archive.Close()
	}()

	for _, source := range sortedKeys(files) {
		if err := addFileToZip(archive, source, files[source]); err != nil {
			return err
		}
	}

	return nil
}

// addFileToZip adds one file to a zip archive.
func addFileToZip(archive *zip.Writer, source, name string) error {
	info, err := os.Stat(source)
	if err != nil {
		return fmt.Errorf("stat zip source %s: %w", source, err)
	}
	header, err := zip.FileInfoHeader(info)
	if err != nil {
		return fmt.Errorf("create zip header %s: %w", name, err)
	}
	header.Name = name
	header.Method = zip.Deflate

	writer, err := archive.CreateHeader(header)
	if err != nil {
		return fmt.Errorf("create zip entry %s: %w", name, err)
	}

	return copyFileContent(writer, source)
}

// createTarGz writes a tar.gz archive from source paths to archive names.
func createTarGz(target string, files map[string]string) error {
	archiveFile, err := os.Create(target)
	if err != nil {
		return fmt.Errorf("create tar.gz archive: %w", err)
	}
	defer func() {
		_ = archiveFile.Close()
	}()

	gzipWriter := gzip.NewWriter(archiveFile)
	defer func() {
		_ = gzipWriter.Close()
	}()

	tarWriter := tar.NewWriter(gzipWriter)
	defer func() {
		_ = tarWriter.Close()
	}()

	for _, source := range sortedKeys(files) {
		if err := addFileToTar(tarWriter, source, files[source]); err != nil {
			return err
		}
	}

	return nil
}

// addFileToTar adds one file to a tar archive.
func addFileToTar(archive *tar.Writer, source, name string) error {
	info, err := os.Stat(source)
	if err != nil {
		return fmt.Errorf("stat tar source %s: %w", source, err)
	}
	header, err := tar.FileInfoHeader(info, info.Name())
	if err != nil {
		return fmt.Errorf("create tar header %s: %w", name, err)
	}
	header.Name = name
	if err := archive.WriteHeader(header); err != nil {
		return fmt.Errorf("write tar header %s: %w", name, err)
	}

	return copyFileContent(archive, source)
}

// copyFileContent writes source file bytes into writer.
func copyFileContent(writer io.Writer, source string) error {
	file, err := os.Open(source)
	if err != nil {
		return fmt.Errorf("open %s: %w", source, err)
	}
	defer func() {
		_ = file.Close()
	}()

	if _, err := io.Copy(writer, file); err != nil {
		return fmt.Errorf("copy %s: %w", source, err)
	}

	return nil
}

// fileSHA256 returns the SHA-256 hex digest for path.
func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open %s for hashing: %w", path, err)
	}
	defer func() {
		_ = file.Close()
	}()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("hash %s: %w", path, err)
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// sortedKeys returns the sorted keys of values.
func sortedKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	return keys
}

// archiveName returns the release archive filename for target.
func archiveName(buildTarget target) string {
	return fmt.Sprintf(
		"%s_%s_%s.%s",
		projectName,
		buildTarget.OS,
		buildTarget.Arch,
		archiveFormat(buildTarget.OS),
	)
}

// archiveFormat returns the archive format used for an OS.
func archiveFormat(goos string) string {
	if goos == "windows" {
		return "zip"
	}

	return "tar.gz"
}

// binaryName returns the binary filename used inside archives.
func binaryName(goos string) string {
	if goos == "windows" {
		return projectName + ".exe"
	}

	return projectName
}

// normalizeVersion returns version without a leading v prefix.
func normalizeVersion(version string) string {
	version = strings.TrimSpace(strings.ToLower(version))
	version = strings.TrimPrefix(version, "refs/tags/")

	return strings.TrimPrefix(version, "v")
}

// tagLike returns value only when it looks like a release tag.
func tagLike(value string) string {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "v") {
		return value
	}

	return ""
}

// firstNonEmpty returns the first non-empty trimmed value.
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}

	return ""
}

// gitOutput returns trimmed stdout from a git command or an empty string.
func gitOutput(ctx context.Context, root string, args ...string) string {
	command := exec.CommandContext(ctx, "git", args...)
	command.Dir = root
	output, err := command.Output()
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(output))
}
