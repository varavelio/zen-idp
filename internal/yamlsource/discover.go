package yamlsource

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

var (
	// ErrNoSelectors indicates that discovery was requested without any inputs.
	ErrNoSelectors = errors.New("no YAML selectors provided")
	// ErrNoFiles indicates that a selector resolved to no YAML files.
	ErrNoFiles = errors.New("no YAML files found")
)

// File contains one discovered YAML file and its path within the filesystem.
type File struct {
	// Path is the slash-separated path used to read the file from the filesystem.
	Path string
	// Content is the complete YAML file content.
	Content []byte
}

// Discover resolves each selector against filesystem and reads the resulting
// YAML files. A selector may be a file, a directory whose immediate files are
// inspected, or a doublestar glob pattern. Results are deduplicated and sorted
// by path.
func Discover(filesystem fs.FS, selectors ...string) ([]File, error) {
	if filesystem == nil {
		return nil, errors.New("discover YAML files: filesystem is nil")
	}
	if len(selectors) == 0 {
		return nil, fmt.Errorf("discover YAML files: %w", ErrNoSelectors)
	}

	paths := make(map[string]struct{})
	for _, selector := range selectors {
		if selector == "" {
			return nil, errors.New("discover YAML files: selector is empty")
		}
		matched, err := resolveSelector(filesystem, selector, paths)
		if err != nil {
			return nil, err
		}
		if !matched {
			return nil, fmt.Errorf("discover YAML files for selector %q: %w", selector, ErrNoFiles)
		}
	}

	orderedPaths := make([]string, 0, len(paths))
	for filePath := range paths {
		orderedPaths = append(orderedPaths, filePath)
	}
	slices.Sort(orderedPaths)

	files := make([]File, 0, len(orderedPaths))
	for _, filePath := range orderedPaths {
		content, err := fs.ReadFile(filesystem, filePath)
		if err != nil {
			return nil, fmt.Errorf("read YAML file %q: %w", filePath, err)
		}
		files = append(files, File{Path: filePath, Content: content})
	}

	return files, nil
}

// resolveSelector adds the YAML files represented by one selector to paths and
// reports whether the selector resolved at least one YAML file.
func resolveSelector(filesystem fs.FS, selector string, paths map[string]struct{}) (bool, error) {
	info, err := fs.Stat(filesystem, selector)
	if err == nil {
		return resolvePath(filesystem, selector, info, paths)
	}
	if !errors.Is(err, fs.ErrNotExist) || !hasGlobMeta(selector) {
		return false, fmt.Errorf("inspect YAML selector %q: %w", selector, err)
	}
	if !doublestar.ValidatePattern(selector) {
		return false, fmt.Errorf("discover YAML files: invalid glob pattern %q", selector)
	}

	matches, err := doublestar.Glob(filesystem, selector, doublestar.WithFailOnIOErrors())
	if err != nil {
		return false, fmt.Errorf("evaluate YAML glob %q: %w", selector, err)
	}

	matched := false
	for _, match := range matches {
		info, statErr := fs.Stat(filesystem, match)
		if statErr != nil {
			return false, fmt.Errorf("inspect YAML glob match %q: %w", match, statErr)
		}
		pathMatched, resolveErr := resolvePath(filesystem, match, info, paths)
		if resolveErr != nil {
			return false, resolveErr
		}
		matched = matched || pathMatched
	}

	return matched, nil
}

// resolvePath adds a YAML file or the immediate YAML files in a directory to
// paths.
func resolvePath(
	filesystem fs.FS,
	filePath string,
	info fs.FileInfo,
	paths map[string]struct{},
) (bool, error) {
	if info.IsDir() {
		return resolveDirectory(filesystem, filePath, paths)
	}
	if !info.Mode().IsRegular() || !isYAML(filePath) {
		return false, nil
	}
	paths[filePath] = struct{}{}
	return true, nil
}

// resolveDirectory adds regular YAML files directly contained in directory.
func resolveDirectory(filesystem fs.FS, directory string, paths map[string]struct{}) (bool, error) {
	entries, err := fs.ReadDir(filesystem, directory)
	if err != nil {
		return false, fmt.Errorf("read YAML directory %q: %w", directory, err)
	}

	matched := false
	for _, entry := range entries {
		if entry.IsDir() || !entry.Type().IsRegular() {
			continue
		}
		filePath := path.Join(directory, entry.Name())
		if !isYAML(filePath) {
			continue
		}
		paths[filePath] = struct{}{}
		matched = true
	}
	return matched, nil
}

// hasGlobMeta reports whether a selector contains doublestar pattern syntax.
func hasGlobMeta(selector string) bool {
	return strings.ContainsAny(selector, "*?[]{}")
}

// isYAML reports whether a path has a supported YAML extension.
func isYAML(filePath string) bool {
	extension := strings.ToLower(path.Ext(filePath))
	return extension == ".yaml" || extension == ".yml"
}
