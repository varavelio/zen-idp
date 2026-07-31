package yamlsource

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

// File contains one discovered YAML source.
type File struct {
	// Path is the normalized absolute path used to read the source.
	Path string
	// Content is the complete YAML source content.
	Content []byte
}

// Discover reads the YAML sources selected by an exact file, an immediate
// directory, or a doublestar glob. Relative selectors resolve from the current
// working directory. Results are sorted by path and deduplicated by resolved
// symlink target.
func Discover(selector string) ([]File, error) {
	if selector == "" {
		return nil, errors.New("discover YAML files: selector is empty")
	}

	absolute, err := filepath.Abs(selector)
	if err != nil {
		return nil, fmt.Errorf("resolve YAML selector %q: %w", selector, err)
	}

	paths := make(map[string]string)
	info, statErr := os.Stat(absolute)
	if statErr == nil {
		if info.IsDir() {
			if err := selectDirectory(absolute, paths); err != nil {
				return nil, err
			}
		} else if err := selectYAMLFile(absolute, info, paths); err != nil {
			return nil, err
		}
	} else {
		if !errors.Is(statErr, fs.ErrNotExist) || !hasGlobMeta(absolute) {
			return nil, fmt.Errorf("inspect YAML selector %q: %w", selector, statErr)
		}
		matches, globErr := doublestar.FilepathGlob(
			absolute,
			doublestar.WithFailOnIOErrors(),
			doublestar.WithNoFollow(),
		)
		if globErr != nil {
			return nil, fmt.Errorf("evaluate YAML glob %q: %w", selector, globErr)
		}
		for _, match := range matches {
			matchInfo, matchErr := os.Stat(match)
			if matchErr != nil {
				return nil, fmt.Errorf("inspect YAML glob match %q: %w", match, matchErr)
			}
			if matchInfo.IsDir() {
				continue
			}
			if err := selectYAMLFile(match, matchInfo, paths); err != nil {
				return nil, err
			}
		}
	}

	if len(paths) == 0 {
		return nil, fmt.Errorf("discover YAML files for selector %q: no YAML files found", selector)
	}
	return readFiles(paths)
}

// selectDirectory records regular or symlinked-regular YAML children without
// descending into nested directories.
func selectDirectory(directory string, paths map[string]string) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return fmt.Errorf("read YAML directory %q: %w", directory, err)
	}
	for _, entry := range entries {
		filePath := filepath.Join(directory, entry.Name())
		if !isYAML(filePath) {
			continue
		}
		info, statErr := os.Stat(filePath)
		if statErr != nil {
			return fmt.Errorf("inspect YAML directory entry %q: %w", filePath, statErr)
		}
		logical, resolved, regular, resolveErr := resolveRegularFile(filePath, info)
		if resolveErr != nil {
			return resolveErr
		}
		if regular {
			recordPath(paths, logical, resolved)
		}
	}
	return nil
}

// selectYAMLFile records a regular file when its resolved target has a YAML
// extension.
func selectYAMLFile(filePath string, info fs.FileInfo, paths map[string]string) error {
	logical, resolved, regular, err := resolveRegularFile(filePath, info)
	if err != nil || !regular || !isYAML(resolved) {
		return err
	}
	recordPath(paths, logical, resolved)
	return nil
}

// resolveRegularFile returns the logical path used for reading and the
// canonical path used as its source identity.
func resolveRegularFile(filePath string, info fs.FileInfo) (string, string, bool, error) {
	if !info.Mode().IsRegular() {
		return "", "", false, nil
	}
	resolved, err := filepath.EvalSymlinks(filePath)
	if err != nil {
		return "", "", false, fmt.Errorf("resolve YAML file %q: %w", filePath, err)
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return "", "", false, fmt.Errorf("normalize YAML file %q: %w", filePath, err)
	}
	logical, err := filepath.Abs(filePath)
	if err != nil {
		return "", "", false, fmt.Errorf("normalize YAML file %q: %w", filePath, err)
	}
	return logical, resolved, true, nil
}

// recordPath retains the lexicographically first logical path for each resolved
// source identity.
func recordPath(paths map[string]string, logical, resolved string) {
	if existing, exists := paths[resolved]; !exists || logical < existing {
		paths[resolved] = logical
	}
}

// readFiles reads selected sources in deterministic logical-path order.
func readFiles(paths map[string]string) ([]File, error) {
	orderedPaths := make([]string, 0, len(paths))
	for _, logical := range paths {
		orderedPaths = append(orderedPaths, logical)
	}
	slices.Sort(orderedPaths)

	files := make([]File, 0, len(orderedPaths))
	for _, filePath := range orderedPaths {
		content, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("read YAML file %q: %w", filePath, err)
		}
		files = append(files, File{Path: filePath, Content: content})
	}
	return files, nil
}

// hasGlobMeta reports whether a selector contains doublestar pattern syntax.
func hasGlobMeta(selector string) bool {
	return strings.ContainsAny(selector, "*?[]{}")
}

// isYAML reports whether a path has a supported YAML extension.
func isYAML(filePath string) bool {
	extension := strings.ToLower(filepath.Ext(filePath))
	return extension == ".yaml" || extension == ".yml"
}
