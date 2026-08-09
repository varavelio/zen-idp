package configloader

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/varavelio/zen-idp/internal/config"
	"github.com/varavelio/zen-idp/internal/yamlmerge"
	"github.com/varavelio/zen-idp/internal/yamlsource"
	"gopkg.in/yaml.v3"
)

// Load discovers, composes, parses, and validates the configuration selected by
// one absolute or working-directory-relative filesystem selector.
func Load(selector string) (*config.Config, error) {
	files, err := yamlsource.Discover(selector)
	if err != nil {
		return nil, fmt.Errorf("load configuration: %w", err)
	}
	return loadFiles(files)
}

// loadFiles validates and composes sources in discovery order before parsing
// the resulting configuration.
func loadFiles(files []yamlsource.File) (*config.Config, error) {
	merged := []byte("{}\n")
	for _, file := range files {
		if err := validateSource(file); err != nil {
			return nil, err
		}
		var err error
		merged, err = yamlmerge.Merge(merged, file.Content)
		if err != nil {
			return nil, fmt.Errorf("merge configuration file %q: %w", file.Path, err)
		}
	}

	configuration, err := config.Parse(merged)
	if err != nil {
		return nil, fmt.Errorf("parse composed configuration: %w", err)
	}
	return configuration, nil
}

// validateSource verifies that a single configuration file is structurally
// valid before it participates in the composition pipeline.
//
// It is called by loadFiles for every discovered file, prior to yamlmerge.Merge.
// This guarantees that each source has a shape compatible with merging and
// parsing, and that any problem is reported against the file that causes it.
//
// A file is considered valid when it satisfies all of the following
// conditions:
//
//   - It decodes as well-formed YAML. Malformed files are rejected with a
//     decode error.
//   - Its root node is a mapping (a YAML object), so that documents can be
//     merged key by key. Documents with a sequence or scalar root, as well as
//     empty documents, are rejected.
//   - It contains exactly one YAML document. Files with multiple documents
//     (separated by "---") are rejected because their composition would be
//     ambiguous.
//
// On failure it returns an error describing the offending file and the
// validation rule that was violated.
func validateSource(file yamlsource.File) error {
	decoder := yaml.NewDecoder(bytes.NewReader(file.Content))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return fmt.Errorf("decode configuration file %q: %w", file.Path, err)
	}
	if len(document.Content) == 0 || document.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("decode configuration file %q: root must be a mapping", file.Path)
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err != nil {
			return fmt.Errorf("decode configuration file %q: %w", file.Path, err)
		}
		return fmt.Errorf(
			"decode configuration file %q: multiple YAML documents are not supported",
			file.Path,
		)
	}
	return nil
}
