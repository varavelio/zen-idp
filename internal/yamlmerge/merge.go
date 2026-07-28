package yamlmerge

import (
	"errors"
	"fmt"

	"github.com/TwiN/deepmerge"
)

// ErrNoDocuments indicates that merging was requested without YAML input.
var ErrNoDocuments = errors.New("no YAML documents provided")

// Merge combines YAML documents in argument order. Mapping values are merged
// recursively, sequences are appended, and repeated primitive values are
// rejected.
func Merge(documents ...[]byte) ([]byte, error) {
	if len(documents) == 0 {
		return nil, fmt.Errorf("merge YAML: %w", ErrNoDocuments)
	}

	merged := []byte("{}\n")
	for index, document := range documents {
		var err error
		merged, err = deepmerge.YAML(merged, document)
		if err != nil {
			return nil, fmt.Errorf("merge YAML document %d: %w", index, err)
		}
	}

	return merged, nil
}
