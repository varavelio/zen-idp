package yamlmerge

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"slices"

	"gopkg.in/yaml.v3"
)

var (
	// ErrNoDocuments indicates that merging was requested without YAML input.
	ErrNoDocuments = errors.New("no YAML documents provided")
	// ErrRepeatedPrimitive indicates that a scalar key was defined more than once.
	ErrRepeatedPrimitive = errors.New("primitive value defined more than once")
	// ErrIncompatibleTypes indicates that one key changed its YAML container type.
	ErrIncompatibleTypes = errors.New("incompatible YAML value types")
)

// Merge combines YAML documents in argument order. Mapping values are merged
// recursively, sequences are appended, and repeated primitive values are
// rejected.
func Merge(documents ...[]byte) ([]byte, error) {
	if len(documents) == 0 {
		return nil, fmt.Errorf("merge YAML: %w", ErrNoDocuments)
	}

	merged := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	for index, document := range documents {
		decoded, err := decodeDocument(document)
		if err != nil {
			return nil, fmt.Errorf("merge YAML document %d: %w", index, err)
		}
		if err := mergeMapping(merged, decoded, ""); err != nil {
			return nil, fmt.Errorf("merge YAML document %d: %w", index, err)
		}
	}
	sortMappings(merged)
	encoded, err := yaml.Marshal(merged)
	if err != nil {
		return nil, fmt.Errorf("encode merged YAML: %w", err)
	}
	return encoded, nil
}

func decodeDocument(contents []byte) (*yaml.Node, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(contents))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return nil, err
	}
	if len(document.Content) == 0 || document.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("root must be a mapping")
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err != nil {
			return nil, err
		}
		return nil, errors.New("multiple YAML documents are not supported")
	}
	return document.Content[0], nil
}

func mergeMapping(destination, source *yaml.Node, currentPath string) error {
	indexes := make(map[string]int, len(destination.Content)/2)
	for index := 0; index < len(destination.Content); index += 2 {
		indexes[destination.Content[index].Value] = index
	}

	for index := 0; index < len(source.Content); index += 2 {
		key := source.Content[index]
		value := source.Content[index+1]
		destinationIndex, exists := indexes[key.Value]
		if !exists {
			destination.Content = append(destination.Content, key, value)
			indexes[key.Value] = len(destination.Content) - 2
			continue
		}

		path := key.Value
		if currentPath != "" {
			path = currentPath + "." + key.Value
		}
		existing := destination.Content[destinationIndex+1]
		switch {
		case existing.Kind == yaml.MappingNode && value.Kind == yaml.MappingNode:
			if err := mergeMapping(existing, value, path); err != nil {
				return err
			}
		case existing.Kind == yaml.SequenceNode && value.Kind == yaml.SequenceNode:
			existing.Content = append(existing.Content, value.Content...)
		case existing.Kind == yaml.ScalarNode && value.Kind == yaml.ScalarNode:
			return fmt.Errorf("%w at %s", ErrRepeatedPrimitive, path)
		default:
			return fmt.Errorf("%w at %s", ErrIncompatibleTypes, path)
		}
	}
	return nil
}

func sortMappings(node *yaml.Node) {
	if node.Kind == yaml.MappingNode {
		type pair struct {
			key   *yaml.Node
			value *yaml.Node
		}
		pairs := make([]pair, 0, len(node.Content)/2)
		for index := 0; index < len(node.Content); index += 2 {
			pairs = append(pairs, pair{key: node.Content[index], value: node.Content[index+1]})
		}
		slices.SortFunc(pairs, func(left, right pair) int {
			return bytes.Compare([]byte(left.key.Value), []byte(right.key.Value))
		})
		node.Content = node.Content[:0]
		for _, pair := range pairs {
			sortMappings(pair.value)
			node.Content = append(node.Content, pair.key, pair.value)
		}
		return
	}
	for _, child := range node.Content {
		sortMappings(child)
	}
}
