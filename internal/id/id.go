package id

import (
	"context"

	"go.jetify.com/typeid/v2"
)

// IDGenerator creates prefix-less TypeID identifiers.
type IDGenerator struct{}

// NewIDGenerator returns a new identifier generator.
func NewIDGenerator() *IDGenerator {
	return &IDGenerator{}
}

// NewID returns a new prefix-less TypeID string.
//
// The context argument is accepted so that every identifier source in the
// application shares one signature; generation is local and never blocks.
func (g *IDGenerator) NewID(_ context.Context) string {
	return typeid.MustGenerate("").String()
}
