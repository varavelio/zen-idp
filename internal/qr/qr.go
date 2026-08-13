package qr

import (
	"encoding/base64"
	"errors"
	"fmt"

	qrcode "github.com/skip2/go-qrcode"
)

// recoveryLevel is the error-correction level of every generated code.
// High recovery is used because enrollment codes are scanned from screens
// and prints where glare or damage is common, and the small payload keeps
// the resulting matrix compact.
const recoveryLevel = qrcode.High

// size is the edge length in pixels of every generated QR code image.
const size = 256

// dataURIPrefix introduces the base64-encoded PNG payload of a data URI.
const dataURIPrefix = "data:image/png;base64,"

// Encode returns the QR code of content as a PNG data URI, ready to embed
// in an HTML img src attribute. The image is a 256-pixel square with high
// error-correction recovery. content must not be empty.
func Encode(content string) (string, error) {
	if content == "" {
		return "", errors.New("qr content must not be empty")
	}
	png, err := qrcode.Encode(content, recoveryLevel, size)
	if err != nil {
		return "", fmt.Errorf("encode qr code: %w", err)
	}
	return dataURIPrefix + base64.StdEncoding.EncodeToString(png), nil
}
