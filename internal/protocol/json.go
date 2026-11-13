// Package protocol defines the versioned, bounded device wire contract. It
// carries requests and observations; it never owns execution state.
package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

var (
	ErrInvalid  = errors.New("invalid protocol message")
	ErrTooLarge = errors.New("protocol message exceeds encoded byte limit")
)

// DecodeStrict rejects unknown fields, duplicate keys, noncanonical field names,
// invalid UTF-8, excessive nesting and concatenated JSON values. No input or
// decoder diagnostic is returned: messages may contain credentials or briefs.
func DecodeStrict[T any](data []byte, target *T, limit int) error {
	if len(data) == 0 || len(data) > limit || !utf8.Valid(data) || !validUnicodeEscapes(data) {
		return ErrInvalid
	}
	check := json.NewDecoder(bytes.NewReader(data))
	check.UseNumber()
	if err := checkValue(check, 0); err != nil {
		return ErrInvalid
	}
	if _, err := check.Token(); !errors.Is(err, io.EOF) {
		return ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return ErrInvalid
	}
	return nil
}

// encoding/json replaces lone surrogate escapes with U+FFFD. Reject them before
// decoding so an admitted brief can never differ silently from its wire bytes.
func validUnicodeEscapes(data []byte) bool {
	quoted := false
	for index := 0; index < len(data); index++ {
		switch data[index] {
		case '"':
			quoted = !quoted
		case '\\':
			if !quoted {
				continue
			}
			index++
			if index >= len(data) {
				return false
			}
			if data[index] != 'u' {
				continue
			}
			next, ok := unicodeEscapeEnd(data, index)
			if !ok {
				return false
			}
			index = next
		}
	}
	return true
}

func unicodeEscapeEnd(data []byte, index int) (int, bool) {
	if index+4 >= len(data) {
		return index, false
	}
	value, err := strconv.ParseUint(string(data[index+1:index+5]), 16, 16)
	if err != nil {
		return index, false
	}
	index += 4
	if value >= 0xdc00 && value <= 0xdfff {
		return index, false
	}
	if value < 0xd800 || value > 0xdbff {
		return index, true
	}
	if index+6 >= len(data) || data[index+1] != '\\' || data[index+2] != 'u' {
		return index, false
	}
	low, err := strconv.ParseUint(string(data[index+3:index+7]), 16, 16)
	return index + 6, err == nil && low >= 0xdc00 && low <= 0xdfff
}

func checkValue(decoder *json.Decoder, depth int) error {
	if depth > 24 {
		return ErrInvalid
	}
	token, err := decoder.Token()
	if err != nil {
		return ErrInvalid
	}
	delim, compound := token.(json.Delim)
	if !compound {
		return nil
	}
	switch delim {
	case '{':
		if objectErr := checkObject(decoder, depth); objectErr != nil {
			return objectErr
		}
	case '[':
		for decoder.More() {
			if valueErr := checkValue(decoder, depth+1); valueErr != nil {
				return valueErr
			}
		}
	default:
		return ErrInvalid
	}
	end, err := decoder.Token()
	if err != nil || (delim == '{' && end != json.Delim('}')) || (delim == '[' && end != json.Delim(']')) {
		return ErrInvalid
	}
	return nil
}

func checkObject(decoder *json.Decoder, depth int) error {
	keys := make(map[string]struct{})
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return ErrInvalid
		}
		key, ok := token.(string)
		if !ok || !fieldName(key) {
			return ErrInvalid
		}
		if _, exists := keys[key]; exists {
			return ErrInvalid
		}
		keys[key] = struct{}{}
		if err := checkValue(decoder, depth+1); err != nil {
			return err
		}
	}
	return nil
}

func fieldName(key string) bool {
	if key == "" || len(key) > 128 {
		return false
	}
	for _, c := range key {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}

// Encode omits HTML escaping so the frame bound reflects the actual wire bytes.
// Callers must still validate brief UTF-8 and the fully generation-bound frame.
func Encode[T any](value T, limit int) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, ErrInvalid
	}
	encoded := bytes.TrimSuffix(buffer.Bytes(), []byte("\n"))
	if len(encoded) > limit {
		return nil, ErrTooLarge
	}
	return encoded, nil
}

func identifier(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, c := range value {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-", c) {
			return false
		}
	}
	return true
}
