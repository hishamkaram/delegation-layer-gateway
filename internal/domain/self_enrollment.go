package domain

import (
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// SelfEnrollmentAttempt is populated by the authenticated enrollment service.
// CSR/public-key hashes are derived from its validated CSR, never JSON claims.
type SelfEnrollmentAttempt struct {
	Request            RequestID
	Name               string
	ReplaceDevice      DeviceID
	ExpectedGeneration uint64
	CSRHash            Digest
	PublicKeyHash      Digest
	Issuance           IssuanceID
	Serial             []byte
	Now                time.Time
}

func ValidateDeviceName(name string) error {
	if len(name) > 256 || strings.TrimSpace(name) == "" || !utf8.ValidString(name) {
		return ErrInvalid
	}
	for _, character := range name {
		if unicode.IsControl(character) {
			return ErrInvalid
		}
	}
	return nil
}
