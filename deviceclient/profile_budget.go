package deviceclient

import (
	"errors"

	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

// The one 8MiB file has independent base/pin partitions. The base owns the
// eight-byte JSON field delimiter; ordinary writes preserve revocation space.
const (
	maxBaseProfileBytes    = (4 << 20) - len(`,"pins":`)
	revocationReserveBytes = protocol.MaxWorkspaces * 64
	ordinaryBaseBytes      = maxBaseProfileBytes - revocationReserveBytes
	futureIssuerBytes      = 96 << 10
)

func encodeProfile(next profile, revocation bool) ([]byte, error) {
	if next.payloadBytesExceedBudget() {
		return nil, ErrCapacity
	}
	if !next.valid() {
		return nil, ErrProfile
	}
	base := next
	base.Pins = nil
	limit := ordinaryBaseLimit(next)
	if revocation {
		limit = maxBaseProfileBytes
	}
	if _, err := profileEncoding(base, limit); err != nil {
		return nil, err
	}
	if _, err := encodedPins(next.Pins); err != nil {
		return nil, err
	}
	return profileEncoding(next, maxProfileBytes)
}

func profileEncoding(value profile, limit int) ([]byte, error) {
	data, err := protocol.Encode(value, limit)
	if errors.Is(err, protocol.ErrTooLarge) {
		return nil, ErrCapacity
	}
	if err != nil {
		return nil, failed(ErrProfile, err)
	}
	return data, nil
}

func encodedPins(records []projectRecord) ([]byte, error) {
	if records == nil {
		records = []projectRecord{}
	}
	// Each record is individually bounded. Count raw bytes before JSON allocation
	// to reject a large aggregate even when strings share backing storage.
	remaining := protocol.MaxProjectPinBytes
	for _, r := range records {
		for _, value := range []string{r.Request.RequestID, r.Request.WorkspaceID, r.Request.RelativePath, r.Directory, r.ProjectContext} {
			if !takeProfileBytes(value, &remaining) {
				return nil, ErrCapacity
			}
		}
	}
	data, err := protocol.Encode(records, protocol.MaxProjectPinBytes)
	if errors.Is(err, protocol.ErrTooLarge) {
		return nil, ErrCapacity
	}
	if err != nil {
		return nil, failed(ErrProfile, err)
	}
	return data, nil
}

// First OAuth use can add three bounded URL fields with worst-case JSON
// escaping. Headless growth cannot spend that future pinning capacity.
func ordinaryBaseLimit(p profile) int {
	if p.Issuer == (issuerEndpoints{}) {
		return ordinaryBaseBytes - futureIssuerBytes
	}
	return ordinaryBaseBytes
}
