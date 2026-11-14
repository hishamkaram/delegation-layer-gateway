package deviceclient

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

type enrollmentToken struct {
	Token     string    `json:"token"`
	DeviceID  string    `json:"device_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (enrollmentToken) String() string     { return "enrollment_token" }
func (t enrollmentToken) GoString() string { return t.String() }
func readToken(ctx context.Context, options ConnectOptions) (enrollmentToken, error) {
	var data []byte
	var err error
	if options.EnrollmentTokenFile != "" {
		data, err = privateRead(options.EnrollmentTokenFile, protocol.MaxEnrollmentBodyBytes)
	} else {
		data, err = finiteRead(ctx, options.EnrollmentTokenReader)
	}
	if err != nil {
		return enrollmentToken{}, failed(ErrConfiguration, err)
	}
	var token enrollmentToken
	if protocol.DecodeStrict(data, &token, protocol.MaxEnrollmentBodyBytes) != nil || domain.Token(token.DeviceID) != nil || token.ExpiresAt.IsZero() {
		return enrollmentToken{}, ErrConfiguration
	}
	decoded, err := base64.RawURLEncoding.DecodeString(token.Token)
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != token.Token {
		return enrollmentToken{}, ErrConfiguration
	}
	// Expiry is enforced by the authoritative Gateway, which may still replay an
	// already committed redemption receipt after the original token expires.
	return token, nil
}

func finiteRead(ctx context.Context, reader io.Reader) ([]byte, error) {
	if reader == nil {
		return nil, ErrConfiguration
	}
	if finite, ok := reader.(interface{ Len() int }); ok {
		if finite.Len() > protocol.MaxEnrollmentBodyBytes {
			return nil, ErrConfiguration
		}
		return boundedRead(reader)
	}
	file, ok := reader.(*os.File)
	if !ok {
		return nil, ErrConfiguration
	}
	info, err := file.Stat()
	if err != nil {
		return nil, ErrConfiguration
	}
	if info.Mode().IsRegular() {
		if info.Size() > protocol.MaxEnrollmentBodyBytes {
			return nil, ErrConfiguration
		}
		return boundedRead(file)
	}
	return readPipe(ctx, file)
}

func readPipe(ctx context.Context, file *os.File) ([]byte, error) {
	deadline, ok := ctx.Deadline()
	if !ok || !deadline.After(time.Now()) {
		return nil, ErrConfiguration
	}
	if maximum := time.Now().Add(30 * time.Second); deadline.After(maximum) {
		deadline = maximum
	}
	if file.SetReadDeadline(deadline) != nil {
		return nil, ErrConfiguration
	}
	// Cancellation interrupts the read, and a started callback is joined before
	// restoring the caller-owned file's deadline. No reader goroutine survives.
	cancelled := make(chan error, 1)
	stop := context.AfterFunc(ctx, func() { cancelled <- file.SetReadDeadline(time.Now()) })
	data, readErr := boundedRead(file)
	if !stop() {
		readErr = errors.Join(readErr, <-cancelled)
	}
	restoreErr := file.SetReadDeadline(time.Time{})
	if ctx.Err() != nil {
		return nil, errors.Join(ErrConfiguration, ctx.Err(), readErr, restoreErr)
	}
	return data, errors.Join(readErr, restoreErr)
}

func boundedRead(reader io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, protocol.MaxEnrollmentBodyBytes+1))
	if err != nil || len(data) > protocol.MaxEnrollmentBodyBytes {
		return nil, ErrConfiguration
	}
	return data, nil
}
