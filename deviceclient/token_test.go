package deviceclient

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/deviceidentity"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

func TestTokenReaderRequiresFiniteInputAndJoinsCancellation(t *testing.T) {
	t.Run("finite bytes", func(t *testing.T) {
		data, err := finiteRead(t.Context(), strings.NewReader("token JSON"))
		if err != nil || string(data) != "token JSON" {
			t.Fatal(err)
		}
	})
	t.Run("unbounded pipe", func(t *testing.T) {
		reader, writer := testPipe(t)
		_ = writer
		if _, err := finiteRead(t.Context(), reader); !errors.Is(err, ErrConfiguration) {
			t.Fatal("pipe accepted without deadline", err)
		}
	})
	t.Run("cancel pipe", func(t *testing.T) {
		reader, writer := testPipe(t)
		_ = writer
		ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
		defer cancel()
		done := make(chan error, 1)
		go func() { _, err := finiteRead(ctx, reader); done <- err }()
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation not surfaced", err)
			}
		case <-time.After(2 * time.Second):
			if err := reader.Close(); err != nil {
				t.Error(err)
			}
			<-done
			t.Fatal("bounded stdin read did not join after cancellation")
		}
	})
}

func testPipe(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := errors.Join(closePipeFile(reader), closePipeFile(writer)); err != nil {
			t.Error(err)
		}
	})
	return reader, writer
}

func TestChallengeAndOptionsFormattingRedactsSecrets(t *testing.T) {
	challenge := Challenge{UserCode: "private-code", VerificationURIComplete: "https://issuer.example/private-code"}
	if strings.Contains(challenge.String(), "private-code") || strings.Contains(challenge.GoString(), "private-code") {
		t.Fatal("challenge formatted secret")
	}
	options := ConnectOptions{EnrollmentTokenFile: "/private/token", PresentChallenge: func(context.Context, Challenge) error { return nil }}
	if strings.Contains(options.String(), "private") || strings.Contains(options.GoString(), "private") {
		t.Fatal("connect options formatted secret input")
	}
}

func TestChallengePresentationFailureRetainsCauseWithoutSecretText(t *testing.T) {
	f := newGatewayFixture(t)
	cause := errors.New("private-code")
	f.options.PresentChallenge = func(context.Context, Challenge) error { return cause }
	_, err := Connect(t.Context(), f.options)
	if !errors.Is(err, ErrDenied) || !errors.Is(err, cause) || strings.Contains(err.Error(), cause.Error()) {
		t.Fatal("challenge failure lost its cause or exposed secret text", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.requests) != 0 || f.issues != 0 {
		t.Fatal("presentation failure admitted enrollment")
	}
}

func closePipeFile(file *os.File) error {
	err := file.Close()
	if errors.Is(err, os.ErrClosed) {
		return nil
	}
	return err
}

func TestConsumedTokenCannotFreezeUnusableCredentialReplacement(t *testing.T) {
	token := enrollmentToken{Token: "original-token", DeviceID: "device-one"}
	previous := deviceidentity.EnrollmentIntent{Completed: true, Plan: deviceidentity.EnrollmentPlan{TokenDevice: "device-one", TokenSHA256: domain.Hash([]byte(token.Token))}}
	if _, err := credentialDisposition(deviceidentity.ErrInvalid, previous, true, token); !errors.Is(err, ErrReplacementRequired) {
		t.Fatal("consumed token froze replacement", err)
	}
	fresh := enrollmentToken{Token: "fresh-token"}
	reuse, err := credentialDisposition(deviceidentity.ErrInvalid, previous, true, fresh)
	if err != nil || reuse {
		t.Fatal("fresh explicit token replacement was rejected", err)
	}
}
