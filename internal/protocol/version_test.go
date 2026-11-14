package protocol

import (
	"bytes"
	"testing"
)

func TestFrameVersionMustMatchNegotiationAndLegacyBytesStayStable(t *testing.T) {
	legacy := validFrame()
	encoded, err := EncodeFrame(legacy)
	if err != nil {
		t.Fatal(err)
	}
	explicit, err := EncodeFrameVersion(legacy, 1)
	if err != nil || !bytes.Equal(encoded, explicit) {
		t.Fatal("explicit negotiation changed v1 encoding")
	}
	if _, err = DecodeFrameVersion(encoded, 2); err == nil {
		t.Fatal("v1 frame accepted on v2 session")
	}
	modern := legacy
	modern.Version = 2
	encoded, err = EncodeFrameVersion(modern, 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = DecodeFrame(encoded); err == nil {
		t.Fatal("legacy entry point accepted v2")
	}
	decoded, err := DecodeFrameVersion(encoded, 2)
	if err != nil || decoded.Version != 2 || decoded.RequestID != modern.RequestID {
		t.Fatal("v2 identity lost")
	}
	for _, unsupported := range []int{0, 3, -1} {
		if _, err = EncodeFrameVersion(modern, unsupported); err == nil {
			t.Fatal("unsupported negotiated version accepted")
		}
	}
}
