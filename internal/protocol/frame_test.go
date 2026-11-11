package protocol

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func validFrame() Frame {
	return Frame{Version: 1, Type: Request, RequestID: "request-1", Generation: Generation{BootEpoch: "boot-1", Counter: 1}, TTLMillis: 30000, Payload: json.RawMessage(`{"operation":"resolve","project":"work","body":{}}`)}
}

func TestStrictEnvelopeRejectsAmbiguity(t *testing.T) {
	good := `{"version":1,"type":"request","request_id":"r","connection_generation":{"boot_epoch":"b","counter":1},"ttl_ms":30000,"payload":{}}`
	if _, err := DecodeFrame([]byte(good)); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"duplicate":        strings.Replace(good, `"version":1`, `"version":1,"version":1`, 1),
		"case alias":       strings.Replace(good, `"version":1`, `"Version":1`, 1),
		"nested duplicate": strings.Replace(good, `"counter":1`, `"counter":1,"counter":2`, 1),
		"unknown":          strings.Replace(good, `"version":1`, `"version":1,"secret":"canary"`, 1),
		"concatenated":     good + `{}`,
		"unsupported":      strings.Replace(good, `"version":1`, `"version":2`, 1),
		"null payload":     strings.Replace(good, `"payload":{}`, `"payload":null`, 1),
		"missing ttl":      strings.Replace(good, `"ttl_ms":30000,`, "", 1),
		"long ttl":         strings.Replace(good, `30000`, `30001`, 1),
		"zero generation":  strings.Replace(good, `"counter":1`, `"counter":0`, 1),
		"invalid utf8":     good[:len(good)-1] + string([]byte{0xff}) + "}",
		"depth":            strings.Replace(good, `"payload":{}`, `"payload":`+strings.Repeat("[", 26)+"0"+strings.Repeat("]", 26), 1),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeFrame([]byte(input)); !errors.Is(err, ErrInvalid) {
				t.Fatalf("want redacted invalid-message error, got %v", err)
			}
		})
	}
}

func TestEncodedLimitUsesWireBytes(t *testing.T) {
	frame := validFrame()
	// Every NUL consumes six JSON bytes. A brief byte bound alone cannot
	// establish that the complete frame fits its independent encoded bound.
	body, err := Encode(struct {
		Brief string `json:"brief"`
	}{Brief: strings.Repeat("\x00", 256<<10)}, 2<<20)
	if err != nil {
		t.Fatal(err)
	}
	frame.Payload = body
	if _, err = EncodeFrame(frame); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversize frame accepted: %v", err)
	}
	frame.Payload = json.RawMessage(`{"brief":"<>&世界"}`)
	data, err := EncodeFrame(frame)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `\u003c`) || !strings.Contains(string(data), "<>&世界") {
		t.Fatal("wire HTML escaping must be disabled")
	}
	decoded, err := DecodeFrame(data)
	if err != nil || decoded.RequestID != frame.RequestID {
		t.Fatalf("frame identity not preserved: %v", err)
	}
}

func TestCommandAuthorizationClasses(t *testing.T) {
	frame := validFrame()
	command, err := DecodeCommand(frame)
	if err != nil || command.Operation != Resolve || command.Project != "work" {
		t.Fatalf("resolve command: %+v %v", command, err)
	}
	for _, operation := range []Operation{Admit, ResumeExisting, OriginReopen} {
		if operation.AllowedRecoveryOnly() {
			t.Fatalf("recovery credential allowed %s", operation)
		}
	}
	for _, operation := range []Operation{OriginBarrier, OriginInventory, OriginReopen} {
		if !operation.Administrative() {
			t.Fatalf("public admin operation %s", operation)
		}
	}
	frame.Payload = json.RawMessage(`{"operation":"exec","project":"work","body":{}}`)
	if _, err = DecodeCommand(frame); !errors.Is(err, ErrInvalid) {
		t.Fatal("arbitrary execution operation accepted")
	}
	frame.Payload = json.RawMessage(`{"operation":"resolve","project":"../../etc","body":{}}`)
	if _, err = DecodeCommand(frame); !errors.Is(err, ErrInvalid) {
		t.Fatal("path project alias accepted")
	}
}

func TestDeadlineStartsAtReceipt(t *testing.T) {
	received := time.Date(2026, time.November, 10, 12, 0, 0, 0, time.UTC)
	if got := validFrame().Deadline(received); !got.Equal(received.Add(30 * time.Second)) {
		t.Fatalf("wrong receipt deadline: %v", got)
	}
}

func TestStrictUnicodeDoesNotReplaceBriefBytes(t *testing.T) {
	type brief struct {
		Text string `json:"text"`
	}
	for _, input := range []string{`{"text":"\ud800"}`, `{"text":"\udc00"}`, `{"text":"\ud800a"}`, `{"text":"\ud800\u0041"}`} {
		var result brief
		if err := DecodeStrict([]byte(input), &result, 100); !errors.Is(err, ErrInvalid) {
			t.Fatalf("unpaired surrogate accepted: %v", err)
		}
	}
	var result brief
	if err := DecodeStrict([]byte(`{"text":"\ud83d\ude00 � \\ud800"}`), &result, 100); err != nil {
		t.Fatal(err)
	}
	if result.Text != "😀 � \\ud800" {
		t.Fatalf("valid Unicode changed: %q", result.Text)
	}
}
