package protocol

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"unicode"
	"unicode/utf8"
)

type ContextBinding struct {
	Root    string `json:"root"`
	Project string `json:"project"`
}

type Origin struct {
	GatewayID           string `json:"gateway_id"`
	AdmissionGeneration string `json:"admission_generation"`
	OperationID         string `json:"operation_id"`
	PrincipalRef        string `json:"principal_ref"`
	RequestSHA256       string `json:"gateway_request_sha256"`
}

type TaskBinding struct {
	TaskID     string         `json:"task_id"`
	Context    ContextBinding `json:"context"`
	Origin     Origin         `json:"origin"`
	SpecSHA256 string         `json:"spec_sha256,omitempty"`
}

func (b TaskBinding) Validate(requireSpec bool) error {
	if !lowerHex(b.TaskID, 32) || !guardToken(b.Context.Root) || !guardToken(b.Context.Project) {
		return ErrInvalid
	}
	for _, id := range []string{b.Origin.GatewayID, b.Origin.AdmissionGeneration, b.Origin.OperationID, b.Origin.PrincipalRef} {
		if !identifier(id) {
			return ErrInvalid
		}
	}
	if !lowerHex(b.Origin.RequestSHA256, 64) || ((requireSpec || b.SpecSHA256 != "") && !lowerHex(b.SpecSHA256, 64)) {
		return ErrInvalid
	}
	return nil
}

type Selection struct {
	Kind  string `json:"kind"`
	Value string `json:"value,omitempty"`
}

func (s Selection) Validate() error {
	if s.Kind == "native_default" && s.Value == "" {
		return nil
	}
	if s.Kind == "explicit" && selectionToken(s.Value) {
		return nil
	}
	return ErrInvalid
}

func selectionToken(value string) bool {
	if value == "" || len(value) > 256 || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

type Admission struct {
	Task          TaskBinding `json:"task"`
	Provider      string      `json:"provider"`
	Model         Selection   `json:"model"`
	Effort        Selection   `json:"effort"`
	Permission    string      `json:"permission"`
	BudgetSeconds uint32      `json:"budget_seconds"`
	Brief         string      `json:"brief"`
}

func (a Admission) Validate() error {
	if a.Task.Validate(false) != nil || a.Task.SpecSHA256 != "" || !identifier(a.Provider) || a.Model.Validate() != nil || a.Effort.Validate() != nil {
		return ErrInvalid
	}
	if a.Permission != "read-only" && a.Permission != "workspace-write" && a.Permission != "danger-full-access" {
		return ErrInvalid
	}
	if a.BudgetSeconds == 0 || len(a.Brief) == 0 || len(a.Brief) > 256<<10 || !utf8.ValidString(a.Brief) {
		return ErrInvalid
	}
	return nil
}

type (
	TaskControl struct {
		Task TaskBinding `json:"task"`
	}
	Cancellation struct {
		Task           TaskBinding `json:"task"`
		CancellationID string      `json:"cancellation_id"`
	}
)

type Descriptor struct {
	SHA256 string `json:"sha256"`
	Length int64  `json:"length"`
}

func (d Descriptor) Validate() error {
	if !lowerHex(d.SHA256, 64) || d.Length < 0 {
		return ErrInvalid
	}
	return nil
}

type RangeRequest struct {
	Task       TaskBinding `json:"task"`
	Descriptor Descriptor  `json:"descriptor"`
	Offset     int64       `json:"offset"`
	Limit      int         `json:"limit"`
}

func (r RangeRequest) Validate() error {
	if r.Task.Validate(true) != nil || r.Descriptor.Validate() != nil || r.Offset < 0 || r.Offset > r.Descriptor.Length || r.Limit < 1 || r.Limit > 65536 {
		return ErrInvalid
	}
	return nil
}

type ResultRange struct {
	Descriptor Descriptor `json:"descriptor"`
	Offset     int64      `json:"offset"`
	DataBase64 string     `json:"data_base64"`
	NextOffset int64      `json:"next_offset"`
	EOF        bool       `json:"eof"`
}

// ValidateFor checks a verified range's descriptor, exact cursor arithmetic and
// decoded bound before bytes can leave the currently authorized response path.
func (r ResultRange) ValidateFor(request RangeRequest) error {
	if request.Validate() != nil || r.Descriptor != request.Descriptor || r.Offset != request.Offset || len(r.DataBase64) > base64.StdEncoding.EncodedLen(request.Limit) {
		return ErrInvalid
	}
	data, err := base64.StdEncoding.Strict().DecodeString(r.DataBase64)
	if err != nil || len(data) > request.Limit || int64(len(data)) > r.Descriptor.Length-r.Offset {
		return ErrInvalid
	}
	if r.NextOffset != r.Offset+int64(len(data)) || r.EOF != (r.NextOffset == r.Descriptor.Length) || (!r.EOF && len(data) == 0) {
		return ErrInvalid
	}
	return nil
}

func guardToken(value string) bool {
	return strings.HasPrefix(value, "ctx1_") && lowerHex(strings.TrimPrefix(value, "ctx1_"), 64)
}

// WireContextGuard binds the connector's locally retained CLI token without
// forwarding its encoded local filesystem path to Gateway or an MCP client.
func WireContextGuard(localToken string) string {
	digest := sha256.Sum256([]byte(localToken))
	return "ctx1_" + hex.EncodeToString(digest[:])
}

func lowerHex(value string, length int) bool {
	if len(value) != length || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
