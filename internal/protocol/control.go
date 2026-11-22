package protocol

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
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
	Binding             string `json:"binding,omitempty"`
}

type TaskBinding struct {
	Route      TaskRoute      `json:"route,omitzero"`
	TaskID     string         `json:"task_id"`
	Context    ContextBinding `json:"context"`
	Origin     Origin         `json:"origin"`
	SpecSHA256 string         `json:"spec_sha256,omitempty"`
}

func (b TaskBinding) Validate(requireSpec bool) error {
	if b.Route != (TaskRoute{}) && b.Route.Validate() != nil {
		return ErrInvalid
	}
	if !lowerHex(b.TaskID, 32) || !guardToken(b.Context.Root) || !guardToken(b.Context.Project) {
		return ErrInvalid
	}
	if b.Origin.Validate() != nil || ((requireSpec || b.SpecSHA256 != "") && !lowerHex(b.SpecSHA256, 64)) {
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

// selectionToken carries one literal fixed-argv value. Native owns support and
// semantic validation; encoded frame size bounds its bytes independently.
func selectionToken(value string) bool {
	return value != "" && len(value) <= MaxFrameBytes && utf8.ValidString(value) && !strings.ContainsRune(value, 0)
}

type Admission struct {
	Native        NativeOptions `json:"native,omitzero"`
	Task          TaskBinding   `json:"task"`
	Provider      string        `json:"provider"`
	Model         Selection     `json:"model"`
	Effort        Selection     `json:"effort"`
	Permission    string        `json:"permission"`
	BudgetSeconds uint32        `json:"budget_seconds"`
	Brief         string        `json:"brief"`
}

func (a Admission) Validate() error {
	if a.Task.Validate(false) != nil || a.Task.SpecSHA256 != "" || !validAdmissionBrief(a.Brief) {
		return ErrInvalid
	}
	if a.Native != (NativeOptions{}) {
		return a.validateNativeOptions()
	}
	return a.validateLegacyOptions()
}

func (a Admission) validateNativeOptions() error {
	if a.Task.Route.Validate() != nil || a.Native.Validate() != nil || !a.legacyOptionsEmpty() {
		return ErrInvalid
	}
	return nil
}

func (a Admission) legacyOptionsEmpty() bool {
	return a.Provider == "" && a.Model == (Selection{}) && a.Effort == (Selection{}) && a.Permission == "" && a.BudgetSeconds == 0
}

func (a Admission) validateLegacyOptions() error {
	if !identifier(a.Provider) || a.Model.Validate() != nil || a.Effort.Validate() != nil {
		return ErrInvalid
	}
	if !selectionToken(a.Permission) {
		return ErrInvalid
	}
	if a.BudgetSeconds == 0 {
		return ErrInvalid
	}
	return nil
}

func validAdmissionBrief(brief string) bool {
	return len(brief) != 0 && len(brief) <= 256<<10 && utf8.ValidString(brief)
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
