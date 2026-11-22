package domain

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path"
	"strings"
	"unicode/utf8"
)

const CompactRequestVersion = 4

type RequestKind string

const (
	RequestKindDispatch     RequestKind = "dispatch"
	RequestKindContinuation RequestKind = "continuation"
)

type InputFormat string

const (
	DispatchInputV1     InputFormat = "dispatch-v1"
	ContinuationInputV1 InputFormat = "continuation-v1"
)

// RequestSelector freezes the original dispatch fingerprint's selector encoding.
// Compact routes use text paths; the base64 field remains for legacy fingerprints.
type RequestSelector struct {
	ScopeID            string `json:"scope_id"`
	RelativePath       string `json:"relative_path,omitempty"`
	RelativePathBase64 string `json:"relative_path_base64,omitempty"`
}

type frozenRequestSelector struct {
	ScopeID            string `json:"scope_id"`
	RelativePath       string `json:"relative_path,omitempty"`
	RelativePathBase64 string `json:"relative_path_base64,omitempty"`
}

// ContinuationOverrides carries only literal Native overrides. Empty inherits;
// output silence "0" explicitly disables it. Native owns option semantics.
type ContinuationOverrides struct {
	Version              int    `json:"version"`
	Budget               string `json:"budget,omitempty"`
	Model                string `json:"model,omitempty"`
	Effort               string `json:"effort,omitempty"`
	OutputSilenceTimeout string `json:"output_silence_timeout,omitempty"`
}

type frozenContinuationOverrides struct {
	Version              int    `json:"version"`
	Budget               string `json:"budget,omitempty"`
	Model                string `json:"model,omitempty"`
	Effort               string `json:"effort,omitempty"`
	OutputSilenceTimeout string `json:"output_silence_timeout,omitempty"`
}

func (o ContinuationOverrides) Validate() error {
	if o.Version != 1 {
		return ErrInvalid
	}
	for _, value := range []string{o.Budget, o.Model, o.Effort, o.OutputSilenceTimeout} {
		if value != "" && optionValue(value) != nil {
			return ErrInvalid
		}
	}
	return nil
}

type ContinuationPredecessor struct {
	Operation     OperationID
	Task          TaskID
	SpecDigest    Digest
	RequestDigest Digest // The predecessor Origin's request commitment, not its spec.
}

func (p ContinuationPredecessor) Validate() error {
	if Token(string(p.Operation)) != nil || p.Task.Validate() != nil || p.SpecDigest.Validate() != nil || p.RequestDigest.Validate() != nil {
		return ErrInvalid
	}
	return nil
}

// These private types are the frozen v2/v3 and dispatch-input-v1 encodings.
// Extending public domain values must never change historical digest bytes.
type frozenSelection struct {
	Kind  string
	Value string
}

type frozenNativeOptions struct {
	Version              int             `json:"version"`
	Provider             string          `json:"provider"`
	Model                frozenSelection `json:"model"`
	Effort               frozenSelection `json:"effort"`
	Permission           string          `json:"permission,omitempty"`
	Budget               string          `json:"budget,omitempty"`
	ReviewTarget         string          `json:"review_target,omitempty"`
	NativeTimeout        string          `json:"native_timeout,omitempty"`
	OutputSilenceTimeout string          `json:"output_silence_timeout,omitempty"`
}

type frozenExecutionOptions struct {
	Native        frozenNativeOptions `json:",omitzero"`
	Provider      string
	Model         frozenSelection
	Effort        frozenSelection
	Permission    string
	BudgetSeconds uint32
}

func freezeOptions(o ExecutionOptions) frozenExecutionOptions {
	n := o.Native
	return frozenExecutionOptions{
		Native:   frozenNativeOptions{n.Version, string(n.Provider), frozenSelection{string(n.Model.Kind), n.Model.Value}, frozenSelection{string(n.Effort.Kind), n.Effort.Value}, n.Permission, n.Budget, n.ReviewTarget, n.NativeTimeout, n.OutputSilenceTimeout},
		Provider: string(o.Provider), Model: frozenSelection{string(o.Model.Kind), o.Model.Value}, Effort: frozenSelection{string(o.Effort.Kind), o.Effort.Value}, Permission: string(o.Permission), BudgetSeconds: o.BudgetSeconds,
	}
}

type (
	frozenOwner       struct{ Kind, Principal string }
	frozenDestination struct{ Device, Project string }
	frozenContext     struct{ Root, Project string }
)

type frozenRequestBinding struct {
	Version     int
	Operation   string
	Task        string
	Gateway     string
	Generation  string
	Owner       frozenOwner
	Destination frozenDestination
	Context     frozenContext
	Options     frozenExecutionOptions
	BriefSHA256 string
}

type frozenRoute struct {
	Version        int
	RequestID      string
	InputDigest    [32]byte
	ScopeID        string
	RelativePath   string
	WorkspaceGuard string
	Predecessor    string
}

func legacyRequestBindingDigest(c Correlation, options ExecutionOptions, brief Digest) (Digest, error) {
	binding := frozenRequestBinding{2, string(c.Operation), string(c.Task), string(c.Gateway), string(c.AdmissionGeneration), frozenOwner{string(c.Owner.Kind), string(c.Owner.Principal)}, frozenDestination{string(c.Destination.Device), string(c.Destination.Project)}, frozenContext{string(c.Context.Root), string(c.Context.Project)}, freezeOptions(options), brief.Hex()}
	var encoded []byte
	var err error
	if c.Route.Version == 1 {
		binding.Version = 3
		r := c.Route
		encoded, err = json.Marshal(struct {
			frozenRequestBinding
			Route frozenRoute
		}{binding, frozenRoute{r.Version, string(r.RequestID), [32]byte(r.InputDigest), r.ScopeID, r.RelativePath, r.WorkspaceGuard, string(r.Predecessor)}})
	} else {
		encoded, err = json.Marshal(binding)
	}
	if err != nil {
		return Digest{}, ErrInvalid
	}
	return Hash(encoded), nil
}

// DispatchInputDigestV1 preserves json.Marshal's original field order, HTML
// escaping and digest-array representation. It does not normalize selectors.
func DispatchInputDigestV1(device DeviceID, selection RequestSelector, options ExecutionOptions, brief Digest) (Digest, error) {
	if CredentialToken(string(device)) != nil || validFingerprintSelector(selection) != nil || options.Validate() != nil || brief.Validate() != nil {
		return Digest{}, ErrInvalid
	}
	encoded, err := json.Marshal(struct {
		Device    string
		Selection frozenRequestSelector
		Options   frozenExecutionOptions
		Brief     [32]byte
	}{string(device), frozenRequestSelector(selection), freezeOptions(options), [32]byte(brief)})
	if err != nil {
		return Digest{}, ErrInvalid
	}
	return Hash(encoded), nil
}

// ContinuationInputDigestV1 commits caller input before predecessor lookup.
// Implicit selection requires the zero selector; the captured execution route
// remains independently committed by BuildOriginBinding.
func ContinuationInputDigestV1(device DeviceID, predecessor OperationID, selection RequestSelector, explicit bool, overrides ContinuationOverrides, briefPresent bool, brief Digest) (Digest, error) {
	if CredentialToken(string(device)) != nil || Token(string(predecessor)) != nil || overrides.Validate() != nil || validRequestedBrief(briefPresent, brief) != nil {
		return Digest{}, ErrInvalid
	}
	if explicit {
		if validCompactSelector(selection) != nil {
			return Digest{}, ErrInvalid
		}
	} else if selection != (RequestSelector{}) {
		return Digest{}, ErrInvalid
	}
	encoded, err := json.Marshal(struct {
		Version           int
		Kind              string
		Device            string
		Predecessor       string
		Selection         frozenRequestSelector
		SelectionExplicit bool
		Overrides         frozenContinuationOverrides
		BriefPresent      bool
		Brief             [32]byte
	}{1, string(RequestKindContinuation), string(device), string(predecessor), frozenRequestSelector(selection), explicit, frozenContinuationOverrides(overrides), briefPresent, [32]byte(brief)})
	if err != nil {
		return Digest{}, ErrInvalid
	}
	return Hash(encoded), nil
}

func validCompactSelector(s RequestSelector) error {
	if s.RelativePathBase64 != "" || s.RelativePath == "" {
		return ErrInvalid
	}
	return validFingerprintSelector(s)
}

func validFingerprintSelector(s RequestSelector) error {
	if Token(s.ScopeID) != nil || s.RelativePath != "" && s.RelativePathBase64 != "" {
		return ErrInvalid
	}
	value := s.RelativePath
	if s.RelativePathBase64 != "" {
		if len(s.RelativePathBase64) > base64.StdEncoding.EncodedLen(4096) {
			return ErrInvalid
		}
		decoded, err := base64.StdEncoding.Strict().DecodeString(s.RelativePathBase64)
		if err != nil {
			return ErrInvalid
		}
		value = string(decoded)
	} else if !utf8.ValidString(value) {
		return ErrInvalid
	}
	if value == "" {
		value = "."
	}
	return validSelectorPath(value)
}

func validSelectorPath(value string) error {
	if len(value) > 4096 || strings.ContainsRune(value, 0) || path.IsAbs(value) || path.Clean(value) != value {
		return ErrInvalid
	}
	for _, component := range strings.Split(value, "/") {
		if component == ".." || len(component) > 255 {
			return ErrInvalid
		}
	}
	return nil
}

func validRequestedBrief(present bool, digest Digest) error {
	if present {
		return digest.Validate()
	}
	if digest != (Digest{}) {
		return ErrInvalid
	}
	return nil
}

func validateRequestVersion(c Correlation) error {
	if c.RequestVersion == 0 {
		return validateLegacyRequestFields(c)
	}
	if c.RequestVersion != CompactRequestVersion || validateCompactRoute(c.Route) != nil || validRequestedBrief(c.BriefPresent, c.BriefDigest) != nil {
		return ErrInvalid
	}
	switch c.Kind {
	case RequestKindDispatch:
		if c.Route.InputFormat != DispatchInputV1 || !c.BriefPresent || c.Predecessor != (ContinuationPredecessor{}) {
			return ErrInvalid
		}
	case RequestKindContinuation:
		if c.Route.InputFormat != ContinuationInputV1 || c.Predecessor.Validate() != nil || c.Predecessor.Operation == c.Operation || c.Predecessor.Task == c.Task {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func validateLegacyRequestFields(c Correlation) error {
	if c.Kind != "" || c.BriefPresent || c.Predecessor != (ContinuationPredecessor{}) || c.Route.InputFormat != "" {
		return ErrInvalid
	}
	return nil
}

func validateCompactRoute(r OperationRoute) error {
	if r.Version != 1 || r.Predecessor != "" || ContextToken(r.WorkspaceGuard) != nil || validCompactSelector(RequestSelector{ScopeID: r.ScopeID, RelativePath: r.RelativePath}) != nil {
		return ErrInvalid
	}
	return nil
}

func compactRequestDigest(c Correlation, r FrozenRequest) (Digest, error) {
	if c.validateBinding() != nil || c.BriefPresent != r.BriefPresent {
		return Digest{}, ErrInvalid
	}
	brief := Digest{}
	if r.BriefPresent {
		brief = Hash([]byte(r.Brief))
	}
	if brief != c.BriefDigest {
		return Digest{}, ErrInvalid
	}
	input, err := compactInputDigest(c, r, brief)
	if err != nil || input != c.Route.InputDigest {
		return Digest{}, ErrInvalid
	}
	binding, err := BuildOriginBinding(c)
	if err != nil {
		return Digest{}, err
	}
	return Hash([]byte(binding)), nil
}

func compactInputDigest(c Correlation, r FrozenRequest, brief Digest) (Digest, error) {
	selection := RequestSelector{ScopeID: c.Route.ScopeID, RelativePath: c.Route.RelativePath}
	switch c.Kind {
	case RequestKindDispatch:
		if r.Native.Version != 1 || r.Continuation != (ContinuationOverrides{}) || r.SelectionExplicit {
			return Digest{}, ErrInvalid
		}
		return DispatchInputDigestV1(c.Destination.Device, selection, r.Options(), brief)
	case RequestKindContinuation:
		if r.Continuation.Version != 1 || r.Options() != (ExecutionOptions{}) {
			return Digest{}, ErrInvalid
		}
		if !r.SelectionExplicit {
			selection = RequestSelector{}
		}
		return ContinuationInputDigestV1(c.Destination.Device, c.Predecessor.Operation, selection, r.SelectionExplicit, r.Continuation, r.BriefPresent, brief)
	default:
		return Digest{}, ErrInvalid
	}
}

type compactContext struct {
	Root    string `json:"root"`
	Project string `json:"project"`
}

type compactRoute struct {
	RequestID      string      `json:"request_id"`
	InputFormat    InputFormat `json:"input_format"`
	InputSHA256    string      `json:"input_sha256"`
	ScopeID        string      `json:"scope_id"`
	RelativePath   string      `json:"relative_path"`
	WorkspaceGuard string      `json:"workspace_guard"`
}

type compactBrief struct {
	Present bool   `json:"present"`
	SHA256  string `json:"sha256,omitempty"`
}

type compactPredecessor struct {
	Operation     string `json:"operation"`
	Task          string `json:"task"`
	SpecSHA256    string `json:"spec_sha256"`
	RequestSHA256 string `json:"request_sha256"`
}

type compactBinding struct {
	Version      int                `json:"v"`
	Kind         RequestKind        `json:"kind"`
	Gateway      string             `json:"gateway"`
	Generation   string             `json:"generation"`
	Operation    string             `json:"operation"`
	Task         string             `json:"task"`
	Principal    string             `json:"principal"`
	Device       string             `json:"device"`
	ProjectAlias string             `json:"project_alias"`
	Context      compactContext     `json:"context"`
	Route        compactRoute       `json:"route"`
	Brief        compactBrief       `json:"brief"`
	Predecessor  compactPredecessor `json:"predecessor,omitzero"`
}

// BuildOriginBinding is the single v4 preimage builder. RequestDigest is excluded
// deliberately, so a caller can compute the digest before publishing correlation.
func BuildOriginBinding(c Correlation) (string, error) {
	if c.RequestVersion != CompactRequestVersion || c.validateBinding() != nil {
		return "", ErrInvalid
	}
	value := compactBinding{Version: CompactRequestVersion, Kind: c.Kind, Gateway: string(c.Gateway), Generation: string(c.AdmissionGeneration), Operation: string(c.Operation), Task: string(c.Task), Principal: string(c.Owner.Principal), Device: string(c.Destination.Device), ProjectAlias: string(c.Destination.Project), Context: compactContext{string(c.Context.Root), string(c.Context.Project)}, Route: compactRoute{string(c.Route.RequestID), c.Route.InputFormat, c.Route.InputDigest.Hex(), c.Route.ScopeID, c.Route.RelativePath, c.Route.WorkspaceGuard}, Brief: compactBrief{Present: c.BriefPresent}}
	if c.BriefPresent {
		value.Brief.SHA256 = c.BriefDigest.Hex()
	}
	if c.Kind == RequestKindContinuation {
		p := c.Predecessor
		value.Predecessor = compactPredecessor{string(p.Operation), string(p.Task), p.SpecDigest.Hex(), p.RequestDigest.Hex()}
	}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return "", ErrInvalid
	}
	return strings.TrimSuffix(buffer.String(), "\n"), nil
}

// ParseOriginBinding accepts only the exact canonical v4 bytes. Strict decoding
// plus canonical equality also rejects duplicate, differently cased or omitted
// required keys, alternate escapes and concatenated values.
func ParseOriginBinding(binding string) (Correlation, error) {
	if binding == "" || len(binding) > MaxFrameBytes || !utf8.ValidString(binding) {
		return Correlation{}, Reject(EvidenceInvalid)
	}
	decoder := json.NewDecoder(strings.NewReader(binding))
	decoder.DisallowUnknownFields()
	var value compactBinding
	if decoder.Decode(&value) != nil {
		return Correlation{}, Reject(EvidenceInvalid)
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return Correlation{}, Reject(EvidenceInvalid)
	}
	c, err := value.correlation()
	if err != nil {
		return Correlation{}, Reject(EvidenceInvalid)
	}
	canonical, err := BuildOriginBinding(c)
	if err != nil || canonical != binding {
		return Correlation{}, Reject(EvidenceInvalid)
	}
	c.RequestDigest = Hash([]byte(binding))
	if c.Validate() != nil {
		return Correlation{}, Reject(EvidenceInvalid)
	}
	return c, nil
}

func bindingDigest(value string) (Digest, error) {
	var digest Digest
	if len(value) != 64 || strings.ToLower(value) != value {
		return digest, ErrInvalid
	}
	data, err := hex.DecodeString(value)
	if err != nil {
		return digest, ErrInvalid
	}
	copy(digest[:], data)
	return digest, digest.Validate()
}

func (b compactBinding) correlation() (Correlation, error) {
	c := Correlation{RequestVersion: b.Version, Kind: b.Kind, Operation: OperationID(b.Operation), Task: TaskID(b.Task), Gateway: GatewayID(b.Gateway), AdmissionGeneration: AdmissionGeneration(b.Generation), Owner: OperationOwner{Kind: Owned, Principal: PrincipalID(b.Principal)}, Destination: Destination{Device: DeviceID(b.Device), Project: ProjectAlias(b.ProjectAlias)}, Context: ContextBinding{Root: RootGuard(b.Context.Root), Project: ProjectGuard(b.Context.Project)}, Route: OperationRoute{Version: 1, RequestID: RequestID(b.Route.RequestID), InputFormat: b.Route.InputFormat, ScopeID: b.Route.ScopeID, RelativePath: b.Route.RelativePath, WorkspaceGuard: b.Route.WorkspaceGuard}, BriefPresent: b.Brief.Present}
	var err error
	c.Route.InputDigest, err = bindingDigest(b.Route.InputSHA256)
	if err != nil {
		return Correlation{}, err
	}
	if b.Brief.Present {
		c.BriefDigest, err = bindingDigest(b.Brief.SHA256)
	} else if b.Brief.SHA256 != "" {
		return Correlation{}, ErrInvalid
	}
	if err != nil {
		return Correlation{}, err
	}
	if b.Predecessor != (compactPredecessor{}) {
		c.Predecessor = ContinuationPredecessor{Operation: OperationID(b.Predecessor.Operation), Task: TaskID(b.Predecessor.Task)}
		c.Predecessor.SpecDigest, err = bindingDigest(b.Predecessor.SpecSHA256)
		if err != nil {
			return Correlation{}, err
		}
		c.Predecessor.RequestDigest, err = bindingDigest(b.Predecessor.RequestSHA256)
	}
	return c, err
}

func CompactOrigin(c Correlation) (TaskOrigin, error) {
	if c.RequestVersion != CompactRequestVersion || c.Validate() != nil {
		return TaskOrigin{}, ErrInvalid
	}
	binding, err := BuildOriginBinding(c)
	if err != nil {
		return TaskOrigin{}, err
	}
	return TaskOrigin{Gateway: c.Gateway, AdmissionGeneration: c.AdmissionGeneration, Operation: c.Operation, Principal: c.Owner.Principal, RequestDigest: c.RequestDigest, Binding: binding}, nil
}

func VerifyOriginBinding(gateway GatewayID, key NativeTaskKey, origin TaskOrigin) (Correlation, error) {
	if Token(string(gateway)) != nil || key.Validate() != nil || origin.Validate() != nil || origin.Gateway != gateway {
		return Correlation{}, Reject(EvidenceInvalid)
	}
	c, err := ParseOriginBinding(origin.Binding)
	if err != nil {
		return Correlation{}, err
	}
	if c.Gateway != origin.Gateway || c.AdmissionGeneration != origin.AdmissionGeneration || c.Operation != origin.Operation || c.Owner.Principal != origin.Principal || c.RequestDigest != origin.RequestDigest || c.Destination.Device != key.Device || c.Context.Root != key.Root || c.Task != key.Task {
		return Correlation{}, Reject(EvidenceInvalid)
	}
	return c, nil
}

// RequestedBriefMatches never assigns an inherited Native brief to an absent
// requested brief. The caller retains the observed Native digest separately.
func RequestedBriefMatches(c Correlation, observed Digest) bool {
	if c.Validate() != nil || observed.Validate() != nil {
		return false
	}
	return c.RequestVersion == CompactRequestVersion && !c.BriefPresent || c.BriefDigest == observed
}

func VerifyBoundNativeReceipt(gateway GatewayID, key NativeTaskKey, receipt NativeTaskReceipt) (Correlation, error) {
	if receipt.Validate() != nil {
		return Correlation{}, Reject(EvidenceInvalid)
	}
	c, err := VerifyOriginBinding(gateway, key, receipt.Binding.Origin)
	if err != nil {
		return Correlation{}, err
	}
	if c.Context != receipt.Binding.Context || receipt.Binding.Task != key.Task || !RequestedBriefMatches(c, receipt.BriefDigest) {
		return Correlation{}, Reject(EvidenceInvalid)
	}
	return c, nil
}
