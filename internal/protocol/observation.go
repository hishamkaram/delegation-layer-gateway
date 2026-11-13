package protocol

// TaskObservation contains only the public Delegate projection and accepted
// descriptor. Liveness alone never authorizes reservation release.
type TaskObservation struct {
	Task                    TaskBinding       `json:"task"`
	BriefSHA256             string            `json:"brief_sha256,omitempty"`
	Resolution              string            `json:"resolution"`
	Admission               string            `json:"admission"`
	Liveness                string            `json:"liveness"`
	Publication             string            `json:"publication"`
	Verdict                 string            `json:"verdict,omitempty"`
	Result                  *Descriptor       `json:"result,omitempty"`
	Stop                    *StopObservation  `json:"stop,omitempty"`
	ExecutionClosure        *ExecutionClosure `json:"execution_closure,omitempty"`
	ExecutionClosurePending string            `json:"execution_closure_pending,omitempty"`
}

type ExecutionClosure struct {
	Kind            string `json:"kind"`
	ReferenceSHA256 string `json:"reference_sha256"`
}

func (c ExecutionClosure) Validate() error {
	if !lowerHex(c.ReferenceSHA256, 64) {
		return ErrInvalid
	}
	switch c.Kind {
	case "registered-native", "registered-recovered", "legacy-previous-boot", "unregistered-recovered", "never-started":
		return nil
	default:
		return ErrInvalid
	}
}

type StopObservation struct {
	RequestID  string `json:"request_id"`
	Requested  bool   `json:"requested"`
	Terminated bool   `json:"terminated"`
}

func (o TaskObservation) Validate() error {
	if o.validateIdentity() != nil || o.validateDisposition() != nil {
		return ErrInvalid
	}
	if o.Result != nil && (o.Result.Validate() != nil || o.Verdict != "committed") {
		return ErrInvalid
	}
	if o.Stop != nil && (!lowerHex(o.Stop.RequestID, 32) || (o.Stop.Terminated && !o.Stop.Requested)) {
		return ErrInvalid
	}
	if o.ExecutionClosure != nil && (o.Resolution != "existing" || o.ExecutionClosure.Validate() != nil) {
		return ErrInvalid
	}
	return o.validatePendingClosure()
}

func (o TaskObservation) validatePendingClosure() error {
	if o.ExecutionClosurePending == "" {
		return nil
	}
	if o.ExecutionClosure != nil || o.Resolution != "existing" {
		return ErrInvalid
	}
	if !oneOf(o.ExecutionClosurePending, "owner_busy", "missing_owner", "partial_evidence", "closure_unproven") {
		return ErrInvalid
	}
	return nil
}

func (o TaskObservation) validateIdentity() error {
	if o.Task.Validate(o.Resolution == "existing") != nil {
		return ErrInvalid
	}
	if !oneOf(o.Resolution, "existing", "permanently_refused", "absent", "unresolved") {
		return ErrInvalid
	}
	if o.Resolution == "existing" && !lowerHex(o.BriefSHA256, 64) {
		return ErrInvalid
	}
	return nil
}

func (o TaskObservation) validateDisposition() error {
	if !oneOf(o.Admission, "unknown", "not-admitted", "admitted") || !oneOf(o.Liveness, "undetermined", "running", "ended") || !oneOf(o.Publication, "unknown", "pending", "committed", "rejected") {
		return ErrInvalid
	}
	if o.Verdict != "" && !oneOf(o.Verdict, "committed", "rejected") {
		return ErrInvalid
	}
	if o.Verdict != "" && (o.Verdict != o.Publication || o.Resolution != "existing") {
		return ErrInvalid
	}
	return nil
}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func (c Cancellation) Validate() error {
	if c.Task.Validate(false) != nil || !lowerHex(c.CancellationID, 32) {
		return ErrInvalid
	}
	return nil
}
