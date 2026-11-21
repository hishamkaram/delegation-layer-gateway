package protocol

// ContinuationOverrides preserves omission. Native alone validates supported
// values and eligibility. Output silence "0" explicitly disables that timeout.
type ContinuationOverrides struct {
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
		if value != "" && !selectionToken(value) {
			return ErrInvalid
		}
	}
	return nil
}

// Continuation creates one successor through Native's guarded continue command.
// It is never dispatch fallback or a retry with a replacement identity.
type Continuation struct {
	Task              TaskBinding           `json:"task"`
	Predecessor       TaskBinding           `json:"predecessor"`
	Overrides         ContinuationOverrides `json:"overrides"`
	SelectionExplicit bool                  `json:"selection_explicit"`
	BriefPresent      bool                  `json:"brief_present"`
	Brief             string                `json:"brief,omitempty"`
}

func (c Continuation) Validate() error {
	if c.Task.Validate(false) != nil || c.Task.SpecSHA256 != "" || c.Predecessor.Validate(true) != nil || c.Overrides.Validate() != nil {
		return ErrInvalid
	}
	if !c.sameExecutionContext() {
		return ErrInvalid
	}
	if c.BriefPresent {
		if !validAdmissionBrief(c.Brief) {
			return ErrInvalid
		}
	} else if c.Brief != "" {
		return ErrInvalid
	}
	return nil
}

func (c Continuation) sameExecutionContext() bool {
	return c.Task.Route.Validate() == nil && c.Predecessor.Route.Validate() == nil && c.Task.Origin.Binding != "" && c.Task.TaskID != c.Predecessor.TaskID && c.Task.Origin.OperationID != c.Predecessor.Origin.OperationID && c.Task.Context == c.Predecessor.Context && c.Task.Route.WorkspaceGuard == c.Predecessor.Route.WorkspaceGuard && c.Task.Origin.GatewayID == c.Predecessor.Origin.GatewayID && c.Task.Origin.PrincipalRef == c.Predecessor.Origin.PrincipalRef
}
