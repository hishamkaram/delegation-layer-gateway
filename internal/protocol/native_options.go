package protocol

// NativeOptions is execution intent with omission preserved. Validation here
// checks only transport shape. Delegate owns provider support and defaults.
type NativeOptions struct {
	Version              int       `json:"version"`
	Provider             string    `json:"provider"`
	Model                Selection `json:"model"`
	Effort               Selection `json:"effort"`
	Permission           string    `json:"permission,omitempty"`
	Budget               string    `json:"budget,omitempty"`
	ReviewTarget         string    `json:"review_target,omitempty"`
	NativeTimeout        string    `json:"native_timeout,omitempty"`
	OutputSilenceTimeout string    `json:"output_silence_timeout,omitempty"`
}

func (o NativeOptions) Validate() error {
	if o.Version != 1 || !identifier(o.Provider) || o.Model.Validate() != nil || o.Effort.Validate() != nil {
		return ErrInvalid
	}
	for _, v := range []string{o.Permission, o.Budget, o.ReviewTarget, o.NativeTimeout, o.OutputSilenceTimeout} {
		if v != "" && !selectionToken(v) {
			return ErrInvalid
		}
	}
	return nil
}

// TaskRoute is an operation-bound selector. It is never registered as a project
// pin. GuardFormat makes historical digest controls explicit, not heuristic.
type TaskRoute struct {
	Version        int           `json:"version"`
	Selection      FileSelection `json:"selection"`
	WorkspaceGuard string        `json:"workspace_guard,omitempty"`
	GuardFormat    string        `json:"guard_format"`
}

func (r TaskRoute) Validate() error {
	if r.Version != 1 || r.Selection.Validate() != nil || r.Selection.RelativePathBase64 != "" || r.GuardFormat != FeatureProjectHashGuard {
		return ErrInvalid
	}
	if r.WorkspaceGuard != "" && !guardToken(r.WorkspaceGuard) {
		return ErrInvalid
	}
	return nil
}
