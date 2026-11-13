package domain

import "time"

// ResolutionID is a caller-retained pin request identity, never a task ID.
type ResolutionID string

func (r ResolutionID) Validate() error {
	if len(r) != 32 {
		return ErrInvalid
	}
	for _, c := range r {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return ErrInvalid
		}
	}
	return nil
}

// WorkspaceBinding is immutable identity. Live policy revisions and provider
// readiness are observations and never become part of this binding.
type WorkspaceBinding struct{ ID, Guard string }

func (w WorkspaceBinding) Validate() error {
	if Token(w.ID) != nil || ContextToken(w.Guard) != nil {
		return ErrInvalid
	}
	return nil
}

type ProjectPin struct {
	Handle    ProjectAlias
	Workspace WorkspaceBinding
	Context   ContextBinding
}

func (p ProjectPin) Validate() error {
	if ResolutionID(p.Handle).Validate() != nil || p.Workspace.Validate() != nil || p.Context.Validate() != nil {
		return ErrInvalid
	}
	return nil
}

// ProjectResolution is Registry's immutable correlation and first validated
// Native pin. Registered is derived from the project route, not a task state.
type ProjectResolution struct {
	Request        ResolutionID
	Principal      PrincipalID
	Device         DeviceID
	Root           RootGuard
	Workspace      WorkspaceBinding
	SelectorDigest Digest
	Pin            *ProjectPin
	Registered     bool
	CreatedAt      time.Time
}

func (r ProjectResolution) Validate() error {
	if r.Request.Validate() != nil || Token(string(r.Principal)) != nil || CredentialToken(string(r.Device)) != nil || ContextToken(string(r.Root)) != nil || r.Workspace.Validate() != nil || r.SelectorDigest.Validate() != nil || r.CreatedAt.IsZero() {
		return ErrInvalid
	}
	if r.Pin != nil && (r.Pin.Validate() != nil || r.Pin.Handle != ProjectAlias(r.Request) || r.Pin.Workspace != r.Workspace || r.Pin.Context.Root != r.Root) {
		return ErrInvalid
	}
	if r.Registered && r.Pin == nil {
		return ErrInvalid
	}
	return nil
}

type ProjectResolutionStart struct {
	Request        ResolutionID
	Binding        OwnedRootBinding
	Workspace      WorkspaceBinding
	SelectorDigest Digest
	Now            time.Time
}

type ProjectResolutionPin struct {
	Request ResolutionID
	Binding OwnedRootBinding
	Pin     ProjectPin
	Now     time.Time
}

type ProjectResolutionCheck struct {
	Request ResolutionID
	Binding OwnedRootBinding
	Now     time.Time
}
