package domain

// RootRoute identifies a Native namespace without requiring a project alias.
// It never stands in for a task destination or grants project access.
type RootRoute struct {
	Device DeviceID
	Root   RootGuard
}

func (r RootRoute) Validate() error {
	if CredentialToken(string(r.Device)) != nil || ContextToken(string(r.Root)) != nil {
		return ErrInvalid
	}
	return nil
}

// OwnedRootBinding is current authenticated connection evidence. Registry
// derives its owner and rechecks that authority on every read and mutation.
type OwnedRootBinding struct {
	Route      RootRoute
	Credential CredentialRef
	Connection ConnectionGeneration
}

func (b OwnedRootBinding) Validate() error {
	if b.Route.Validate() != nil || b.Credential.Validate() != nil || b.Connection.Validate() != nil || b.Route.Device != b.Credential.Device {
		return ErrInvalid
	}
	return nil
}

func (l RootInitializationLookup) Validate() error {
	if l.RootRoute != nil {
		if l.Route != (Destination{}) || l.ExpectedContext != (ContextBinding{}) {
			return ErrInvalid
		}
		return l.RootRoute.Validate()
	}
	if l.Route.Validate() != nil || l.ExpectedContext.Validate() != nil {
		return ErrInvalid
	}
	return nil
}

func (l RootInitializationLookup) Namespace() (RootRoute, error) {
	if l.Validate() != nil {
		return RootRoute{}, ErrInvalid
	}
	if l.RootRoute != nil {
		return *l.RootRoute, nil
	}
	return RootRoute{Device: l.Route.Device, Root: l.ExpectedContext.Root}, nil
}

func (s RootInitializationStart) Lookup() RootInitializationLookup {
	return RootInitializationLookup{Route: s.Route, ExpectedContext: s.ExpectedContext, RootRoute: s.RootRoute}
}

func (p RootInitializationProgress) Lookup() RootInitializationLookup {
	return RootInitializationLookup{Route: p.Route, ExpectedContext: p.Context, RootRoute: p.RootRoute}
}
