package protocol

import (
	"encoding/hex"
	"strings"
	"unicode/utf8"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

// NativeInputRecordBytes mirrors Delegate's public connector JSON input bound.
// It is separate from stdout capture and wire framing limits.
const NativeInputRecordBytes = 1 << 20

// Validate checks transport shape. Gateway's domain verifier owns the binding's
// meaning and corroborates it against authenticated recovery coordinates.
func (o Origin) Validate() error {
	for _, value := range []string{o.GatewayID, o.AdmissionGeneration, o.OperationID, o.PrincipalRef} {
		if !identifier(value) {
			return ErrInvalid
		}
	}
	if !lowerHex(o.RequestSHA256, 64) || len(o.Binding) > NativeInputRecordBytes || !utf8.ValidString(o.Binding) || strings.ContainsRune(o.Binding, 0) {
		return ErrInvalid
	}
	return nil
}

// OriginFromCorrelation is the sole wire-origin constructor for task controls,
// admission, fencing and recovery. Invalid compact intent never loses its binding.
func OriginFromCorrelation(c domain.Correlation) (Origin, error) {
	if c.Validate() != nil {
		return Origin{}, ErrInvalid
	}
	if c.RequestVersion == domain.CompactRequestVersion {
		origin, err := domain.CompactOrigin(c)
		if err != nil {
			return Origin{}, err
		}
		return OriginFromDomain(origin)
	}
	return OriginFromDomain(domain.OriginFromCorrelation(c))
}

func OriginFromDomain(o domain.TaskOrigin) (Origin, error) {
	if o.Validate() != nil {
		return Origin{}, ErrInvalid
	}
	result := Origin{GatewayID: string(o.Gateway), AdmissionGeneration: string(o.AdmissionGeneration), OperationID: string(o.Operation), PrincipalRef: string(o.Principal), RequestSHA256: o.RequestDigest.Hex(), Binding: o.Binding}
	if result.Validate() != nil {
		return Origin{}, ErrInvalid
	}
	return result, nil
}

// DomainOrigin preserves every immutable origin field on the inverse path.
func (o Origin) DomainOrigin() (domain.TaskOrigin, error) {
	if o.Validate() != nil {
		return domain.TaskOrigin{}, ErrInvalid
	}
	var digest domain.Digest
	if _, err := hex.Decode(digest[:], []byte(o.RequestSHA256)); err != nil {
		return domain.TaskOrigin{}, ErrInvalid
	}
	return domain.TaskOrigin{Gateway: domain.GatewayID(o.GatewayID), AdmissionGeneration: domain.AdmissionGeneration(o.AdmissionGeneration), Operation: domain.OperationID(o.OperationID), Principal: domain.PrincipalID(o.PrincipalRef), RequestDigest: digest, Binding: o.Binding}, nil
}

func TaskRouteFromDomain(route domain.OperationRoute) (TaskRoute, error) {
	if route == (domain.OperationRoute{}) {
		return TaskRoute{}, nil
	}
	if route.Validate() != nil {
		return TaskRoute{}, ErrInvalid
	}
	result := TaskRoute{Version: route.Version, Selection: FileSelection{ScopeID: route.ScopeID, RelativePath: route.RelativePath}, WorkspaceGuard: route.WorkspaceGuard, GuardFormat: FeatureProjectHashGuard}
	if result.Validate() != nil {
		return TaskRoute{}, ErrInvalid
	}
	return result, nil
}
