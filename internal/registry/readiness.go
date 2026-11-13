package registry

import (
	"context"
	"database/sql"
	"errors"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

func validateProjectReadiness(input domain.ProjectReadinessRequest) error {
	if err := input.Actor.Validate(); err != nil {
		return err
	}
	if err := input.Destination.Validate(); err != nil {
		return err
	}
	if err := input.Context.Validate(); err != nil {
		return err
	}
	if err := domain.RoutingToken(string(input.Generation)); err != nil {
		return err
	}
	if err := input.Credential.Validate(); err != nil {
		return err
	}
	if err := input.Connection.Validate(); err != nil {
		return err
	}
	if input.Now.IsZero() || input.Credential.Device != input.Destination.Device {
		return domain.ErrInvalid
	}
	return nil
}

// CheckProjectReadiness never turns an authorization failure into visibility.
// The bool is a current eligibility decision, not provider or task liveness.
func (s *Store) CheckProjectReadiness(ctx context.Context, input domain.ProjectReadinessRequest) (bool, error) {
	if err := validateProjectReadiness(input); err != nil {
		return false, err
	}
	return transaction(ctx, s, func(tx *sql.Tx) (bool, error) {
		if _, err := authorize(ctx, tx, domain.AuthorizationRequest{Actor: input.Actor, Destination: input.Destination, Scope: domain.InventoryRead}); err != nil {
			return false, err
		}
		credential, err := checkConnection(ctx, tx, input.Credential, input.Connection, input.Now)
		if err != nil {
			if readinessDenial(err, domain.Forbidden, domain.Conflict, domain.NotFound) {
				return false, nil
			}
			return false, err
		}
		if credential.Mode != domain.Regular {
			return false, nil
		}
		generation, err := checkProjectAdmission(ctx, tx, input.Destination, input.Context)
		if err != nil {
			if readinessDenial(err, domain.Pending, domain.Conflict) {
				return false, nil
			}
			return false, err
		}
		return generation == input.Generation, nil
	})
}

func readinessDenial(err error, codes ...domain.ErrorCode) bool {
	var classified *domain.Error
	if !errors.As(err, &classified) {
		return false
	}
	for _, code := range codes {
		if classified.Code == code {
			return true
		}
	}
	return false
}
