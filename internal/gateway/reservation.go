package gateway

import (
	"context"
	"errors"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

// The app owns an unused transport buffer until Publish. Once a possible write
// is armed, transport owns its completion callbacks and uncertain route lifetime.
func (s *Service) acquireControlRoute(ctx context.Context, reservation Reservation, attempt *routingAttempt, transmission domain.Transmission) error {
	route, err := reservation.Routing()
	if err != nil {
		return err
	}
	attempt.route(transmission, route)
	route.Now = s.now()
	if err = s.store.AcquireRouting(ctx, route); err != nil {
		return err
	}
	return reservation.ArmRouting(route)
}

// Cleanup has its own finite context after observation cancellation. A failure
// surfaces to the caller; it never silently declares the durable route released.
func releaseReservation(ctx context.Context, reservation Reservation, result *error) {
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	*result = errors.Join(*result, reservation.Release(cleanup))
}
