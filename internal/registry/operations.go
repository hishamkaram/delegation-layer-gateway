package registry

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
)

type storedOperation struct {
	view          domain.OperationView
	request       []byte
	options       []byte
	optionsDigest []byte
}

func readOperation(ctx context.Context, tx *sql.Tx, id domain.OperationID) (storedOperation, error) {
	var op storedOperation
	var correlation, observation []byte
	var created, expires string
	var owner domain.PrincipalID
	var root domain.RootGuard
	var project domain.ProjectGuard
	var kind string
	var originOperation domain.OperationID
	err := tx.QueryRowContext(ctx, "SELECT correlation,request,state,created,expires,reserved,cancellation,observation,coalesce(owner,''),execution_options,options_sha256,root_guard,project_guard,kind,origin_operation FROM operations WHERE id=?", id).Scan(&correlation, &op.request, &op.view.Delivery, &created, &expires, &op.view.Reserved, &op.view.Cancellation, &observation, &owner, &op.options, &op.optionsDigest, &root, &project, &kind, &originOperation)
	if err != nil {
		return op, notFound(err)
	}
	op.view.Correlation, err = decode[domain.Correlation](correlation)
	if err != nil {
		return op, err
	}
	if err = op.view.Correlation.Validate(); err != nil {
		return op, fmt.Errorf("stored correlation: %w", err)
	}
	if !storedOperationIdentityMatches(op.view.Correlation, id, originOperation, kind, domain.ContextBinding{Root: root, Project: project}) {
		return op, domain.Reject(domain.EvidenceInvalid)
	}
	if err = op.view.Delivery.Validate(); err != nil {
		return op, err
	}
	if owner != "" && (op.view.Correlation.Owner.Kind != domain.Owned || owner != op.view.Correlation.Owner.Principal) {
		return op, domain.Reject(domain.EvidenceInvalid)
	}
	op.view.EffectiveOwner = domain.OperationOwner{Kind: domain.Ownerless}
	if owner != "" {
		op.view.EffectiveOwner = domain.OperationOwner{Kind: domain.Owned, Principal: owner}
	}
	op.view.CreatedAt, err = time.Parse(time.RFC3339Nano, created)
	if err != nil {
		return op, err
	}
	op.view.ExpiresAt, err = time.Parse(time.RFC3339Nano, expires)
	if err != nil {
		return op, err
	}
	if len(observation) > 0 {
		value, decodeErr := decode[domain.DelegateObservation](observation)
		if decodeErr != nil {
			return op, decodeErr
		}
		if validateErr := value.Validate(value.ObservedAt); validateErr != nil {
			return op, validateErr
		}
		op.view.Observation = &value
	}
	return op, nil
}

func storedOperationIdentityMatches(c domain.Correlation, id, origin domain.OperationID, kind string, binding domain.ContextBinding) bool {
	return c.Operation == id && origin == id && kind == "attributed" && c.Context == binding
}

func authorizeOperation(ctx context.Context, tx *sql.Tx, actor domain.Actor, op storedOperation, scope domain.Scope) (domain.Authorization, error) {
	if op.view.EffectiveOwner.Kind != domain.Owned || op.view.EffectiveOwner.Principal != actor.Principal {
		return domain.Authorization{}, domain.Reject(domain.NotFound)
	}
	return authorize(ctx, tx, domain.AuthorizationRequest{Actor: actor, Destination: op.view.Correlation.Destination, Scope: scope})
}

func checkActiveBinding(ctx context.Context, tx *sql.Tx, c domain.Correlation) error {
	generation, err := checkOpenContext(ctx, tx, c)
	if err != nil {
		return err
	}
	if generation != c.AdmissionGeneration {
		return domain.Reject(domain.Conflict)
	}
	return nil
}

func checkOpenContext(ctx context.Context, tx *sql.Tx, c domain.Correlation) (domain.AdmissionGeneration, error) {
	var gateway domain.GatewayID
	if err := tx.QueryRowContext(ctx, "SELECT gateway FROM settings WHERE id=1").Scan(&gateway); err != nil {
		return "", err
	}
	if gateway != c.Gateway {
		return "", domain.Reject(domain.Conflict)
	}
	return checkProjectAdmission(ctx, tx, c.Destination, c.Context)
}

func checkProjectAdmission(ctx context.Context, tx *sql.Tx, destination domain.Destination, expectedContext domain.ContextBinding) (domain.AdmissionGeneration, error) {
	if err := admissionsOpen(ctx, tx); err != nil {
		return "", err
	}
	binding, err := readContext(ctx, tx, destination)
	if err != nil {
		return "", err
	}
	if binding != expectedContext {
		return "", domain.Reject(domain.Conflict)
	}
	var generation domain.AdmissionGeneration
	if err = tx.QueryRowContext(ctx, "SELECT generation FROM root_admissions WHERE device=? AND root_guard=? AND state='open'", destination.Device, binding.Root).Scan(&generation); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", domain.Reject(domain.Pending)
		}
		return "", err
	}
	if domain.RoutingToken(string(generation)) != nil {
		return "", domain.Reject(domain.EvidenceInvalid)
	}
	return generation, nil
}

func validatePreparation(actor domain.Actor, input domain.Preparation) error {
	if err := actor.Validate(); err != nil {
		return err
	}
	if err := input.Correlation.Validate(); err != nil {
		return err
	}
	if err := input.Request.Validate(); err != nil {
		return err
	}
	if input.Now.IsZero() || input.Correlation.Owner.Kind != domain.Owned || input.Correlation.Owner.Principal != actor.Principal {
		return domain.ErrInvalid
	}
	digest, err := domain.RequestDigest(input.Correlation, input.Request)
	if err != nil {
		return err
	}
	if input.Correlation.RequestDigest != digest || input.Correlation.BriefDigest != domain.Hash([]byte(input.Request.Brief)) {
		return domain.Reject(domain.Conflict)
	}
	return nil
}

func (s *Store) Prepare(ctx context.Context, actor domain.Actor, input domain.Preparation) (domain.PreparedOperation, error) {
	if err := validatePreparation(actor, input); err != nil {
		return domain.PreparedOperation{}, err
	}
	request, err := encode(input.Request)
	if err != nil {
		return domain.PreparedOperation{}, err
	}
	correlation, err := encode(input.Correlation)
	if err != nil {
		return domain.PreparedOperation{}, err
	}
	options, err := encode(input.Request.Options())
	if err != nil {
		return domain.PreparedOperation{}, err
	}
	return transaction(ctx, s, func(tx *sql.Tx) (domain.PreparedOperation, error) {
		if err := checkActiveBinding(ctx, tx, input.Correlation); err != nil {
			return domain.PreparedOperation{}, err
		}
		auth, err := authorize(ctx, tx, domain.AuthorizationRequest{Actor: actor, Destination: input.Correlation.Destination, Scope: domain.TaskDispatch})
		if err != nil {
			return domain.PreparedOperation{}, err
		}
		if !auth.Grant.Ceiling.Allows(input.Request) {
			return domain.PreparedOperation{}, domain.Reject(domain.Forbidden)
		}
		return insertPreparation(ctx, tx, input, request, correlation, options)
	})
}

func insertPreparation(ctx context.Context, tx *sql.Tx, input domain.Preparation, request, correlation, options []byte) (domain.PreparedOperation, error) {
	existing, err := readOperation(ctx, tx, input.Correlation.Operation)
	if err == nil {
		if existing.view.Correlation != input.Correlation {
			return domain.PreparedOperation{}, domain.Reject(domain.Conflict)
		}
		if _, err = storedExecutionOptions(existing); err != nil {
			return domain.PreparedOperation{}, err
		}
		return domain.PreparedOperation{Correlation: existing.view.Correlation, ExpiresAt: existing.view.ExpiresAt}, nil
	}
	var classified *domain.Error
	if !errors.As(err, &classified) || classified.Code != domain.NotFound {
		return domain.PreparedOperation{}, err
	}
	var count, retained int64
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*),COALESCE(SUM(length(request)),0) FROM operations").Scan(&count, &retained); err != nil {
		return domain.PreparedOperation{}, err
	}
	if count >= domain.MaxCorrelations || retained+int64(len(request)) > domain.MaxRetainedBytes {
		return domain.PreparedOperation{}, domain.Reject(domain.ResourceLimit)
	}
	var taskCount int
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM operations WHERE (device=? AND root_guard=? AND task=?) OR origin_operation=?", input.Correlation.Destination.Device, input.Correlation.Context.Root, input.Correlation.Task, input.Correlation.Operation).Scan(&taskCount); err != nil {
		return domain.PreparedOperation{}, err
	}
	if taskCount != 0 {
		return domain.PreparedOperation{}, domain.Reject(domain.Conflict)
	}
	expires := input.Now.Add(domain.DraftTTL)
	optionsDigest := domain.Hash(options)
	_, err = tx.ExecContext(ctx, "INSERT INTO operations(id,origin_operation,kind,root_guard,project_guard,task,owner,device,project,correlation,request,execution_options,options_sha256,state,created,expires) VALUES(?,?,'attributed',?,?,?,?,?,?,?,?,?,?,?,?,?)", input.Correlation.Operation, input.Correlation.Operation, input.Correlation.Context.Root, input.Correlation.Context.Project, input.Correlation.Task, input.Correlation.Owner.Principal, input.Correlation.Destination.Device, input.Correlation.Destination.Project, correlation, request, options, optionsDigest[:], domain.Prepared, input.Now.UTC().Format(timestampLayout), expires.UTC().Format(timestampLayout))
	return domain.PreparedOperation{Correlation: input.Correlation, ExpiresAt: expires}, err
}

// GetForDispatch exposes only the caller's own still-unsent request under current
// dispatch authorization; it grants no status/result-read permission.
func (s *Store) GetForDispatch(ctx context.Context, actor domain.Actor, id domain.OperationID, now time.Time) (domain.DispatchView, error) {
	if err := actor.Validate(); err != nil {
		return domain.DispatchView{}, err
	}
	if err := domain.Token(string(id)); err != nil {
		return domain.DispatchView{}, err
	}
	if now.IsZero() {
		return domain.DispatchView{}, domain.ErrInvalid
	}
	return transaction(ctx, s, func(tx *sql.Tx) (domain.DispatchView, error) {
		op, err := readOperation(ctx, tx, id)
		if err != nil {
			return domain.DispatchView{}, err
		}
		if _, err = authorizeOperation(ctx, tx, actor, op, domain.TaskDispatch); err != nil {
			return domain.DispatchView{}, err
		}
		if op.view.Delivery != domain.Prepared {
			op.view.Observation = nil
			return domain.DispatchView{Operation: op.view}, nil
		}
		if op.view.Cancellation != "" {
			return domain.DispatchView{}, domain.Reject(domain.Conflict)
		}
		if !now.Before(op.view.ExpiresAt) {
			return domain.DispatchView{}, domain.Reject(domain.Expired)
		}
		request, err := decode[domain.FrozenRequest](op.request)
		if err == nil {
			err = validateFrozenRequest(op.view.Correlation, request)
		}
		if err == nil {
			err = validateOptionsAgainstRequest(op, request)
		}
		return domain.DispatchView{Operation: op.view, Request: request}, err
	})
}

func checkConnection(ctx context.Context, tx *sql.Tx, ref domain.CredentialRef, generation domain.ConnectionGeneration, now time.Time) (domain.Credential, error) {
	if err := generation.Validate(); err != nil {
		return domain.Credential{}, err
	}
	cred, err := credential(ctx, tx, ref, now)
	if err != nil {
		return cred, err
	}
	var boot domain.BootEpoch
	var counter uint64
	if err = tx.QueryRowContext(ctx, "SELECT boot,counter FROM devices WHERE id=?", ref.Device).Scan(&boot, &counter); err != nil {
		return cred, err
	}
	if boot != generation.BootEpoch || counter != generation.Counter {
		return cred, domain.Reject(domain.Conflict)
	}
	return cred, nil
}

func (s *Store) MarkPossibleSend(ctx context.Context, actor domain.Actor, input domain.Transmission) (domain.SendDecision, error) {
	return s.markPossibleSend(ctx, actor, input, nil)
}

func (s *Store) markPossibleSend(ctx context.Context, actor domain.Actor, input domain.Transmission, route *routing.Request) (domain.SendDecision, error) {
	if err := actor.Validate(); err != nil {
		return domain.SendDecision{}, err
	}
	if err := domain.Token(string(input.Operation)); err != nil {
		return domain.SendDecision{}, err
	}
	if err := input.Credential.Validate(); err != nil {
		return domain.SendDecision{}, err
	}
	if err := input.Connection.Validate(); err != nil {
		return domain.SendDecision{}, err
	}
	if input.Now.IsZero() || input.EncodedFrameBytes < 1 || input.EncodedFrameBytes > domain.MaxFrameBytes {
		return domain.SendDecision{}, domain.ErrInvalid
	}
	return transaction(ctx, s, func(tx *sql.Tx) (domain.SendDecision, error) {
		op, err := readOperation(ctx, tx, input.Operation)
		if err != nil {
			return domain.SendDecision{}, err
		}
		auth, err := authorizeOperation(ctx, tx, actor, op, domain.TaskDispatch)
		if err != nil {
			return domain.SendDecision{}, err
		}
		if op.view.Delivery != domain.Prepared {
			// Dispatch authorization exposes correlation/delivery, never cached results.
			op.view.Observation = nil
			return domain.SendDecision{Kind: domain.ObserveExisting, Operation: op.view}, nil
		}
		if route == nil {
			return domain.SendDecision{}, domain.Reject(domain.Forbidden)
		}
		decision, err := reserveTransmission(ctx, tx, input, op, auth)
		if err != nil {
			return decision, err
		}
		if err = validateRoutingAdmission(*route, decision.Operation.Correlation, decision.Request); err != nil {
			return domain.SendDecision{}, err
		}
		if err = s.acquireRouting(ctx, tx, *route); err != nil {
			return domain.SendDecision{}, err
		}
		return decision, nil
	})
}

func reserveTransmission(ctx context.Context, tx *sql.Tx, input domain.Transmission, op storedOperation, auth domain.Authorization) (domain.SendDecision, error) {
	if op.view.Cancellation != "" {
		return domain.SendDecision{}, domain.Reject(domain.Conflict)
	}
	if !input.Now.Before(op.view.ExpiresAt) {
		return domain.SendDecision{}, domain.Reject(domain.Expired)
	}
	if err := validateAdmissionDestination(ctx, tx, input, op.view.Correlation); err != nil {
		return domain.SendDecision{}, err
	}
	request, err := decode[domain.FrozenRequest](op.request)
	if err != nil {
		return domain.SendDecision{}, err
	}
	if err = validateFrozenRequest(op.view.Correlation, request); err != nil {
		return domain.SendDecision{}, err
	}
	if err = validateOptionsAgainstRequest(op, request); err != nil {
		return domain.SendDecision{}, err
	}
	if !auth.Grant.Ceiling.Allows(request) {
		return domain.SendDecision{}, domain.Reject(domain.Forbidden)
	}
	var global, device int
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*),COALESCE(SUM(CASE WHEN device=? THEN 1 ELSE 0 END),0) FROM operations WHERE reserved=1", input.Credential.Device).Scan(&global, &device); err != nil {
		return domain.SendDecision{}, err
	}
	if global >= domain.MaxGlobalReservations || device >= domain.MaxDeviceReservations {
		return domain.SendDecision{}, domain.Reject(domain.ResourceLimit)
	}
	if _, err = tx.ExecContext(ctx, "UPDATE operations SET state=?,reserved=1 WHERE id=?", domain.PossibleSend, input.Operation); err != nil {
		return domain.SendDecision{}, err
	}
	op.view.Delivery = domain.PossibleSend
	op.view.Reserved = true
	return domain.SendDecision{Kind: domain.SendOnce, Operation: op.view, Request: request}, nil
}

func validateFrozenRequest(c domain.Correlation, r domain.FrozenRequest) error {
	digest, err := domain.RequestDigest(c, r)
	if err != nil {
		// These values came from persisted prepared evidence, not caller input.
		return domain.Reject(domain.EvidenceInvalid)
	}
	if digest != c.RequestDigest || domain.Hash([]byte(r.Brief)) != c.BriefDigest {
		return domain.Reject(domain.EvidenceInvalid)
	}
	return nil
}

func (s *Store) GetOperation(ctx context.Context, actor domain.Actor, id domain.OperationID) (domain.OperationView, error) {
	if err := actor.Validate(); err != nil {
		return domain.OperationView{}, err
	}
	if err := domain.Token(string(id)); err != nil {
		return domain.OperationView{}, err
	}
	return transaction(ctx, s, func(tx *sql.Tx) (domain.OperationView, error) {
		op, err := readOperation(ctx, tx, id)
		if err != nil {
			return domain.OperationView{}, err
		}
		if _, err = authorizeOperation(ctx, tx, actor, op, domain.TaskRead); err != nil {
			return domain.OperationView{}, err
		}
		return op.view, nil
	})
}

func (s *Store) ExpireUnsent(ctx context.Context, now time.Time) (domain.ExpirySummary, error) {
	if err := s.requireAdmin(ctx); err != nil {
		return domain.ExpirySummary{}, err
	}
	if now.IsZero() {
		return domain.ExpirySummary{}, domain.ErrInvalid
	}
	return transaction(ctx, s, func(tx *sql.Tx) (domain.ExpirySummary, error) {
		var summary domain.ExpirySummary
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*),COALESCE(SUM(length(request)),0) FROM operations WHERE state=? AND expires<=?", domain.Prepared, now.UTC().Format(timestampLayout)).Scan(&summary.Count, &summary.RemovedBytes); err != nil {
			return summary, err
		}
		_, err := tx.ExecContext(ctx, "UPDATE operations SET state=?,request=NULL WHERE state=? AND expires<=?", domain.ExpiredUnsent, domain.Prepared, now.UTC().Format(timestampLayout))
		return summary, err
	})
}

func validateObservation(input domain.ValidatedObservation) error {
	for _, err := range []error{input.Correlation.Validate(), input.Connection.Validate(), input.Credential.Validate(), input.Observation.Validate(input.Now)} {
		if err != nil {
			return err
		}
	}
	if input.Credential.Device != input.Correlation.Destination.Device {
		return domain.Reject(domain.EvidenceInvalid)
	}
	return nil
}

func (s *Store) RecordObservation(ctx context.Context, input domain.ValidatedObservation) error {
	_, err := s.ApplyResolution(ctx, domain.ValidatedResolution{ValidatedObservation: input})
	return err
}

func (s *Store) ApplyResolution(ctx context.Context, input domain.ValidatedResolution) (domain.OperationView, error) {
	if err := validateObservation(input.ValidatedObservation); err != nil {
		return domain.OperationView{}, err
	}
	return transaction(ctx, s, func(tx *sql.Tx) (domain.OperationView, error) {
		if _, err := checkConnection(ctx, tx, input.Credential, input.Connection, input.Now); err != nil {
			return domain.OperationView{}, err
		}
		op, err := readOperation(ctx, tx, input.Correlation.Operation)
		if err != nil {
			return domain.OperationView{}, err
		}
		if op.view.Correlation != input.Correlation || op.view.Delivery == domain.Prepared || op.view.Delivery == domain.ExpiredUnsent {
			return domain.OperationView{}, domain.Reject(domain.EvidenceInvalid)
		}
		if op.view.Observation != nil && input.Observation.ObservedAt.Before(op.view.Observation.ObservedAt) {
			return domain.OperationView{}, domain.Reject(domain.Conflict)
		}
		return applyObservation(ctx, tx, op, input.Observation, input.DurableRequest)
	})
}

func applyObservation(ctx context.Context, tx *sql.Tx, op storedOperation, observation domain.DelegateObservation, durable bool) (domain.OperationView, error) {
	observation = preserveImmutableObservation(op.view.Observation, observation)
	if err := checkObservationContinuity(op.view.Observation, observation); err != nil {
		return domain.OperationView{}, err
	}
	if op.view.Delivery == domain.Resolved && observation.Kind != domain.Terminal && observation.Kind != domain.Refused {
		return domain.OperationView{}, domain.Reject(domain.Conflict)
	}
	if observation.Kind == domain.Terminal || observation.Kind == domain.Refused {
		op.view.Reserved = false
		op.view.Delivery = domain.Resolved
		durable = true
	}
	if durable && observation.Kind == domain.Unknown {
		return domain.OperationView{}, domain.Reject(domain.EvidenceInvalid)
	}
	data, err := encode(observation)
	if err != nil {
		return domain.OperationView{}, err
	}
	if durable {
		op.request = nil
	}
	_, err = tx.ExecContext(ctx, "UPDATE operations SET state=?,reserved=?,request=?,observation=? WHERE id=?", op.view.Delivery, op.view.Reserved, op.request, data, op.view.Correlation.Operation)
	op.view.Observation = &observation
	return op.view, err
}

func preserveImmutableObservation(previous *domain.DelegateObservation, next domain.DelegateObservation) domain.DelegateObservation {
	if previous == nil {
		return next
	}
	if next.SpecDigest == (domain.Digest{}) && (next.Kind == domain.Unknown || next.Kind == domain.Refused) {
		next.SpecDigest = previous.SpecDigest
	}
	if next.Kind == domain.Unknown && next.Result == nil {
		next.Result = previous.Result
	}
	if next.Kind == domain.Terminal && next.Closure == nil {
		next.Closure = previous.Closure
	}
	if next.Kind == domain.Terminal && next.ConfirmedStop == nil {
		next.ConfirmedStop = previous.ConfirmedStop
	}
	return next
}

func checkObservationContinuity(previous *domain.DelegateObservation, next domain.DelegateObservation) error {
	if previous == nil {
		return nil
	}
	if next.ObservedAt.Before(previous.ObservedAt) {
		return domain.Reject(domain.Conflict)
	}
	if previous.Kind == domain.Terminal || previous.Kind == domain.Refused {
		if next.Kind != previous.Kind {
			return domain.Reject(domain.Conflict)
		}
	}
	if previous.SpecDigest != (domain.Digest{}) && previous.SpecDigest != next.SpecDigest {
		return domain.Reject(domain.Conflict)
	}
	if previous.Result != nil && (next.Result == nil || *previous.Result != *next.Result) {
		return domain.Reject(domain.Conflict)
	}
	return checkClosureContinuity(previous, next)
}

func checkClosureContinuity(previous *domain.DelegateObservation, next domain.DelegateObservation) error {
	if previous.Closure != nil && (next.Closure == nil || *previous.Closure != *next.Closure) {
		return domain.Reject(domain.Conflict)
	}
	if previous.ConfirmedStop != nil && (next.ConfirmedStop == nil || *previous.ConfirmedStop != *next.ConfirmedStop) {
		return domain.Reject(domain.Conflict)
	}
	return nil
}

func (s *Store) BindCancellation(ctx context.Context, actor domain.Actor, id domain.OperationID, cancellation domain.CancellationID) (domain.CancellationBinding, error) {
	if err := actor.Validate(); err != nil {
		return domain.CancellationBinding{}, err
	}
	if err := domain.Token(string(id)); err != nil {
		return domain.CancellationBinding{}, err
	}
	if err := cancellation.Validate(); err != nil {
		return domain.CancellationBinding{}, err
	}
	return transaction(ctx, s, func(tx *sql.Tx) (domain.CancellationBinding, error) {
		op, err := readOperation(ctx, tx, id)
		if err != nil {
			return domain.CancellationBinding{}, err
		}
		if _, err = authorizeOperation(ctx, tx, actor, op, domain.TaskCancel); err != nil {
			return domain.CancellationBinding{}, err
		}
		if op.view.Cancellation != "" && op.view.Cancellation != cancellation {
			return domain.CancellationBinding{}, domain.Reject(domain.Conflict)
		}
		_, err = tx.ExecContext(ctx, "UPDATE operations SET cancellation=? WHERE id=?", cancellation, id)
		return domain.CancellationBinding{Operation: id, Cancellation: cancellation, Correlation: op.view.Correlation, SpecDigest: knownSpecDigest(op), DefinitelyUnsent: op.view.Delivery == domain.Prepared || op.view.Delivery == domain.ExpiredUnsent}, err
	})
}
