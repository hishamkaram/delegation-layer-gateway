package registry

import (
	"context"
	"database/sql"
	"errors"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/routing"
)

func (s *Store) ListRoutingPermits(ctx context.Context, input routing.PermitPageRequest) (routing.PermitPage, error) {
	if err := s.requireAdmin(ctx); err != nil {
		return routing.PermitPage{}, err
	}
	if _, err := domain.PageLimit(input.Limit); err != nil {
		return routing.PermitPage{}, err
	}
	after := routing.PermitCursor{}
	if input.After != nil {
		after = *input.After
		if domain.CredentialToken(string(after.Device)) != nil || after.Connection.Validate() != nil || domain.RoutingToken(after.Request) != nil {
			return routing.PermitPage{}, domain.ErrInvalid
		}
	}
	return transaction(ctx, s, func(tx *sql.Tx) (routing.PermitPage, error) {
		return readRoutingPermits(ctx, tx, after, input.Limit)
	})
}

func readRoutingPermits(ctx context.Context, tx *sql.Tx, after routing.PermitCursor, limit int) (page routing.PermitPage, err error) {
	rows, err := tx.QueryContext(ctx, `SELECT device,connection_boot,connection_counter,request,process_boot,call,protected,scan FROM routing_permits WHERE state='active' AND (device,connection_boot,connection_counter,request)>(?,?,?,?) ORDER BY device,connection_boot,connection_counter,request LIMIT ?`, after.Device, after.Connection.BootEpoch, after.Connection.Counter, after.Request, limit+1)
	if err != nil {
		return page, err
	}
	defer func() { err = errors.Join(err, rows.Close()) }()
	for rows.Next() {
		var view routing.PermitView
		var cursor routing.PermitCursor
		var call []byte
		if err = rows.Scan(&view.Device, &cursor.Connection.BootEpoch, &cursor.Connection.Counter, &cursor.Request, &view.ProcessBoot, &call, &view.Protected, &view.Scan); err != nil {
			return page, err
		}
		view.Call, err = decode[protocol.ControlCall](call)
		if err != nil {
			return page, err
		}
		if view.Call.Validate() != nil || !routing.ValidProcessBoot(view.ProcessBoot) || domain.CredentialToken(string(view.Device)) != nil || routingGeneration(view.Call.Generation) != cursor.Connection || view.Call.RequestID != cursor.Request || view.Protected != view.Call.Operation.ProtectedControl() || view.Scan != view.Call.Operation.ScanConsumer() {
			return page, domain.Reject(domain.EvidenceInvalid)
		}
		if len(page.Items) == limit {
			return page, rows.Err()
		}
		page.Items = append(page.Items, view)
		cursor.Device = view.Device
		page.Next = &cursor
	}
	page.Next = nil
	return page, rows.Err()
}
