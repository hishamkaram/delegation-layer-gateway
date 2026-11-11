package registry

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

func verifyRoutingSchema(ctx context.Context, tx *sql.Tx) (err error) {
	for _, query := range []string{"SELECT device,credential,generation,boot,barrier,digest,blocked,claimed FROM routing_peers LIMIT 0", "SELECT device,connection_boot,connection_counter,request,process_boot,credential,call,protected,scan,state FROM routing_permits LIMIT 0", "SELECT recovery,digest FROM routing_rosters LIMIT 0", "SELECT recovery,device,covered FROM routing_roster_devices LIMIT 0"} {
		if err = verifyRoutingColumns(ctx, tx, query); err != nil {
			return err
		}
	}
	return nil
}

func verifyRoutingConstraints(ctx context.Context, tx *sql.Tx) error {
	if err := verifyRoutingDefinition(ctx, tx, "table", "routing_permits", "CREATE TABLE routing_permits "+routingPermitDefinition); err != nil {
		return err
	}
	return verifyRoutingDefinition(ctx, tx, "index", "routing_permits_active", routingActiveIndex)
}

func verifyRoutingDefinition(ctx context.Context, tx *sql.Tx, kind, name, expected string) error {
	var actual string
	if err := tx.QueryRowContext(ctx, "SELECT sql FROM sqlite_schema WHERE type=? AND name=?", kind, name).Scan(&actual); err != nil {
		return err
	}
	// ALTER TABLE preserves the declaration but quotes the new table name.
	actual = strings.Replace(actual, `CREATE TABLE "routing_permits"`, "CREATE TABLE routing_permits", 1)
	if strings.Join(strings.Fields(actual), " ") != strings.Join(strings.Fields(expected), " ") {
		return domain.Reject(domain.Conflict)
	}
	return nil
}

func verifyRoutingColumns(ctx context.Context, tx *sql.Tx, query string) (err error) {
	rows, err := tx.QueryContext(ctx, query)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, rows.Close()) }()
	return rows.Err()
}
