package registry

import (
	"context"
	"database/sql"
)

const preparationCapacityIndex = `CREATE INDEX operations_preparations ON operations(owner,preparation_expires_ns) WHERE state='prepared' AND cancellation=''`

const preparationKeyIndex = `CREATE UNIQUE INDEX operations_preparation_key ON operations(owner,device,preparation_key) WHERE preparation_key IS NOT NULL`

const retainedBodiesIndex = `CREATE INDEX operations_retained_bodies ON operations(row_id) WHERE request IS NOT NULL`

const preparationSchema = retainedBodiesIndex + `;
` + preparationCapacityIndex + `;
` + preparationKeyIndex + `;
PRAGMA user_version=10;
`

func verifyPreparationSchema(ctx context.Context, tx *sql.Tx) error {
	if err := verifyRegistryQuery(ctx, tx, "SELECT preparation_key,preparation_expires_ns FROM operations LIMIT 0"); err != nil {
		return err
	}
	if err := verifyRoutingDefinition(ctx, tx, "index", "operations_preparations", preparationCapacityIndex); err != nil {
		return err
	}
	if err := verifyRoutingDefinition(ctx, tx, "index", "operations_preparation_key", preparationKeyIndex); err != nil {
		return err
	}
	return verifyRoutingDefinition(ctx, tx, "index", "operations_retained_bodies", retainedBodiesIndex)
}
