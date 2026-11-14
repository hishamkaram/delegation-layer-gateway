package registry

import (
	"context"
	"database/sql"
)

// The first pin is stored once in project_resolutions. owned_projects contains
// only references to that receipt and its derived existing project route.
const projectResolutionSchema = `
CREATE TABLE IF NOT EXISTS project_resolutions (
 request TEXT PRIMARY KEY,
 principal TEXT NOT NULL REFERENCES principals(id),
 device TEXT NOT NULL REFERENCES devices(id),
 root_guard TEXT NOT NULL,
 workspace_id TEXT NOT NULL,
 workspace_guard TEXT NOT NULL,
 selector_sha256 BLOB NOT NULL CHECK(length(selector_sha256)=32),
 pin BLOB,
 created TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS project_resolutions_device ON project_resolutions(device,request);
CREATE TABLE IF NOT EXISTS owned_projects (
 device TEXT NOT NULL,
 alias TEXT NOT NULL,
 request TEXT NOT NULL UNIQUE REFERENCES project_resolutions(request),
 PRIMARY KEY(device,alias),
 FOREIGN KEY(device,alias) REFERENCES projects(device,alias)
);
PRAGMA user_version=9;
`

func verifyProjectResolutionSchema(ctx context.Context, tx *sql.Tx) error {
	for _, query := range []string{
		"SELECT request,principal,device,root_guard,workspace_id,workspace_guard,selector_sha256,pin,created FROM project_resolutions LIMIT 0",
		"SELECT device,alias,request FROM owned_projects LIMIT 0",
	} {
		if err := verifyRegistryQuery(ctx, tx, query); err != nil {
			return err
		}
	}
	return nil
}
