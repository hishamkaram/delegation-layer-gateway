package registry

import (
	"bytes"
	"context"
	"database/sql"
	"errors"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

type importSlot struct {
	known       *administrativeRow
	correlation *domain.Correlation
	options     domain.ExecutionOptions
}

type importedIdentityEntry struct {
	Receipt *domain.NativeTaskReceipt
	Refusal *domain.NamespaceRefusal
}

func importedPageHeader(p domain.ImportedInventoryPage) domain.ValidatedInventoryPage {
	return domain.ValidatedInventoryPage{Destination: p.Destination, Generation: p.Generation, Cursor: p.Cursor, NextCursor: p.NextCursor, Membership: p.Membership, Now: p.Now, CompletenessReceipt: p.CompletenessReceipt}
}

func validateImportedPage(p domain.ImportedInventoryPage) error {
	if err := validateInventoryPage(importedPageHeader(p)); err != nil {
		return err
	}
	if p.Credential.Device != p.Destination.Device || p.Credential.Validate() != nil || p.Connection.Validate() != nil {
		return domain.ErrInvalid
	}
	previous := p.Cursor
	for _, e := range p.Entries {
		task, err := validateImportedEntry(e, p)
		if err != nil {
			return err
		}
		if string(task) <= previous {
			return domain.ErrInvalid
		}
		previous = string(task)
	}
	if len(p.Entries) > domain.MaxPageLimit || p.NextCursor != "" && (len(p.Entries) == 0 || p.NextCursor != previous) {
		return domain.ErrInvalid
	}
	return nil
}

func validateImportedEntry(e domain.ImportedInventoryEntry, p domain.ImportedInventoryPage) (domain.TaskID, error) {
	if (e.Existing == nil) == (e.Refusal == nil) {
		return "", domain.ErrInvalid
	}
	if e.Refusal != nil {
		if e.Refusal.Task.Validate() != nil {
			return "", domain.ErrInvalid
		}
		if e.Refusal.Origin != nil && e.Refusal.Origin.Validate() != nil {
			return "", domain.ErrInvalid
		}
		return e.Refusal.Task, nil
	}
	r := e.Existing.Receipt
	o := e.Existing.Observation
	if r.Validate() != nil || o.Validate(p.Now) != nil || o.Kind != domain.Existing || r.Binding.Context.Root != p.Destination.Root || o.SpecDigest != r.Binding.SpecDigest {
		return "", domain.ErrInvalid
	}
	return r.Binding.Task, nil
}

func importedPageDigest(p domain.ImportedInventoryPage) (domain.Digest, error) {
	entries := make([]importedIdentityEntry, 0, len(p.Entries))
	for _, e := range p.Entries {
		v := importedIdentityEntry{Refusal: e.Refusal}
		if e.Existing != nil {
			r := e.Existing.Receipt
			v.Receipt = &r
		}
		entries = append(entries, v)
	}
	identity := struct {
		Header  inventoryIdentityRecord
		Entries []importedIdentityEntry
	}{inventoryIdentity(importedPageHeader(p)), entries}
	b, err := encode(identity)
	return domain.Hash(b), err
}

func (s *Store) ApplyImportedInventoryPage(ctx context.Context, p domain.ImportedInventoryPage) (domain.InventoryApplyResult, error) {
	if err := s.requireAdmin(ctx); err != nil {
		return domain.InventoryApplyResult{}, err
	}
	if err := validateImportedPage(p); err != nil {
		return domain.InventoryApplyResult{}, err
	}
	digest, err := importedPageDigest(p)
	if err != nil {
		return domain.InventoryApplyResult{}, err
	}
	return transaction(ctx, s, func(tx *sql.Tx) (domain.InventoryApplyResult, error) { return applyImportedPage(ctx, tx, p, digest) })
}

func applyImportedPage(ctx context.Context, tx *sql.Tx, p domain.ImportedInventoryPage, digest domain.Digest) (domain.InventoryApplyResult, error) {
	var result domain.InventoryApplyResult
	session, state, err := importedPageState(ctx, tx, p)
	if err != nil {
		return result, err
	}
	replay, err := importedPageReplay(ctx, tx, p, digest)
	if err != nil {
		return result, err
	}
	if !replay {
		if state.finished || state.cursor != p.Cursor || state.started && !bytes.Equal(state.membership, p.Membership[:]) {
			return result, domain.Reject(domain.Conflict)
		}
		if err = importCanonicalEntries(ctx, tx, p, session.kind); err != nil {
			return result, err
		}
		if err = recordImportedPage(ctx, tx, p, digest); err != nil {
			return result, err
		}
	}
	if _, err = completeFinalPage(ctx, tx, importedPageHeader(p)); err != nil {
		return result, err
	}
	result.CanonicalComplete = p.CompletenessReceipt != nil
	result.MissingMappings, err = missingDestinationMappings(ctx, tx, p.Destination)
	return result, err
}

func importedPageState(ctx context.Context, tx *sql.Tx, p domain.ImportedInventoryPage) (recoveryState, inventoryState, error) {
	if err := activeRecovery(ctx, tx, p.Destination.Recovery, true); err != nil {
		return recoveryState{}, inventoryState{}, err
	}
	credential, err := checkConnection(ctx, tx, p.Credential, p.Connection, p.Now)
	if err != nil {
		return recoveryState{}, inventoryState{}, err
	}
	session, err := readRecovery(ctx, tx, p.Destination.Recovery)
	if err != nil {
		return session, inventoryState{}, err
	}
	if session.kind == domain.RootRecovery && credential.Mode != domain.Regular {
		return session, inventoryState{}, domain.Reject(domain.Forbidden)
	}
	state, err := readInventoryState(ctx, tx, p.Destination)
	if err != nil {
		return session, state, err
	}
	if len(state.barrier) != len(domain.Digest{}) || state.generation != p.Generation {
		return session, state, domain.Reject(domain.Conflict)
	}
	return session, state, nil
}

func importedPageReplay(ctx context.Context, tx *sql.Tx, p domain.ImportedInventoryPage, digest domain.Digest) (bool, error) {
	var prior []byte
	err := tx.QueryRowContext(ctx, "SELECT digest FROM inventory_pages WHERE recovery=? AND device=? AND root_guard=? AND cursor=?", p.Destination.Recovery, p.Destination.Device, p.Destination.Root, p.Cursor).Scan(&prior)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !bytes.Equal(prior, digest[:]) {
		return false, domain.Reject(domain.Conflict)
	}
	return true, nil
}

func recordImportedPage(ctx context.Context, tx *sql.Tx, p domain.ImportedInventoryPage, digest domain.Digest) error {
	if _, err := tx.ExecContext(ctx, "INSERT INTO inventory_pages(recovery,device,root_guard,cursor,digest) VALUES(?,?,?,?,?)", p.Destination.Recovery, p.Destination.Device, p.Destination.Root, p.Cursor, digest[:]); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, "UPDATE recovery_destinations SET membership=?,cursor=?,started=1,finished=? WHERE recovery=? AND device=? AND root_guard=?", p.Membership[:], p.NextCursor, p.NextCursor == "", p.Destination.Recovery, p.Destination.Device, p.Destination.Root)
	return err
}

func importCanonicalEntries(ctx context.Context, tx *sql.Tx, p domain.ImportedInventoryPage, kind domain.RecoveryKind) error {
	var gateway domain.GatewayID
	if err := tx.QueryRowContext(ctx, "SELECT gateway FROM settings WHERE id=1").Scan(&gateway); err != nil {
		return err
	}
	slots, err := prepareImportSlots(ctx, tx, p, gateway, kind)
	if err != nil {
		return err
	}
	if err = classifyImportSlots(ctx, tx, p, gateway, slots); err != nil {
		return err
	}
	for i, e := range p.Entries {
		if e.Refusal != nil {
			err = applyNamespaceRefusal(ctx, tx, p, *e.Refusal)
		} else if slots[i].known != nil {
			err = hydrateKnownReceipt(ctx, tx, *slots[i].known, *e.Existing)
		} else {
			err = insertCanonicalTask(ctx, tx, p, *e.Existing, slots[i])
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func prepareImportSlots(ctx context.Context, tx *sql.Tx, p domain.ImportedInventoryPage, gateway domain.GatewayID, kind domain.RecoveryKind) ([]importSlot, error) {
	slots := make([]importSlot, len(p.Entries))
	if kind == domain.RootRecovery && len(p.Entries) != 0 {
		return nil, domain.Reject(domain.EvidenceInvalid)
	}
	seen := make(map[domain.OperationID]domain.TaskID, len(p.Entries))
	for i, e := range p.Entries {
		if err := checkPageOriginIdentity(e, seen); err != nil {
			return nil, err
		}
		row, err := prepareImportSlot(ctx, tx, p, e, gateway)
		if err != nil {
			return nil, err
		}
		slots[i].known = row
	}
	return slots, nil
}

func prepareImportSlot(ctx context.Context, tx *sql.Tx, p domain.ImportedInventoryPage, entry domain.ImportedInventoryEntry, gateway domain.GatewayID) (*administrativeRow, error) {
	if entry.Existing == nil {
		if entry.Refusal.Origin != nil && entry.Refusal.Origin.Gateway != gateway {
			return nil, domain.Reject(domain.EvidenceInvalid)
		}
		return nil, nil
	}
	r := entry.Existing.Receipt
	if r.Binding.Origin.Gateway != gateway {
		return nil, domain.Reject(domain.EvidenceInvalid)
	}
	key := domain.NativeTaskKey{Device: p.Destination.Device, Root: p.Destination.Root, Task: r.Binding.Task}
	if err := checkPhysicalOrigin(ctx, tx, key, r.Binding.Origin.Operation); err != nil {
		return nil, err
	}
	row, err := readAdministrativeTask(ctx, tx, key)
	if hasCode(err, domain.NotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err = validateKnownReceipt(ctx, tx, row, r); err != nil {
		return nil, err
	}
	return &row, nil
}

func checkPageOriginIdentity(entry domain.ImportedInventoryEntry, seen map[domain.OperationID]domain.TaskID) error {
	var origin *domain.TaskOrigin
	var task domain.TaskID
	if entry.Existing != nil {
		origin = &entry.Existing.Receipt.Binding.Origin
		task = entry.Existing.Receipt.Binding.Task
	} else if entry.Refusal != nil {
		origin = entry.Refusal.Origin
		task = entry.Refusal.Task
	}
	if origin == nil {
		return nil
	}
	if prior, ok := seen[origin.Operation]; ok && prior != task {
		return domain.Reject(domain.EvidenceInvalid)
	}
	seen[origin.Operation] = task
	return nil
}

func hasCode(err error, code domain.ErrorCode) bool {
	var classified *domain.Error
	return errors.As(err, &classified) && classified.Code == code
}

// One alias stream per distinct context, at most one candidate plus page-sized
// match slots retained. Closing the reader precedes every write.
func classifyImportSlots(ctx context.Context, tx *sql.Tx, p domain.ImportedInventoryPage, gateway domain.GatewayID, slots []importSlot) error {
	contexts := make(map[domain.ContextBinding][]int)
	for i, e := range p.Entries {
		if e.Existing != nil && slots[i].known == nil {
			c := e.Existing.Receipt.Binding.Context
			contexts[c] = append(contexts[c], i)
		}
	}
	for context, indices := range contexts {
		if err := classifyImportContext(ctx, tx, p, gateway, slots, context, indices); err != nil {
			return err
		}
	}
	return nil
}

func classifyImportContext(ctx context.Context, tx *sql.Tx, p domain.ImportedInventoryPage, gateway domain.GatewayID, slots []importSlot, binding domain.ContextBinding, indices []int) (err error) {
	rows, err := tx.QueryContext(ctx, "SELECT alias FROM projects WHERE device=? AND root_guard=? AND project_guard=? ORDER BY alias", p.Destination.Device, binding.Root, binding.Project)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, rows.Close()) }()
	for rows.Next() {
		candidate := domain.ProjectRegistration{Destination: domain.Destination{Device: p.Destination.Device}, Context: binding}
		if err = rows.Scan(&candidate.Destination.Project); err != nil {
			return err
		}
		for _, i := range indices {
			c, o, matched, matchErr := domain.AttributeNativeReceipt(gateway, p.Destination.Device, candidate, p.Entries[i].Existing.Receipt)
			if matchErr != nil {
				return matchErr
			}
			if !matched {
				continue
			}
			if slots[i].correlation != nil {
				return domain.Reject(domain.EvidenceInvalid)
			}
			slots[i].correlation = &c
			slots[i].options = o
		}
	}
	return rows.Err()
}
