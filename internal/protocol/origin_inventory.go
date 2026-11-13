package protocol

// OriginInventoryReport is root-wide frozen attribution, not a project alias listing.
// Local CLI context tokens are never part of this wire contract.
type OriginInventoryReport struct {
	Entries             []OriginInventoryEntry `json:"entries"`
	NextCursor          string                 `json:"next_cursor,omitempty"`
	Complete            bool                   `json:"complete"`
	MembershipSHA256    string                 `json:"membership_sha256"`
	CompletenessReceipt string                 `json:"completeness_receipt,omitempty"`
}

type OriginInventoryEntry struct {
	TaskID      string            `json:"task_id"`
	Resolution  string            `json:"resolution"`
	Origin      *Origin           `json:"origin,omitempty"`
	SpecSHA256  string            `json:"spec_sha256,omitempty"`
	BriefSHA256 string            `json:"brief_sha256,omitempty"`
	Receipt     *InventoryReceipt `json:"receipt,omitempty"`
}

type InventoryReceipt struct {
	Task             TaskBinding               `json:"task"`
	ExecutionOptions InventoryExecutionOptions `json:"execution_options"`
	BriefSHA256      string                    `json:"brief_sha256"`
}

// Exact nanoseconds preserve historical options that cannot be represented as
// whole seconds. Recovery must not round them into a different request digest.
type InventoryExecutionOptions struct {
	Provider          string    `json:"provider"`
	Permission        string    `json:"permission"`
	BudgetNanoseconds int64     `json:"budget_nanoseconds"`
	Model             Selection `json:"model"`
	Effort            Selection `json:"effort"`
}

func (o InventoryExecutionOptions) Validate() error {
	if !identifier(o.Provider) || o.BudgetNanoseconds <= 0 || o.Model.Validate() != nil || o.Effort.Validate() != nil {
		return ErrInvalid
	}
	if o.Permission != "read-only" && o.Permission != "workspace-write" && o.Permission != "danger-full-access" {
		return ErrInvalid
	}
	return nil
}

func (r InventoryReceipt) Validate() error {
	if r.Task.Validate(true) != nil || r.ExecutionOptions.Validate() != nil || !lowerHex(r.BriefSHA256, 64) {
		return ErrInvalid
	}
	return nil
}

func inventoryOriginValid(origin Origin) bool {
	return identifier(origin.GatewayID) && identifier(origin.AdmissionGeneration) && identifier(origin.OperationID) && identifier(origin.PrincipalRef) && lowerHex(origin.RequestSHA256, 64)
}

func (e OriginInventoryEntry) Validate() error {
	if !lowerHex(e.TaskID, 32) || (e.SpecSHA256 != "" && !lowerHex(e.SpecSHA256, 64)) || (e.BriefSHA256 != "" && !lowerHex(e.BriefSHA256, 64)) {
		return ErrInvalid
	}
	if e.Origin != nil && !inventoryOriginValid(*e.Origin) {
		return ErrInvalid
	}
	if e.Resolution == "permanently_refused" {
		if e.Receipt != nil {
			return ErrInvalid
		}
		return nil
	}
	if e.Resolution != "existing" || e.Origin == nil || e.Receipt == nil {
		return ErrInvalid
	}
	return e.validateReceipt()
}

func (e OriginInventoryEntry) validateReceipt() error {
	r := e.Receipt
	if r.Validate() != nil || r.Task.TaskID != e.TaskID || r.Task.Origin != *e.Origin || r.Task.SpecSHA256 != e.SpecSHA256 || r.BriefSHA256 != e.BriefSHA256 {
		return ErrInvalid
	}
	return nil
}

func (i OriginInventoryReport) Validate() error {
	if len(i.Entries) > 100 || !lowerHex(i.MembershipSHA256, 64) {
		return ErrInvalid
	}
	previous := ""
	for _, entry := range i.Entries {
		if entry.Validate() != nil || entry.TaskID <= previous {
			return ErrInvalid
		}
		previous = entry.TaskID
	}
	if i.Complete {
		if i.NextCursor != "" || !lowerHex(i.CompletenessReceipt, 64) {
			return ErrInvalid
		}
	} else if len(i.Entries) == 0 || i.NextCursor != previous || i.CompletenessReceipt != "" {
		return ErrInvalid
	}
	return nil
}

func (i OriginInventoryReport) ValidateFor(request OriginInventoryRequest) error {
	if i.Validate() != nil || !inventoryRequestValid(request) || len(i.Entries) > request.Limit {
		return ErrInvalid
	}
	for _, entry := range i.Entries {
		if entry.TaskID <= request.Cursor || (entry.Origin != nil && entry.Origin.GatewayID != request.GatewayID) {
			return ErrInvalid
		}
		if entry.Receipt != nil && entry.Receipt.Task.Context.Root != request.ExpectedRoot {
			return ErrInvalid
		}
	}
	return nil
}

func inventoryRequestValid(request OriginInventoryRequest) bool {
	return identifier(request.GatewayID) && identifier(request.Generation) && guardToken(request.ExpectedRoot) && request.Limit >= 1 && request.Limit <= 100 && (request.Cursor == "" || lowerHex(request.Cursor, 32))
}
