package protocol

import (
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const ProviderModels Operation = "provider_models"

// ModelQuery is an explicit advisory Native discovery request. It is not part
// of admission and never determines whether an explicit model may be used.
type ModelQuery struct {
	Selection FileSelection `json:"selection"`
	Provider  string        `json:"provider"`
	Cursor    string        `json:"cursor,omitempty"`
	Limit     int           `json:"limit,omitempty"`
}

func (q ModelQuery) Validate() error {
	if (SelectionRequest{Selection: q.Selection}).Validate() != nil || !identifier(q.Provider) || len(q.Cursor) > 2048 || q.Limit < 0 || q.Limit > 100 {
		return ErrInvalid
	}
	return nil
}

type ModelFact struct {
	ID            string   `json:"id"`
	Name          string   `json:"name,omitempty"`
	Efforts       []string `json:"efforts"`
	DefaultEffort string   `json:"default_effort,omitempty"`
}

type ModelPage struct {
	Provider        string      `json:"provider"`
	ObservedAt      time.Time   `json:"observed_at"`
	Status          string      `json:"status"`
	ReasonCode      string      `json:"reason_code"`
	Source          string      `json:"source"`
	CatalogComplete bool        `json:"catalog_complete"`
	Version         string      `json:"version"`
	Models          []ModelFact `json:"models"`
	Efforts         []string    `json:"efforts"`
	NextCursor      string      `json:"next_cursor,omitempty"`
	EOF             bool        `json:"eof"`
}

func (p ModelPage) ValidateFor(q ModelQuery) error {
	if err := p.validateHeader(q); err != nil {
		return err
	}
	if err := p.validateMetadata(); err != nil {
		return err
	}
	seen := make(map[string]bool)
	for _, m := range p.Models {
		if m.validate() != nil || seen[m.ID] {
			return ErrInvalid
		}
		seen[m.ID] = true
	}
	return validateModelEfforts(p.Efforts)
}

func (p ModelPage) validateHeader(q ModelQuery) error {
	limit := q.Limit
	if limit == 0 {
		limit = 100
	}
	if q.Validate() != nil || p.Provider != q.Provider || p.ObservedAt.IsZero() || !lowerHex(p.Version, 64) || len(p.Models) > limit || len(p.Efforts) > 4096 || len(p.NextCursor) > 2048 || p.EOF != (p.NextCursor == "") {
		return ErrInvalid
	}
	return nil
}

func (p ModelPage) validateMetadata() error {
	switch p.Status {
	case "available", "partial", "blocked", "unavailable", "failed":
	default:
		return ErrInvalid
	}
	if !modelFactText(p.ReasonCode, false) || !selectionToken(p.Source) {
		return ErrInvalid
	}
	return nil
}

func (m ModelFact) validate() error {
	if !modelFactText(m.ID, false) || !modelFactText(m.Name, true) || len(m.Efforts) > 4096 || !modelFactText(m.DefaultEffort, true) {
		return ErrInvalid
	}
	return validateModelEfforts(m.Efforts)
}

func validateModelEfforts(efforts []string) error {
	for _, effort := range efforts {
		if !modelFactText(effort, false) {
			return ErrInvalid
		}
	}
	return nil
}

type ModelCursor struct {
	Version       int    `json:"version"`
	BindingSHA256 string `json:"binding_sha256"`
	CatalogSHA256 string `json:"catalog_sha256"`
	Next          int    `json:"next"`
}

func EncodeModelCursor(c ModelCursor) (string, error) {
	if c.Version != 1 || !lowerHex(c.BindingSHA256, 64) || !lowerHex(c.CatalogSHA256, 64) || (c.Next < 1 || c.Next > 4096) {
		return "", ErrInvalid
	}
	data, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func DecodeModelCursor(value, binding, version string) (ModelCursor, error) {
	var c ModelCursor
	if len(value) > 2048 {
		return c, ErrInvalid
	}
	data, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || DecodeStrict(data, &c, 1536) != nil || c.Version != 1 || c.BindingSHA256 != binding || c.CatalogSHA256 != version || (c.Next < 1 || c.Next > 4096) {
		return ModelCursor{}, ErrInvalid
	}
	return c, nil
}

// PageModelFacts paginates a complete bounded Native observation. Sorting is
// deterministic; cursors carry no authority and current approval is rechecked.
func PageModelFacts(facts []ModelFact, next int, limit int) ([]ModelFact, bool) {
	ordered := slices.Clone(facts)
	slices.SortFunc(ordered, func(a, b ModelFact) int { return strings.Compare(a.ID, b.ID) })
	if limit == 0 {
		limit = 100
	}
	start := min(max(0, next), len(ordered))
	end := min(len(ordered), start+limit)
	return ordered[start:end], end == len(ordered)
}

func modelFactText(value string, optional bool) bool {
	if value == "" {
		return optional
	}
	if len(value) > MaxFrameBytes || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
