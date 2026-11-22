package protocol

import (
	"encoding/base64"
	"path"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	FeatureFilesystem          = "workspace-filesystem-v1"
	FeatureNativeOptions       = "native-execution-options-v1"
	FeatureProjectHashGuard    = "project-token-sha256-v1"
	FeatureGuardedContinuation = "guarded-continuation-v1"
	FeatureScopedModels        = "scoped-model-discovery-v1"
	FeatureOriginBinding       = "origin-binding-v1"
	SharedTempScope            = "system-shared-temp"
	UserTempScope              = "system-user-temp"
	MaxDirectoryEntries        = 100
	MaxFileReadBytes           = 65536
)

// FileSelection addresses a saved local approval or an automatic OS temp scope.
// It never accepts a local absolute path, executable or Native context token.
// Base64 preserves Unix names that JSON cannot represent losslessly.
type FileSelection struct {
	ScopeID            string `json:"scope_id"`
	RelativePath       string `json:"relative_path,omitempty"`
	RelativePathBase64 string `json:"relative_path_base64,omitempty"`
}

func (s FileSelection) Path() (string, error) {
	if !identifier(s.ScopeID) || (s.RelativePath != "" && s.RelativePathBase64 != "") {
		return "", ErrInvalid
	}
	value, err := s.decodedPath()
	if err != nil {
		return "", err
	}
	if value == "" {
		value = "."
	}
	if !validRelativePath(value) {
		return "", ErrInvalid
	}
	return value, nil
}

func (s FileSelection) decodedPath() (string, error) {
	value := s.RelativePath
	if s.RelativePathBase64 != "" {
		if len(s.RelativePathBase64) > base64.StdEncoding.EncodedLen(4096) {
			return "", ErrInvalid
		}
		decoded, err := base64.StdEncoding.Strict().DecodeString(s.RelativePathBase64)
		if err != nil {
			return "", ErrInvalid
		}
		value = string(decoded)
	} else if !utf8.ValidString(value) {
		return "", ErrInvalid
	}
	return value, nil
}

func validRelativePath(value string) bool {
	if len(value) > 4096 || strings.ContainsRune(value, 0) || path.IsAbs(value) || path.Clean(value) != value {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if part == ".." || len(part) > 255 {
			return false
		}
	}
	return true
}

func (s FileSelection) Validate() error { _, err := s.Path(); return err }

type FilesystemRequest struct {
	Selection       FileSelection `json:"selection"`
	Cursor          string        `json:"cursor,omitempty"`
	Limit           int           `json:"limit,omitempty"`
	Offset          int64         `json:"offset,omitempty"`
	ExpectedVersion string        `json:"expected_version,omitempty"`
}

func (r FilesystemRequest) ValidateFor(operation Operation) error {
	if err := r.validateFields(operation); err != nil {
		return err
	}
	switch operation {
	case FilesystemScopes:
		return nil
	case ListDirectory:
		if r.Limit > MaxDirectoryEntries || r.Offset != 0 || r.ExpectedVersion != "" {
			return ErrInvalid
		}
	case ReadFile:
		if r.Limit > MaxFileReadBytes || r.Cursor != "" {
			return ErrInvalid
		}
	case InspectFile, InspectGit:
		return r.validateInspectionOptions()
	case ContextInspect, Admit, Continue, Resolve, ResumeExisting, FenceAbsent, Status, Collect, ResultChunk, Cancel,
		OriginBarrier, OriginInventory, OriginReopen, ResolveProject, SelectProject, ProviderModels:
		return ErrInvalid
	default:
		return ErrInvalid
	}
	return nil
}

func (r FilesystemRequest) validateInspectionOptions() error {
	if r.Limit != 0 || r.Offset != 0 || r.Cursor != "" || r.ExpectedVersion != "" {
		return ErrInvalid
	}
	return nil
}

func (r FilesystemRequest) validateFields(operation Operation) error {
	if operation == FilesystemScopes {
		if r != (FilesystemRequest{}) {
			return ErrInvalid
		}
		return nil
	}
	if r.Selection.Validate() != nil || len(r.Cursor) > 16384 || len(r.ExpectedVersion) > 256 || r.Offset < 0 || r.Limit < 0 {
		return ErrInvalid
	}
	return nil
}

// FilesystemResponse mirrors Native's typed read-only result. Relative names
// and requested bytes are response data; they must never enter diagnostics.
type FilesystemResponse struct {
	SchemaVersion int                     `json:"schema_version"`
	Operation     string                  `json:"operation"`
	ObservedAt    time.Time               `json:"observed_at"`
	List          *DirectoryPage          `json:"list,omitempty"`
	Read          *FileRange              `json:"read,omitempty"`
	Inspect       *FileInspection         `json:"inspect,omitempty"`
	Scopes        *FilesystemScopesResult `json:"scopes,omitempty"`
}

type FileEntry struct {
	Name               *string        `json:"name,omitempty"`
	NameBase64         string         `json:"name_base64"`
	RelativePath       *string        `json:"relative_path,omitempty"`
	RelativePathBase64 string         `json:"relative_path_base64"`
	Kind               string         `json:"kind"`
	Size               int64          `json:"size"`
	ModifiedAt         time.Time      `json:"modified_at"`
	Version            string         `json:"version"`
	Git                *GitInspection `json:"git,omitempty"`
}

type DirectoryPage struct {
	Entries    []FileEntry `json:"entries"`
	Version    string      `json:"version"`
	NextCursor string      `json:"next_cursor,omitempty"`
	EOF        bool        `json:"eof"`
}

type FileRange struct {
	DataBase64 string  `json:"data_base64"`
	Text       *string `json:"text,omitempty"`
	Offset     int64   `json:"offset"`
	NextOffset int64   `json:"next_offset"`
	EOF        bool    `json:"eof"`
	Version    string  `json:"version"`
}

type FileInspection struct {
	Entry FileEntry      `json:"entry"`
	Git   *GitInspection `json:"git,omitempty"`
}

type GitInspection struct {
	Marker             string  `json:"marker,omitempty"`
	MetadataPathBase64 string  `json:"metadata_path_base64,omitempty"`
	HEADBase64         string  `json:"head_base64,omitempty"`
	HEADShape          string  `json:"head_shape,omitempty"`
	Status             string  `json:"status"`
	Kind               string  `json:"kind,omitempty"`
	Reason             string  `json:"reason,omitempty"`
	HEAD               *string `json:"head,omitempty"`
}

type FilesystemScope struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
	Name string `json:"name"`
}

type FilesystemScopesResult struct {
	Scopes []FilesystemScope `json:"scopes"`
}

func (r FilesystemResponse) ValidateFor(operation Operation, request FilesystemRequest) error {
	if err := r.validateHeader(operation, request); err != nil {
		return err
	}
	switch operation {
	case ListDirectory:
		if r.Operation != "list" || r.List == nil {
			return ErrInvalid
		}
		return r.List.validate(request)
	case ReadFile:
		if r.Operation != "read" || r.Read == nil {
			return ErrInvalid
		}
		return r.Read.validate(request)
	case InspectFile, InspectGit:
		return r.validateInspection(operation)
	case FilesystemScopes:
		if r.Operation != "scopes" || r.Scopes == nil {
			return ErrInvalid
		}
		return r.Scopes.validate()
	case ContextInspect, Admit, Continue, Resolve, ResumeExisting, FenceAbsent, Status, Collect, ResultChunk, Cancel,
		OriginBarrier, OriginInventory, OriginReopen, ResolveProject, SelectProject, ProviderModels:
		return ErrInvalid
	default:
		return ErrInvalid
	}
}

func (r FilesystemResponse) validateHeader(operation Operation, request FilesystemRequest) error {
	if request.ValidateFor(operation) != nil || r.SchemaVersion != 1 || r.ObservedAt.IsZero() {
		return ErrInvalid
	}
	count := 0
	if r.List != nil {
		count++
	}
	if r.Read != nil {
		count++
	}
	if r.Inspect != nil {
		count++
	}
	if r.Scopes != nil {
		count++
	}
	if count != 1 {
		return ErrInvalid
	}
	return nil
}

func (r FilesystemResponse) validateInspection(operation Operation) error {
	expected := "inspect"
	if operation == InspectGit {
		expected = "git"
	}
	if r.Operation != expected || r.Inspect == nil || r.Inspect.Entry.validate() != nil {
		return ErrInvalid
	}
	if r.Inspect.Git != nil {
		return r.Inspect.Git.validate()
	}
	return nil
}

func (r FilesystemScopesResult) validate() error {
	if len(r.Scopes) > MaxWorkspaces+2 {
		return ErrInvalid
	}
	seen := make(map[string]bool)
	for _, s := range r.Scopes {
		if s.validate() != nil || seen[s.ID] {
			return ErrInvalid
		}
		seen[s.ID] = true
	}
	return nil
}

func (s FilesystemScope) validate() error {
	if !identifier(s.ID) || !identifier(s.Name) {
		return ErrInvalid
	}
	switch s.Kind {
	case "workspace", "user_temp", "shared_temp":
		return nil
	default:
		return ErrInvalid
	}
}

func (e FileEntry) validate() error {
	if e.validateName() != nil || e.validateRelativePath() != nil || e.Size < 0 || e.ModifiedAt.IsZero() || !validFileVersion(e.Version) {
		return ErrInvalid
	}
	switch e.Kind {
	case "file", "directory", "symlink", "fifo", "socket", "device", "other":
	default:
		return ErrInvalid
	}
	if e.Git != nil {
		return e.Git.validate()
	}
	return nil
}

func (e FileEntry) validateName() error {
	name, err := base64.StdEncoding.Strict().DecodeString(e.NameBase64)
	if err != nil || len(name) == 0 || len(name) > 255 || strings.ContainsAny(string(name), "\x00/") || !matchesOptionalText(e.Name, name) {
		return ErrInvalid
	}
	return nil
}

func (e FileEntry) validateRelativePath() error {
	selection := FileSelection{ScopeID: "scope", RelativePathBase64: e.RelativePathBase64}
	value, err := selection.Path()
	if err != nil || !matchesOptionalText(e.RelativePath, []byte(value)) {
		return ErrInvalid
	}
	return nil
}

func matchesOptionalText(text *string, data []byte) bool {
	return text == nil || (utf8.Valid(data) && *text == string(data))
}

func validFileVersion(version string) bool { return version != "" && len(version) <= 256 }

func (p DirectoryPage) validate(request FilesystemRequest) error {
	limit := request.Limit
	if limit == 0 {
		limit = MaxDirectoryEntries
	}
	if len(p.Entries) > limit || !validFileVersion(p.Version) || len(p.NextCursor) > 16384 || p.EOF != (p.NextCursor == "") {
		return ErrInvalid
	}
	seen := make(map[string]bool)
	for _, e := range p.Entries {
		if e.validate() != nil || seen[e.NameBase64] {
			return ErrInvalid
		}
		seen[e.NameBase64] = true
	}
	return nil
}

func (r FileRange) validate(request FilesystemRequest) error {
	limit := request.Limit
	if limit == 0 {
		limit = MaxFileReadBytes
	}
	if !r.matchesRequest(request, limit) {
		return ErrInvalid
	}
	data, err := base64.StdEncoding.Strict().DecodeString(r.DataBase64)
	if err != nil || len(data) > limit || r.NextOffset < r.Offset || r.NextOffset-r.Offset != int64(len(data)) || (!r.EOF && len(data) == 0) {
		return ErrInvalid
	}
	if !matchesOptionalText(r.Text, data) {
		return ErrInvalid
	}
	return nil
}

func (r FileRange) matchesRequest(request FilesystemRequest, limit int) bool {
	return len(r.DataBase64) <= base64.StdEncoding.EncodedLen(limit) && r.Offset == request.Offset && validFileVersion(r.Version) &&
		(request.ExpectedVersion == "" || request.ExpectedVersion == r.Version)
}

func (g GitInspection) validate() error {
	if g.validateKinds() != nil || g.validateMetadataPath() != nil || g.validateHEAD() != nil || len(g.Reason) > 128 {
		return ErrInvalid
	}
	return nil
}

func (g GitInspection) validateKinds() error {
	switch g.Marker {
	case "", "dot_git", "bare_layout":
	default:
		return ErrInvalid
	}
	switch g.HEADShape {
	case "", "symbolic", "detached", "malformed":
	default:
		return ErrInvalid
	}
	switch g.Status {
	case "candidate", "validated", "partial", "not_repository", "fault":
	default:
		return ErrInvalid
	}
	switch g.Kind {
	case "", "worktree", "linked_worktree", "bare":
	default:
		return ErrInvalid
	}
	return nil
}

func (g GitInspection) validateMetadataPath() error {
	if len(g.MetadataPathBase64) > base64.StdEncoding.EncodedLen(8193) {
		return ErrInvalid
	}
	if g.MetadataPathBase64 != "" {
		if _, err := base64.StdEncoding.Strict().DecodeString(g.MetadataPathBase64); err != nil {
			return ErrInvalid
		}
	}
	return nil
}

func (g GitInspection) validateHEAD() error {
	if len(g.HEADBase64) > base64.StdEncoding.EncodedLen(4096) {
		return ErrInvalid
	}
	if g.HEADBase64 != "" {
		data, err := base64.StdEncoding.Strict().DecodeString(g.HEADBase64)
		if err != nil || len(data) > 4096 {
			return ErrInvalid
		}
		if !matchesOptionalText(g.HEAD, data) {
			return ErrInvalid
		}
	}

	if g.HEAD != nil && len(*g.HEAD) > 4096 {
		return ErrInvalid
	}
	return nil
}
