// Package observability accepts closed metadata events, never request bodies,
// provider output, native errors, secrets, paths or caller-defined labels.
package observability

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/instance"
)

const (
	MaxAuditBytes int64 = 100 << 20
	SegmentBytes  int64 = 10 << 20
	RetentionDays       = 7
)

var ErrUnavailable = errors.New("metadata_audit_unavailable")

type Code string

const (
	AuthenticationDenied       Code = "authentication_denied"
	DeviceCredentialDenied     Code = "device_credential_denied"
	EnrollmentIssued           Code = "enrollment_issued"
	DeviceConnected            Code = "device_connected"
	DeviceDisconnected         Code = "device_disconnected"
	CredentialRevoked          Code = "credential_revoked"
	OperationPrepared          Code = "operation_prepared"
	ControlSent                Code = "control_sent"
	ControlCompleted           Code = "control_completed"
	ControlUnknown             Code = "control_unknown"
	AuthorizationDenied        Code = "authorization_denied"
	ResourceDenied             Code = "resource_denied"
	RecoveryBlocked            Code = "recovery_blocked"
	ShutdownStarted            Code = "shutdown_started"
	MCPRequestStarted          Code = "mcp_request_started"
	MCPRequestCompleted        Code = "mcp_request_completed"
	MCPToolResponseReady       Code = "mcp_tool_response_ready"
	MCPToolErrorReady          Code = "mcp_tool_error_ready"
	EnrollmentRequestStarted   Code = "enrollment_request_started"
	EnrollmentRequestCompleted Code = "enrollment_request_completed"
	MetadataRequestStarted     Code = "metadata_request_started"
	MetadataRequestCompleted   Code = "metadata_request_completed"
	DeviceRequestStarted       Code = "device_request_started"
	DeviceRequestCompleted     Code = "device_request_completed"
	RenewalIssued              Code = "renewal_issued"
	RenewalUnavailable         Code = "renewal_unavailable"
)

func (c Code) valid() bool {
	for _, candidate := range metricCodes() {
		if c == candidate {
			return true
		}
	}
	return false
}

// CredentialIdentity is public certificate identity metadata. Its audit-only
// encoding is independent of the registry's persisted domain representation.
type CredentialIdentity struct {
	DeviceID   domain.DeviceID        `json:"device_id"`
	Epoch      domain.CredentialEpoch `json:"epoch"`
	Generation uint64                 `json:"generation"`
}

// Event contains only bounded identity metadata. Code is a closed enum; no
// free-text message or map can carry a prompt, payload or native diagnostic.
type Event struct {
	Code       Code               `json:"code"`
	Credential CredentialIdentity `json:"credential,omitzero"`
	Principal  domain.PrincipalID `json:"principal,omitempty"`
	Device     domain.DeviceID    `json:"device,omitempty"`
	Operation  domain.OperationID `json:"operation,omitempty"`
}
type record struct {
	At time.Time `json:"at"`
	Event
}

func (e Event) validate() bool {
	if !e.Code.valid() {
		return false
	}
	for _, value := range []string{string(e.Principal), string(e.Device), string(e.Operation)} {
		if value != "" && domain.Token(value) != nil {
			return false
		}
	}
	if e.Code == DeviceCredentialDenied {
		ref := domain.CredentialRef{Device: e.Credential.DeviceID, Epoch: e.Credential.Epoch, Generation: e.Credential.Generation}
		return ref.Validate() == nil && ref.Device == e.Device && e.Principal == "" && e.Operation == ""
	}
	return e.Credential == (CredentialIdentity{})
}

// Audit owns its private directory lease and serializes append/rotation. Record
// returns only after file Sync; callers must surface failure rather than assume
// an event was persisted. Retention discards complete oldest segments.
type Audit struct {
	mu        sync.Mutex
	directory string
	lease     *instance.Lease
	now       func() time.Time
	closed    bool
	lastDay   string
}

func Open(directory string, now func() time.Time) (*Audit, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || now == nil {
		return nil, ErrUnavailable
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return nil, ErrUnavailable
	}
	lease, err := instance.Acquire(filepath.Join(directory, ".audit.lock"))
	if err != nil {
		return nil, ErrUnavailable
	}
	a := &Audit{directory: directory, lease: lease, now: now}
	if _, err = a.segments(); err != nil {
		return nil, errors.Join(ErrUnavailable, lease.Close())
	}
	return a, nil
}

func (a *Audit) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil
	}
	a.closed = true
	return a.lease.Close()
}

func (a *Audit) Record(event Event) error {
	if !event.validate() {
		return ErrUnavailable
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return ErrUnavailable
	}
	now := a.now().UTC()
	if now.IsZero() {
		return ErrUnavailable
	}
	day := now.Format("20060102")
	if day < a.lastDay {
		return ErrUnavailable
	}
	a.lastDay = day
	data, err := json.Marshal(record{At: now, Event: event})
	if err != nil {
		return ErrUnavailable
	}
	data = append(data, '\n')
	segments, err := a.prune(now, int64(len(data)))
	if err != nil {
		return ErrUnavailable
	}
	path, err := a.appendPath(day, int64(len(data)), segments)
	if err != nil {
		return ErrUnavailable
	}
	return a.append(path, data)
}

type segment struct {
	name string
	size int64
	day  time.Time
}

func parseName(name string) (time.Time, bool) {
	if len(name) != len("audit-20060102-00.jsonl") || !strings.HasPrefix(name, "audit-") || !strings.HasSuffix(name, ".jsonl") || name[14] != '-' || name[15] < '0' || name[15] > '9' || name[16] < '0' || name[16] > '9' {
		return time.Time{}, false
	}
	day, err := time.Parse("20060102", name[6:14])
	return day, err == nil
}

func (a *Audit) segments() ([]segment, error) {
	entries, err := os.ReadDir(a.directory)
	if err != nil {
		return nil, err
	}
	result := make([]segment, 0, RetentionDays*10)
	for _, entry := range entries {
		day, valid := parseName(entry.Name())
		if !valid {
			if strings.HasPrefix(entry.Name(), "audit-") {
				return nil, ErrUnavailable
			}
			continue
		}
		info, statErr := entry.Info()
		if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > SegmentBytes {
			return nil, ErrUnavailable
		}
		result = append(result, segment{name: entry.Name(), size: info.Size(), day: day})
		if len(result) > RetentionDays*100 {
			return nil, ErrUnavailable
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].name < result[j].name })
	return result, nil
}

func (a *Audit) prune(now time.Time, incoming int64) ([]segment, error) {
	segments, err := a.segments()
	if err != nil {
		return nil, err
	}
	cutoff := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, -RetentionDays+1)
	var total int64
	for _, entry := range segments {
		total += entry.size
	}
	first := 0
	for first < len(segments) && (segments[first].day.Before(cutoff) || total+incoming > MaxAuditBytes) {
		if err = os.Remove(filepath.Join(a.directory, segments[first].name)); err != nil {
			return nil, err
		}
		total -= segments[first].size
		first++
	}
	if first > 0 {
		if err = syncDirectory(a.directory); err != nil {
			return nil, err
		}
	}
	return segments[first:], nil
}

func (a *Audit) appendPath(day string, incoming int64, segments []segment) (string, error) {
	prefix := "audit-" + day + "-"
	next := 0
	for _, entry := range segments {
		if !strings.HasPrefix(entry.name, prefix) {
			continue
		}
		index := int(entry.name[15]-'0')*10 + int(entry.name[16]-'0')
		if entry.size+incoming <= SegmentBytes {
			return filepath.Join(a.directory, entry.name), nil
		}
		if index >= next {
			next = index + 1
		}
	}
	if next >= 100 {
		return "", ErrUnavailable
	}
	return filepath.Join(a.directory, fmt.Sprintf("%s%02d.jsonl", prefix, next)), nil
}

func (a *Audit) append(path string, data []byte) error {
	before, statErr := os.Lstat(path)
	if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return ErrUnavailable
	}
	flags := os.O_WRONLY | os.O_APPEND
	if errors.Is(statErr, os.ErrNotExist) {
		flags |= os.O_CREATE | os.O_EXCL
	}
	file, err := os.OpenFile(path, flags, 0o600)
	if err != nil {
		return ErrUnavailable
	}
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || opened.Mode().Perm()&0o077 != 0 || opened.Size()+int64(len(data)) > SegmentBytes || (before != nil && !os.SameFile(before, opened)) {
		return errors.Join(ErrUnavailable, file.Close())
	}
	written, writeErr := file.Write(data)
	if writeErr == nil && written != len(data) {
		writeErr = io.ErrShortWrite
	}
	syncErr := file.Sync()
	closeErr := file.Close()
	dirErr := syncDirectory(a.directory)
	if errors.Join(writeErr, syncErr, closeErr, dirErr) != nil {
		return ErrUnavailable
	}
	return nil
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}
