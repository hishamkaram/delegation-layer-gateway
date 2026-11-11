package transport

import (
	"context"
	"crypto/x509"
	"sync"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

const (
	MaxDevices             = 256
	QueueFrames            = 32
	DeviceQueueBytes       = 1 << 20
	GlobalQueueBytes       = 8 << 20
	ProtectedFrames        = 2
	ProtectedDeviceBytes   = DeviceQueueBytes - protocol.MaxAdmissionFrameBytes
	ProtectedGlobalBytes   = 256 << 10
	MaxProtectedFrameBytes = 16 << 10
)

type trafficClass uint8

const (
	ordinaryTraffic trafficClass = iota
	protectedTraffic
)

func hasCountCapacity(total, ordinary int, class trafficClass) bool {
	return total < QueueFrames && (class == protectedTraffic || ordinary < QueueFrames-ProtectedFrames)
}

// Only fully validated bounded cancellation/fence controls receive headroom.
// There is no peer-supplied priority flag; replies inherit their request class.
func commandClass(command protocol.Command) (trafficClass, error) {
	switch command.Operation {
	case protocol.Cancel:
		var body protocol.Cancellation
		if protocol.DecodeStrict(command.Body, &body, protocol.MaxFrameBytes) != nil || body.Validate() != nil {
			return ordinaryTraffic, fail(ErrProtocol, nil)
		}
	case protocol.FenceAbsent:
		var body protocol.TaskControl
		if protocol.DecodeStrict(command.Body, &body, protocol.MaxFrameBytes) != nil || body.Task.Validate(false) != nil {
			return ordinaryTraffic, fail(ErrProtocol, nil)
		}
	case protocol.ContextInspect, protocol.Admit, protocol.Resolve, protocol.ResumeExisting, protocol.Status, protocol.Collect, protocol.ResultChunk, protocol.OriginBarrier, protocol.OriginInventory, protocol.OriginReopen:
		return ordinaryTraffic, nil
	default:
		return ordinaryTraffic, fail(ErrProtocol, nil)
	}
	return protectedTraffic, nil
}

type CredentialStore interface {
	CheckCredential(context.Context, domain.CredentialRef, time.Time) (domain.Credential, error)
	NextConnectionGeneration(context.Context, domain.CredentialRef, domain.BootEpoch, time.Time) (domain.ConnectionGeneration, error)
}

type Settings struct {
	HeartbeatInterval time.Duration
	OfflineTimeout    time.Duration
	HandshakeTimeout  time.Duration
	WriteTimeout      time.Duration
}

func settings(s Settings) (Settings, error) {
	if s.HeartbeatInterval == 0 {
		s.HeartbeatInterval = 15 * time.Second
	}
	if s.OfflineTimeout == 0 {
		s.OfflineTimeout = 45 * time.Second
	}
	if s.HandshakeTimeout == 0 {
		s.HandshakeTimeout = 5 * time.Second
	}
	if s.WriteTimeout == 0 {
		s.WriteTimeout = 5 * time.Second
	}
	if s.HeartbeatInterval <= 0 || s.OfflineTimeout <= s.HeartbeatInterval || s.HandshakeTimeout <= 0 || s.HandshakeTimeout > protocol.MaxTTL || s.WriteTimeout <= 0 || s.WriteTimeout > protocol.MaxTTL {
		return Settings{}, fail(ErrProtocol, nil)
	}
	return s, nil
}

type (
	Config struct {
		Routing   RoutingAuthority
		GatewayID domain.GatewayID
		BootEpoch domain.BootEpoch
		Settings  Settings
	}
	ClientConfig struct {
		Routing      ConnectorRouting
		URL          string
		GatewayID    domain.GatewayID
		Certificate  *x509.Certificate
		Mode         domain.CredentialMode
		Capabilities protocol.CapabilityReport
		Settings     Settings
	}
)

// Metadata is immutable encoded-wire identity, suitable for registry accounting.
// It intentionally retains no brief or result payload after its write completes.
type Metadata struct {
	ProcessBoot       string
	Call              protocol.ControlCall
	Credential        domain.CredentialRef
	Connection        domain.ConnectionGeneration
	RequestID         string
	OperationID       string
	EncodedFrameBytes int
}

// SendGuard rechecks current application authorization immediately before write.
// It must honor cancellation; transport separately checks the device credential.
type SendGuard func(context.Context, Metadata) error

// budget is the sole byte owner; callers hold their session mutex first.
type budget struct {
	mu   sync.Mutex
	used int
}

func (b *budget) acquire(s *session, n int, class trafficClass) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	deviceLimit, globalLimit := DeviceQueueBytes-ProtectedDeviceBytes, GlobalQueueBytes-ProtectedGlobalBytes
	if class == protectedTraffic {
		deviceLimit, globalLimit = DeviceQueueBytes, GlobalQueueBytes
		if n > MaxProtectedFrameBytes {
			return false
		}
	}
	if n < 0 || n > deviceLimit-s.bytes || n > globalLimit-b.used {
		return false
	}
	b.used += n
	s.bytes += n
	return true
}

func (b *budget) release(s *session, n int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.used -= n
	s.bytes -= n
}
