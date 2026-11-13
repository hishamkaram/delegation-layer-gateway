package transport

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/coder/websocket"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/identity"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

// Client owns one outbound WSS session. Its caller owns reconnect/backoff and
// the identity OS lease. A new Client never resends any old session's frames.
type Client struct {
	routing ConnectorRouting
	session *session
	gateway domain.GatewayID
}

func Dial(ctx context.Context, config ClientConfig, client *http.Client, now func() time.Time) (*Client, error) {
	if client == nil || now == nil || ctx == nil {
		return nil, fail(ErrProtocol, nil)
	}
	config, err := checkedClientConfig(config)
	if err != nil {
		return nil, err
	}
	certificate, err := x509.ParseCertificate(bytes.Clone(config.Certificate.Raw))
	if err != nil {
		return nil, fail(ErrProtocol, err)
	}
	ref, err := identity.CredentialFromCertificate(certificate)
	if err != nil {
		return nil, fail(ErrForbidden, err)
	}
	return dial(ctx, config, client, now, certificate, ref)
}

func checkedClientConfig(config ClientConfig) (ClientConfig, error) {
	u, err := url.Parse(config.URL)
	if err != nil || u.Scheme != "wss" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || config.Certificate == nil {
		return ClientConfig{}, fail(ErrProtocol, err)
	}
	checked, err := settings(config.Settings)
	if err != nil {
		return ClientConfig{}, err
	}
	if config.Mode == "" {
		config.Mode = domain.Regular
	}
	if config.Mode.Validate() != nil || config.Capabilities.Validate() != nil {
		return ClientConfig{}, fail(ErrProtocol, nil)
	}
	config.Settings = checked
	return config, nil
}

func dial(ctx context.Context, config ClientConfig, client *http.Client, now func() time.Time, certificate *x509.Certificate, ref domain.CredentialRef) (*Client, error) {
	checked := config.Settings
	owned := *client
	owned.Jar = nil
	owned.Timeout = checked.HandshakeTimeout
	owned.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	s := newSession(ctx, checked, now, &budget{}, make(chan *Received, QueueFrames))
	s.strictRouting = config.Routing != nil
	s.ref = ref
	s.certificate = certificate
	s.mode = config.Mode
	if checkErr := s.check(ctx); checkErr != nil {
		s.cancel()
		return nil, checkErr
	}
	handshake, cancel := context.WithTimeout(ctx, checked.HandshakeTimeout)
	defer cancel()
	conn, response, err := websocket.Dial(handshake, config.URL, &websocket.DialOptions{HTTPClient: &owned, Subprotocols: []string{protocol.Subprotocol}, CompressionMode: websocket.CompressionDisabled})
	// websocket v1.8.15 transfers the live HTTP body to Conn. Only its
	// bounded failure diagnostic body remains on the returned response.
	if response != nil && response.Body != nil {
		if closeErr := response.Body.Close(); closeErr != nil {
			if conn != nil {
				closeErr = errors.Join(closeErr, conn.CloseNow())
			}
			s.cancel()
			return nil, fail(ErrOffline, errors.Join(err, closeErr))
		}
	}
	if err != nil {
		s.cancel()
		return nil, fail(ErrOffline, err)
	}
	s.conn = conn
	conn.SetReadLimit(protocol.MaxFrameBytes)
	if conn.Subprotocol() != protocol.Subprotocol {
		s.stop(fail(ErrProtocol, nil))
		return nil, fail(ErrProtocol, nil)
	}
	c := &Client{session: s, gateway: config.GatewayID, routing: config.Routing}
	if checkErr := c.handshake(handshake, config.Capabilities); checkErr != nil {
		s.stop(checkErr)
		return nil, checkErr
	}
	close(s.ready)
	go s.run(ctx)
	return c, nil
}

func (c *Client) handshake(ctx context.Context, report protocol.CapabilityReport) error {
	s := c.session
	kind, data, err := s.conn.Read(ctx)
	if err != nil {
		return fail(ErrOffline, err)
	}
	if kind != websocket.MessageText {
		return fail(ErrProtocol, nil)
	}
	frame, err := protocol.DecodeFrame(data)
	if err != nil || frame.Type != protocol.Hello || frame.OperationID != "" {
		return fail(ErrProtocol, err)
	}
	var hello protocol.HelloBody
	if checkErr := protocol.DecodeStrict(frame.Payload, &hello, protocol.MaxFrameBytes); checkErr != nil || hello.Validate() != nil || hello.GatewayID != string(c.gateway) || hello.DeviceID != string(s.ref.Device) {
		return fail(ErrProtocol, checkErr)
	}
	s.generation = domain.ConnectionGeneration{BootEpoch: domain.BootEpoch(frame.Generation.BootEpoch), Counter: frame.Generation.Counter}
	if checkErr := s.writeHandshake(ctx, frame); checkErr != nil {
		return checkErr
	}
	report, err = c.handshakeCapabilities(ctx, report)
	if err != nil {
		return err
	}
	capabilities, err := c.capabilityFrame(report)
	if err != nil {
		return err
	}
	return s.writeHandshake(ctx, capabilities)
}

func (c *Client) capabilityFrame(report protocol.CapabilityReport) (protocol.Frame, error) {
	if report.Validate() != nil {
		return protocol.Frame{}, fail(ErrProtocol, nil)
	}
	payload, err := protocol.Encode(report, protocol.MaxFrameBytes)
	if err != nil {
		return protocol.Frame{}, fail(ErrProtocol, err)
	}
	s := c.session
	s.mu.Lock()
	id, idErr := s.nextIDLocked()
	s.mu.Unlock()
	if idErr != nil {
		s.stop(idErr)
		return protocol.Frame{}, idErr
	}
	return protocol.Frame{Version: protocol.Version, Type: protocol.Capabilities, RequestID: id, Generation: wireGeneration(s.generation), TTLMillis: protocol.MaxTTL.Milliseconds(), Payload: payload}, nil
}

func (c *Client) ReportCapabilities(ctx context.Context, report protocol.CapabilityReport) error {
	frame, err := c.capabilityFrame(report)
	if err != nil {
		return err
	}
	return c.session.send(ctx, frame)
}

func (c *Client) Receive(ctx context.Context) (*Received, error) {
	select {
	case <-ctx.Done():
		return nil, fail(ErrOffline, ctx.Err())
	case <-c.session.done:
		return nil, fail(ErrOffline, nil)
	case received := <-c.session.incoming:
		return received, nil
	}
}

func (c *Client) Reserve(ctx context.Context, frame protocol.Frame) (*Reservation, error) {
	return c.session.reserve(ctx, frame)
}
func (c *Client) Generation() domain.ConnectionGeneration { return c.session.generation }
func (c *Client) Close() error {
	c.session.stop(fail(ErrOffline, nil))
	<-c.session.done
	return c.session.closeFailure()
}

func (c *Client) handshakeCapabilities(ctx context.Context, report protocol.CapabilityReport) (protocol.CapabilityReport, error) {
	if !c.session.strictRouting {
		return report, nil
	}
	if err := c.routingHandshake(ctx); err != nil {
		return protocol.CapabilityReport{}, err
	}
	if !c.RoutingReady() {
		// Capability input remains caller-owned; only this session's projection
		// suppresses readiness while its routing census is pending.
		report.Projects = append([]protocol.ProjectCapability(nil), report.Projects...)
		for i := range report.Projects {
			report.Projects[i].Ready = false
		}
	}
	return report, nil
}
