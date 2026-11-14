package transport

import (
	"context"

	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func validateCapabilityPayload(data []byte, version int) error {
	if version == protocol.WireVersion2 {
		var report protocol.CapabilityReportV2
		if err := protocol.DecodeStrict(data, &report, protocol.MaxFrameBytes); err != nil {
			return err
		}
		return report.Validate()
	}
	var report protocol.CapabilityReport
	if err := protocol.DecodeStrict(data, &report, protocol.MaxFrameBytes); err != nil {
		return err
	}
	return report.Validate()
}

func (c *Client) capabilityFrameV2(report protocol.CapabilityReportV2) (protocol.Frame, error) {
	if c.session.wireVersion != protocol.WireVersion2 || report.Validate() != nil {
		return protocol.Frame{}, fail(ErrProtocol, nil)
	}
	payload, err := protocol.Encode(report, protocol.MaxFrameBytes)
	if err != nil {
		return protocol.Frame{}, fail(ErrProtocol, err)
	}
	return c.capabilityPayloadFrame(payload)
}

func (c *Client) handshakeCapabilitiesV2(ctx context.Context, report *protocol.CapabilityReportV2) error {
	if report == nil {
		return fail(ErrProtocol, nil)
	}
	if c.session.strictRouting {
		if err := c.routingHandshake(ctx); err != nil {
			return err
		}
	}
	frame, err := c.capabilityFrameV2(*report)
	if err != nil {
		return err
	}
	return c.session.writeHandshake(ctx, frame)
}

func (c *Client) ReportCapabilitiesV2(ctx context.Context, report protocol.CapabilityReportV2) error {
	frame, err := c.capabilityFrameV2(report)
	if err != nil {
		return err
	}
	return c.session.send(ctx, frame)
}
