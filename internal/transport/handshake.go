package transport

import (
	"context"

	"github.com/coder/websocket"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

func (s *session) readHandshake(ctx context.Context) (protocol.Frame, error) {
	kind, data, err := s.conn.Read(ctx)
	if err != nil {
		return protocol.Frame{}, fail(ErrOffline, err)
	}
	if kind != websocket.MessageText {
		return protocol.Frame{}, fail(ErrProtocol, nil)
	}
	if checkErr := s.check(ctx); checkErr != nil {
		return protocol.Frame{}, checkErr
	}
	frame, err := protocol.DecodeFrameVersion(data, s.wireVersion)
	if err != nil || frame.Generation != wireGeneration(s.generation) {
		return protocol.Frame{}, fail(ErrProtocol, err)
	}
	return frame, nil
}

func (s *session) writeHandshake(ctx context.Context, frame protocol.Frame) error {
	if checkErr := s.check(ctx); checkErr != nil {
		return checkErr
	}
	encoded, err := protocol.EncodeFrameVersion(frame, s.wireVersion)
	if err != nil {
		return fail(ErrProtocol, err)
	}
	if checkErr := s.conn.Write(ctx, websocket.MessageText, encoded); checkErr != nil {
		return fail(ErrOffline, checkErr)
	}
	return nil
}
