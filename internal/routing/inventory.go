package routing

import (
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

type PermitCursor struct {
	Device     domain.DeviceID
	Connection domain.ConnectionGeneration
	Request    string
}

type PermitPageRequest struct {
	After *PermitCursor
	Limit int
}

type PermitView struct {
	Device      domain.DeviceID
	ProcessBoot string
	Call        protocol.ControlCall
	Protected   bool
	Scan        bool
}

// PermitPage is a moving metadata read. It supplies no release authority.
type PermitPage struct {
	Items []PermitView
	Next  *PermitCursor
}
