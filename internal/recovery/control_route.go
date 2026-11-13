package recovery

import (
	"context"

	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

// Exactly one typed route is present. A root control never invents a project
// alias and cannot be reused for admission or ordinary task controls.
type controlRoute struct {
	project *domain.Destination
	root    *domain.RootRoute
}

func (r controlRoute) device() domain.DeviceID {
	if r.root != nil {
		return r.root.Device
	}
	return r.project.Device
}

func (r controlRoute) valid(command protocol.Command, guard func(context.Context, domain.Transmission) error, accept func(protocol.Reply, domain.Transmission) error) bool {
	if guard == nil || accept == nil || (r.project == nil) == (r.root == nil) {
		return false
	}
	if r.project != nil {
		return r.project.Validate() == nil && command.Project == string(r.project.Project) && command.Root == ""
	}
	return r.root.Validate() == nil && command.Root == string(r.root.Root) && command.Project == "" && (command.Operation == protocol.ContextInspect || command.Operation.Administrative())
}

func (r controlRoute) validate() error {
	if (r.project == nil) == (r.root == nil) {
		return domain.ErrInvalid
	}
	if r.root != nil {
		return r.root.Validate()
	}
	return r.project.Validate()
}

func (r controlRoute) command(operation protocol.Operation, body []byte) protocol.Command {
	command := protocol.Command{Operation: operation, Body: body}
	if r.root != nil {
		command.Root = string(r.root.Root)
	} else {
		command.Project = string(r.project.Project)
	}
	return command
}
