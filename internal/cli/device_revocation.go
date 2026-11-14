package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/hishamkaram/delegation-layer-gateway/internal/adminapi"
	"github.com/hishamkaram/delegation-layer-gateway/internal/config"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

func adminConfiguration(path string) (config.Gateway, error) {
	data, err := privateRead(path, maxConfigBytes)
	if err != nil {
		return config.Gateway{}, err
	}
	value, err := config.ReadGateway(bytes.NewReader(data))
	if err != nil {
		return config.Gateway{}, problem(exitUsage, "configuration_invalid", err)
	}
	return value, nil
}

// This is only typed CLI input for the existing private revocation endpoint.
// Registry still commits revocation; its handler owns subsequent socket cleanup.
func revokeDeviceCommand(ctx context.Context, args []string, stdout io.Writer) error {
	set := flags("devices revoke")
	configuration := set.String("config", "", "Gateway private configuration; exclusive with socket")
	socket := set.String("socket", "", "explicit private admin socket; exclusive with config")
	device := set.String("device", "", "exact device ID to revoke")
	if err := parse(set, args); err != nil {
		return err
	}
	if *configuration != "" {
		if *socket != "" {
			return problem(exitUsage, "invalid_arguments", nil)
		}
		cfg, err := adminConfiguration(*configuration)
		if err != nil {
			return err
		}
		*socket = cfg.AdminSocket
	}
	if !absolute(*socket) || domain.CredentialToken(*device) != nil {
		return problem(exitUsage, "invalid_arguments", nil)
	}
	revoked := true
	input := adminapi.DeviceRevocationInput{DeviceID: *device, Revoked: &revoked}
	data, err := json.Marshal(input)
	if err != nil {
		return problem(exitUsage, "invalid_arguments", err)
	}
	return adminRequest[adminapi.DeviceRevocationInput, adminapi.Mutation](ctx, *socket, http.MethodPost, "/v1/devices/revocation", data, "", false, stdout, validMutation[adminapi.DeviceRevocationInput])
}
