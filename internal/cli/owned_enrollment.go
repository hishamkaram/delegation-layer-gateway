package cli

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/adminapi"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

func devicesCommand(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) > 0 && args[0] == "revoke" {
		return revokeDeviceCommand(ctx, args[1:], stdout)
	}
	if len(args) == 0 || args[0] != "enrollment-token" {
		return problem(exitUsage, "invalid_arguments", nil)
	}
	set := flags("devices enrollment-token")
	var target ownerFlags
	set.StringVar(&target.configPath, "config", "", "Gateway configuration selects issuer and private socket")
	set.StringVar(&target.socket, "socket", "", "explicit private socket; exclusive with config")
	set.StringVar(&target.issuer, "issuer", "", "exact owner issuer; exclusive with config")
	set.StringVar(&target.subject, "subject", "", "exact eligible owner subject")
	name := set.String("name", "", "new device name")
	output := set.String("output-file", "", "new private token file; required")
	if err := parse(set, args[1:]); err != nil {
		return err
	}
	if err := target.resolve(); err != nil {
		return err
	}
	input := adminapi.OwnedEnrollmentInput{Issuer: target.issuer, Subject: target.subject, Name: *name}
	if input.Validate() != nil || *output == "" {
		return problem(exitUsage, "invalid_arguments", nil)
	}
	data, err := json.Marshal(input)
	if err != nil {
		return problem(exitUsage, "invalid_arguments", err)
	}
	started := time.Now()
	return adminRequest[adminapi.OwnedEnrollmentInput, adminapi.Enrollment](ctx, target.socket, http.MethodPost, "/v1/devices/enrollment-tokens", data, *output, true, stdout, func(_ adminapi.OwnedEnrollmentInput, result adminapi.Enrollment) bool {
		return validEnrollmentResponse(adminapi.EnrollmentInput{DeviceID: result.DeviceID, Mode: domain.Regular, Generation: 1}, result) && result.ExpiresAt.After(started) && !result.ExpiresAt.After(time.Now().Add(domain.EnrollmentTTL))
	})
}
