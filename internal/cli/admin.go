package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/adminapi"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

const maxAdminResponse = adminapi.MaxResponseBytes

func admin(ctx context.Context, args []string, stdout io.Writer) error {
	set := flags("admin")
	socket := set.String("socket", "", "private Unix socket")
	action, actionSet := "", false
	set.Func("action", "closed administrative action", func(value string) error {
		if actionSet {
			return errors.New("administrative action specified more than once")
		}
		action, actionSet = value, true
		return nil
	})
	input := set.String("input-file", "", "private JSON input")
	output := set.String("output-file", "", "new private JSON output")
	if err := parse(set, args); err != nil {
		return err
	}
	if !absolute(*socket) || *input == "" {
		return problem(exitUsage, "invalid_arguments", nil)
	}
	data, err := privateRead(*input, adminapi.MaxBodyBytes)
	if err != nil {
		return err
	}
	return adminAction(ctx, *socket, action, *output, data, stdout)
}

func adminAction(ctx context.Context, socket, action, output string, data []byte, stdout io.Writer) error {
	if handled, err := routingAdminAction(ctx, socket, action, output, data, stdout); handled {
		return err
	}
	if handled, err := recoveryAdminAction(ctx, socket, action, output, data, stdout); handled {
		return err
	}
	switch action {
	case "initialize-root":
		return adminRequest[adminapi.RootInput, adminapi.RootProgress](ctx, socket, http.MethodPost, "/v1/roots/initialize", data, output, false, stdout, validRootProgress)
	case "root-progress":
		return adminRequest[adminapi.RootInput, adminapi.RootProgress](ctx, socket, http.MethodPost, "/v1/roots/progress", data, output, false, stdout, validRootProgress)
	case "abandon-root":
		return adminRequest[adminapi.RootAbandonInput, adminapi.Mutation](ctx, socket, http.MethodPost, "/v1/roots/abandon", data, output, false, stdout, validMutation[adminapi.RootAbandonInput])
	case "register-device":
		return adminRequest[adminapi.RegisterDeviceInput, adminapi.Device](ctx, socket, http.MethodPost, "/v1/devices", data, output, false, stdout, validDeviceResponse)
	case "register-project":
		return adminRequest[adminapi.RegisterProjectInput, adminapi.Mutation](ctx, socket, http.MethodPost, "/v1/projects", data, output, false, stdout, validMutation[adminapi.RegisterProjectInput])
	case "resolve-principal":
		return adminRequest[adminapi.ResolvePrincipalInput, adminapi.Principal](ctx, socket, http.MethodPost, "/v1/principals/resolve", data, output, false, stdout, validPrincipalResponse)
	case "put-grant":
		return adminRequest[adminapi.PutGrantInput, adminapi.Mutation](ctx, socket, http.MethodPut, "/v1/grants", data, output, false, stdout, validMutation[adminapi.PutGrantInput])
	case "revoke-grant":
		return adminRequest[adminapi.GrantKey, adminapi.Mutation](ctx, socket, http.MethodDelete, "/v1/grants", data, output, false, stdout, validMutation[adminapi.GrantKey])
	case "revoke-principal":
		return adminRequest[adminapi.PrincipalRevocationInput, adminapi.Mutation](ctx, socket, http.MethodPost, "/v1/principals/revocation", data, output, false, stdout, validMutation[adminapi.PrincipalRevocationInput])
	case "revoke-device":
		return adminRequest[adminapi.DeviceRevocationInput, adminapi.Mutation](ctx, socket, http.MethodPost, "/v1/devices/revocation", data, output, false, stdout, validMutation[adminapi.DeviceRevocationInput])
	case "issue-enrollment-token":
		return adminRequest[adminapi.EnrollmentInput, adminapi.Enrollment](ctx, socket, http.MethodPost, "/v1/enrollment-tokens", data, output, true, stdout, validEnrollmentResponse)
	default:
		return problem(exitUsage, "invalid_arguments", nil)
	}
}

func adminRequest[In, Out any](ctx context.Context, socket, method, path string, data []byte, output string, credential bool, stdout io.Writer, valid func(In, Out) bool) (result error) {
	input, err := decodeAdminInput[In](data)
	if err != nil {
		return err
	}
	if credential && output == "" {
		return problem(exitUsage, "credential_output_required", nil)
	}
	var owned *outputFile
	if output != "" {
		file, prepareErr := prepareOutput(output)
		if prepareErr != nil {
			return prepareErr
		}
		owned = file
		defer func() {
			if closeErr := owned.close(); closeErr != nil {
				result = problem(exitCleanup, "output_cleanup_unconfirmed", errors.Join(result, closeErr))
			}
		}()
	}
	encoded, err := json.Marshal(input)
	if err != nil {
		return problem(exitUsage, "invalid_admin_input", err)
	}
	response, err := unixRequest(ctx, socket, method, path, encoded)
	if err != nil {
		return credentialDeliveryError(credential, err)
	}
	var value Out
	if protocol.DecodeStrict(response, &value, maxAdminResponse) != nil || !valid(input, value) {
		return credentialDeliveryError(credential, problem(exitRuntime, "invalid_admin_response", nil))
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return problem(exitRuntime, "invalid_admin_response", err)
	}
	canonical = append(canonical, '\n')
	if owned != nil {
		return owned.write(canonical)
	}
	if _, err = stdout.Write(canonical); err != nil {
		return problem(exitRuntime, "output_unavailable", err)
	}
	return nil
}

func decodeAdminInput[In any](data []byte) (In, error) {
	var input In
	if protocol.DecodeStrict(data, &input, adminapi.MaxBodyBytes) != nil {
		return input, problem(exitUsage, "invalid_admin_input", nil)
	}
	// Optional boundary validators belong to their precise DTO. The checked
	// generic assertion never changes the input's concrete type or contents.
	if checked, ok := any(input).(interface{ Validate() error }); ok && checked.Validate() != nil {
		return input, problem(exitUsage, "invalid_admin_input", nil)
	}
	return input, nil
}

func unixRequest(ctx context.Context, socket, method, path string, data []byte) (body []byte, result error) {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	owned := &http.Transport{Proxy: nil, DialContext: func(call context.Context, _, _ string) (net.Conn, error) {
		return dialer.DialContext(call, "unix", socket)
	}, DisableCompression: true, MaxConnsPerHost: 1, MaxIdleConns: 1, MaxIdleConnsPerHost: 1, ResponseHeaderTimeout: 30 * time.Second, MaxResponseHeaderBytes: 16 << 10}
	defer owned.CloseIdleConnections()
	client := &http.Client{Transport: owned, Timeout: 35 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, method, "http://unix"+path, bytes.NewReader(data))
	if err != nil {
		return nil, problem(exitRuntime, "admin_unavailable", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return nil, problem(exitRuntime, "admin_response_unconfirmed", err)
	}
	defer func() {
		if closeErr := response.Body.Close(); closeErr != nil {
			result = problem(exitCleanup, "admin_cleanup_unconfirmed", errors.Join(result, closeErr))
		}
	}()
	return readAdminResponse(response)
}

// readAdminResponse borrows the body; unixRequest owns its close.
func readAdminResponse(response *http.Response) (data []byte, result error) {
	body, err := io.ReadAll(io.LimitReader(response.Body, maxAdminResponse+1))
	if err != nil || len(body) > maxAdminResponse {
		return nil, problem(exitRuntime, "admin_response_unconfirmed", err)
	}
	media, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if mediaErr != nil || media != "application/json" {
		return nil, problem(exitRuntime, "invalid_admin_response", mediaErr)
	}
	if response.StatusCode != http.StatusOK {
		var failure adminapi.Failure
		if protocol.DecodeStrict(body, &failure, maxAdminResponse) != nil {
			return nil, problem(exitRuntime, "invalid_admin_response", nil)
		}
		if failure.Committed {
			return nil, problem(exitCleanup, "admin_mutation_committed_cleanup_unconfirmed", nil)
		}
		if response.StatusCode == http.StatusBadRequest {
			return nil, problem(exitUsage, "admin_input_rejected", nil)
		}
		return nil, problem(exitRuntime, "admin_request_rejected", nil)
	}
	return body, nil
}

func validDeviceResponse(input adminapi.RegisterDeviceInput, output adminapi.Device) bool {
	return input.DeviceID == output.DeviceID && input.Name == output.Name && domain.CredentialToken(output.DeviceID) == nil
}

func validPrincipalResponse(_ adminapi.ResolvePrincipalInput, output adminapi.Principal) bool {
	return domain.Token(output.PrincipalID) == nil
}
func validMutation[In any](_ In, output adminapi.Mutation) bool { return output.Committed }
func validEnrollmentResponse(input adminapi.EnrollmentInput, output adminapi.Enrollment) bool {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(output.Token)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == output.Token && output.DeviceID == input.DeviceID && domain.CredentialToken(output.DeviceID) == nil && input.Mode.Validate() == nil && input.Generation > 0 && !output.ExpiresAt.IsZero()
}

func credentialDeliveryError(credential bool, err error) error {
	var failure *commandError
	if credential && errors.As(err, &failure) && failure.exit == exitRuntime && failure.code != "admin_request_rejected" {
		return problem(exitCleanup, "credential_delivery_unconfirmed", err)
	}
	return err
}

func validRootProgress(input adminapi.RootInput, output adminapi.RootProgress) bool {
	if input.DeviceID != output.DeviceID || input.ProjectAlias != output.ProjectAlias || domain.Token(output.GatewayID) != nil {
		return false
	}
	if output.RecoveryID != "" && domain.RoutingToken(output.RecoveryID) != nil {
		return false
	}
	if output.Generation != "" && domain.RoutingToken(output.Generation) != nil {
		return false
	}
	switch output.Stage {
	case domain.RootNeedsBarrier:
		return (output.RecoveryID == "") == (output.Generation == "")
	case domain.RootNeedsInventory, domain.RootNeedsApproval, domain.RootNeedsReopen, domain.RootReady, domain.RootRestoreRequired, domain.RootNeedsMapping, domain.RootNeedsRegularCredential:
		return output.RecoveryID != "" && output.Generation != ""
	default:
		return false
	}
}
