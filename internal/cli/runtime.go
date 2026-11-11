package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"io"
	"strings"

	"github.com/hishamkaram/delegation-layer-gateway/internal/adminapi"
	"github.com/hishamkaram/delegation-layer-gateway/internal/config"
	"github.com/hishamkaram/delegation-layer-gateway/internal/connectorconfig"
	"github.com/hishamkaram/delegation-layer-gateway/internal/deviceidentity"
	"github.com/hishamkaram/delegation-layer-gateway/internal/deviceruntime"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/server"
)

func serve(ctx context.Context, args []string, stdout io.Writer) (result error) {
	set := flags("serve")
	path := set.String("config", "", "private Gateway JSON configuration")
	if err := parse(set, args); err != nil {
		return err
	}
	data, err := privateRead(*path, 65536)
	if err != nil {
		return err
	}
	cfg, err := config.ReadGateway(bytes.NewReader(data))
	if err != nil {
		return problem(exitUsage, "configuration_invalid", err)
	}
	runtime, err := server.New(ctx, cfg, server.Options{})
	if err != nil {
		return problem(exitRuntime, "server_unavailable", err)
	}
	defer func() {
		if closeErr := runtime.Close(); closeErr != nil {
			result = problem(exitCleanup, "server_cleanup_unconfirmed", errors.Join(result, closeErr))
		}
	}()
	addresses := runtime.Addresses()
	if err = writeJSON(stdout, struct {
		State  string `json:"state"`
		Public string `json:"public"`
		Device string `json:"device"`
	}{"bound", addresses.Public, addresses.Device}); err != nil {
		return err
	}
	err = runtime.Serve(ctx)
	if err != nil && !errors.Is(err, context.Canceled) {
		return problem(exitRuntime, "server_failed", err)
	}
	return nil
}

func connector(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return problem(exitUsage, "invalid_arguments", nil)
	}
	if args[0] == "-h" || args[0] == "--help" {
		return flag.ErrHelp
	}
	switch args[0] {
	case "enroll":
		return enroll(ctx, args[1:], stdout)
	case "run":
		return runConnector(ctx, args[1:])
	default:
		return problem(exitUsage, "invalid_arguments", nil)
	}
}

func connectorConfig(path string) (*connectorconfig.Config, error) {
	if _, err := privateRead(path, maxConfigBytes); err != nil {
		return nil, err
	}
	cfg, err := connectorconfig.Load(path)
	if err != nil {
		return nil, problem(exitUsage, "configuration_invalid", err)
	}
	return cfg, nil
}

func enroll(ctx context.Context, args []string, stdout io.Writer) error {
	set := flags("connector enroll")
	path := set.String("config", "", "private connector JSON configuration")
	tokenFile := set.String("token-file", "", "private enrollment response JSON")
	replace := set.Bool("replace-existing", false, "explicitly replace existing identity")
	if err := parse(set, args); err != nil {
		return err
	}
	cfg, err := connectorConfig(*path)
	if err != nil {
		return err
	}
	token, err := readToken(*tokenFile, string(cfg.DeviceID()))
	if err != nil {
		return err
	}
	store, err := deviceidentity.Open(cfg.IdentityDirectory())
	if err != nil {
		return problem(exitRuntime, "identity_unavailable", err)
	}
	var runErr error
	if *replace {
		runErr = deviceruntime.Reenroll(ctx, cfg, store, token)
	} else {
		runErr = deviceruntime.Enroll(ctx, cfg, store, token)
	}
	closeErr := store.Close()
	if err = connectorResult(runErr, closeErr); err != nil {
		return err
	}
	return writeJSON(stdout, struct {
		State  string `json:"state"`
		Device string `json:"device_id"`
	}{"enrolled", string(cfg.DeviceID())})
}

func runConnector(ctx context.Context, args []string) error {
	set := flags("connector run")
	path := set.String("config", "", "private connector JSON configuration")
	if err := parse(set, args); err != nil {
		return err
	}
	cfg, err := connectorConfig(*path)
	if err != nil {
		return err
	}
	store, err := deviceidentity.Open(cfg.IdentityDirectory())
	if err != nil {
		return problem(exitRuntime, "identity_unavailable", err)
	}
	// Run cannot return until accepted CLI/cleanup ownership joins. The caller
	// retains the Store lease until that invariant is satisfied, then closes once.
	runErr := deviceruntime.Run(ctx, cfg, store)
	return connectorResult(runErr, store.Close())
}

func connectorResult(runErr, closeErr error) error {
	if closeErr != nil || errors.Is(runErr, deviceruntime.ErrCleanup) || errors.Is(runErr, deviceidentity.ErrUncertain) {
		return problem(exitCleanup, "connector_cleanup_unconfirmed", errors.Join(runErr, closeErr))
	}
	if runErr != nil && !errors.Is(runErr, context.Canceled) {
		return problem(exitRuntime, "connector_failed", runErr)
	}
	return nil
}

func readToken(path, expectedDevice string) (string, error) {
	data, err := privateRead(path, 16<<10)
	if err != nil {
		return "", err
	}
	var input adminapi.Enrollment
	if protocol.DecodeStrict(data, &input, 16<<10) != nil || input.DeviceID != expectedDevice || input.ExpiresAt.IsZero() {
		return "", problem(exitUsage, "enrollment_input_invalid", nil)
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(input.Token)
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != input.Token || strings.TrimSpace(input.Token) != input.Token {
		return "", problem(exitUsage, "enrollment_input_invalid", err)
	}
	return input.Token, nil
}
