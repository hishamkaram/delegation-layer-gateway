package cli

import (
	"context"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"slices"

	"github.com/hishamkaram/delegation-layer-gateway/internal/adminapi"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

type ownerFlags struct {
	configPath string
	socket     string
	issuer     string
	subject    string
}

func users(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) == 0 || (args[0] != "allow" && args[0] != "show" && args[0] != "disable") {
		return problem(exitUsage, "invalid_arguments", nil)
	}
	set := flags("users " + args[0])
	var target ownerFlags
	set.StringVar(&target.configPath, "config", "", "Gateway configuration selects issuer and private socket")
	set.StringVar(&target.socket, "socket", "", "explicit private socket; exclusive with config")
	set.StringVar(&target.issuer, "issuer", "", "exact verified issuer; exclusive with config")
	set.StringVar(&target.subject, "subject", "", "exact identity-provider subject")
	input := adminapi.OwnerPolicyInput{}
	var budget, devices uint
	if args[0] == "allow" {
		set.Func("provider", "allowed provider; repeat for each provider", func(value string) error {
			input.Providers = append(input.Providers, domain.ProviderID(value))
			return nil
		})
		set.Func("permission", "allowed permission; repeat as needed; default read-only", func(value string) error {
			input.Permissions = append(input.Permissions, domain.Permission(value))
			return nil
		})
		set.Func("scope", "task scope; repeat as needed; default all four task scopes", func(value string) error {
			input.Scopes = append(input.Scopes, domain.Scope(value))
			return nil
		})
		set.UintVar(&budget, "max-budget-seconds", 60, "maximum per-task duration")
		set.UintVar(&devices, "max-devices", 5, "maximum concurrently enrolled devices")
	}
	if err := parse(set, args[1:]); err != nil {
		return err
	}
	if err := target.resolve(); err != nil {
		return err
	}
	if args[0] != "allow" {
		return ownerReadOrDisable(ctx, args[0], target, stdout)
	}
	if budget > math.MaxUint32 || devices > math.MaxUint32 {
		return problem(exitUsage, "invalid_owner_policy", nil)
	}
	input.Issuer, input.Subject = target.issuer, target.subject
	input.MaxBudgetSeconds, input.MaxDevices = uint32(budget), uint32(devices)
	if len(input.Permissions) == 0 {
		input.Permissions = []domain.Permission{domain.ReadOnly}
	}
	if len(input.Scopes) == 0 {
		input.Scopes = domain.ScopeSet{domain.InventoryRead, domain.TaskDispatch, domain.TaskRead, domain.TaskCancel}
	}
	return allowOwner(ctx, target.socket, input, stdout)
}

func (f *ownerFlags) resolve() error {
	if f.configPath != "" {
		if f.socket != "" || f.issuer != "" {
			return problem(exitUsage, "invalid_arguments", nil)
		}
		cfg, err := adminConfiguration(f.configPath)
		if err != nil {
			return err
		}
		f.socket, f.issuer = cfg.AdminSocket, cfg.Identity.Issuer
	}
	if !absolute(f.socket) || (domain.ExternalSubject{Issuer: f.issuer, Subject: f.subject}).Validate() != nil {
		return problem(exitUsage, "invalid_arguments", nil)
	}
	return nil
}

func allowOwner(ctx context.Context, socket string, input adminapi.OwnerPolicyInput, stdout io.Writer) error {
	if err := input.Validate(); err != nil {
		return problem(exitUsage, "invalid_owner_policy", err)
	}
	data, err := json.Marshal(input)
	if err != nil {
		return problem(exitUsage, "invalid_owner_policy", err)
	}
	return adminRequest[adminapi.OwnerPolicyInput, adminapi.OwnerPolicyView](ctx, socket, http.MethodPost, "/v1/users/allow", data, "", false, stdout, func(expected adminapi.OwnerPolicyInput, view adminapi.OwnerPolicyView) bool {
		actual := view.Policy
		return view.Validate() == nil && view.Enabled && actual.Issuer == expected.Issuer && actual.Subject == expected.Subject && actual.MaxDevices == expected.MaxDevices && actual.MaxBudgetSeconds == expected.MaxBudgetSeconds && slices.Equal(actual.Scopes, expected.Scopes) && slices.Equal(actual.Providers, expected.Providers) && slices.Equal(actual.Permissions, expected.Permissions)
	})
}

func ownerReadOrDisable(ctx context.Context, action string, target ownerFlags, stdout io.Writer) error {
	input := adminapi.ResolvePrincipalInput{Issuer: target.issuer, Subject: target.subject}
	data, err := json.Marshal(input)
	if err != nil {
		return problem(exitUsage, "invalid_arguments", err)
	}
	if action == "disable" {
		return adminRequest[adminapi.ResolvePrincipalInput, adminapi.Mutation](ctx, target.socket, http.MethodPost, "/v1/users/disable", data, "", false, stdout, validMutation[adminapi.ResolvePrincipalInput])
	}
	return adminRequest[adminapi.ResolvePrincipalInput, adminapi.OwnerPolicyView](ctx, target.socket, http.MethodPost, "/v1/users/show", data, "", false, stdout, func(expected adminapi.ResolvePrincipalInput, view adminapi.OwnerPolicyView) bool {
		return view.Validate() == nil && view.Policy.Issuer == expected.Issuer && view.Policy.Subject == expected.Subject
	})
}
