package domain

import "time"

// AttributeNativeReceipt reconstructs immutable attribution; it grants no
// authority and never infers an alias or rounds historical execution options.
func AttributeNativeReceipt(gateway GatewayID, device DeviceID, candidate ProjectRegistration, receipt NativeTaskReceipt) (Correlation, ExecutionOptions, bool, error) {
	if RoutingToken(string(gateway)) != nil || CredentialToken(string(device)) != nil || candidate.Validate() != nil || receipt.Validate() != nil {
		return Correlation{}, ExecutionOptions{}, false, ErrInvalid
	}
	if candidate.Destination.Device != device || receipt.Binding.Origin.Gateway != gateway || candidate.Context != receipt.Binding.Context {
		return Correlation{}, ExecutionOptions{}, false, nil
	}
	options, representable := receipt.Options.ExecutionOptions()
	if !representable {
		return Correlation{}, ExecutionOptions{}, false, nil
	}
	origin := receipt.Binding.Origin
	correlation := Correlation{
		Operation: origin.Operation, Task: receipt.Binding.Task, Gateway: gateway,
		AdmissionGeneration: origin.AdmissionGeneration,
		Owner:               OperationOwner{Kind: Owned, Principal: origin.Principal},
		Destination:         candidate.Destination, Context: candidate.Context,
		RequestDigest: origin.RequestDigest, BriefDigest: receipt.BriefDigest,
	}
	digest, err := RequestBindingDigest(correlation, options, receipt.BriefDigest)
	if err != nil {
		return Correlation{}, ExecutionOptions{}, false, err
	}
	if digest != origin.RequestDigest {
		return Correlation{}, ExecutionOptions{}, false, nil
	}
	return correlation, options, true, nil
}

func (o HistoricalExecutionOptions) ExecutionOptions() (ExecutionOptions, bool) {
	const second = int64(time.Second)
	if o.Validate() != nil || o.BudgetNanoseconds%second != 0 || o.BudgetNanoseconds/second > int64(^uint32(0)) {
		return ExecutionOptions{}, false
	}
	return ExecutionOptions{Provider: o.Provider, Permission: o.Permission, BudgetSeconds: uint32(o.BudgetNanoseconds / second), Model: o.Model, Effort: o.Effort}, true
}

func OriginFromCorrelation(c Correlation) TaskOrigin {
	return TaskOrigin{Gateway: c.Gateway, AdmissionGeneration: c.AdmissionGeneration, Operation: c.Operation, Principal: c.Owner.Principal, RequestDigest: c.RequestDigest}
}
