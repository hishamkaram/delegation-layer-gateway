package domain

import (
	"math"
	"testing"
	"time"
)

func attributionFixture(t *testing.T) (Correlation, NativeTaskReceipt) {
	t.Helper()
	c := Correlation{Operation: "operation", Task: "0123456789abcdef0123456789abcdef", Gateway: "gateway", AdmissionGeneration: "old-generation", Owner: OperationOwner{Kind: Owned, Principal: "principal"}, Destination: Destination{Device: "device", Project: "original-alias"}, Context: ContextBinding{Root: RootGuard("ctx1_1111111111111111111111111111111111111111111111111111111111111111"), Project: ProjectGuard("ctx1_2222222222222222222222222222222222222222222222222222222222222222")}, BriefDigest: Hash([]byte("brief"))}
	options := ExecutionOptions{Provider: "provider", Permission: ReadOnly, BudgetSeconds: 60, Model: Selection{Kind: NativeDefault}, Effort: Selection{Kind: Explicit, Value: "high"}}
	digest, err := RequestBindingDigest(c, options, c.BriefDigest)
	if err != nil {
		t.Fatal(err)
	}
	c.RequestDigest = digest
	r := NativeTaskReceipt{Binding: NativeTaskBinding{Task: c.Task, Context: c.Context, Origin: OriginFromCorrelation(c), SpecDigest: Hash([]byte("actual task bytes"))}, BriefDigest: c.BriefDigest, Options: HistoricalExecutionOptions{Provider: options.Provider, Permission: options.Permission, BudgetNanoseconds: int64(time.Minute), Model: options.Model, Effort: options.Effort}}
	return c, r
}

func TestAttributionRequiresExactImmutableRequest(t *testing.T) {
	c, receipt := attributionFixture(t)
	candidate := ProjectRegistration{Destination: c.Destination, Context: c.Context}
	got, options, matched, err := AttributeNativeReceipt(c.Gateway, c.Destination.Device, candidate, receipt)
	if err != nil || !matched || got != c || options.BudgetSeconds != 60 {
		t.Fatal("exact original correlation did not reconstruct")
	}
	for _, name := range []string{"alias", "device", "context", "principal", "options", "brief", "native-default", "fractional", "overflow"} {
		t.Run(name, func(t *testing.T) {
			candidate := candidate
			r := receipt
			mutateAttributionCandidate(name, &candidate, &r)
			if _, _, matched, err := AttributeNativeReceipt(c.Gateway, c.Destination.Device, candidate, r); err != nil || matched {
				t.Fatal("valid conflicting receipt invented attribution")
			}
		})
	}
}

func TestHistoricalBudgetConversionIsExactAndChecked(t *testing.T) {
	_, receipt := attributionFixture(t)
	for _, budget := range []int64{0, -1, 1500000000, math.MaxInt64} {
		options := receipt.Options
		options.BudgetNanoseconds = budget
		if _, ok := options.ExecutionOptions(); ok {
			t.Fatal("unrepresentable budget converted to a different request")
		}
	}
	options := receipt.Options
	options.BudgetNanoseconds = int64(math.MaxUint32) * int64(time.Second)
	converted, ok := options.ExecutionOptions()
	if !ok || converted.BudgetSeconds != math.MaxUint32 {
		t.Fatal("maximum exact representable budget rejected")
	}
}

func mutateAttributionCandidate(name string, candidate *ProjectRegistration, r *NativeTaskReceipt) {
	switch name {
	case "alias":
		candidate.Destination.Project = "alternative-drain-alias"
	case "device":
		candidate.Destination.Device = "other-device"
	case "context":
		candidate.Context.Project = ProjectGuard("ctx1_3333333333333333333333333333333333333333333333333333333333333333")
	case "principal":
		r.Binding.Origin.Principal = "other-principal"
	case "options":
		r.Options.Permission = WorkspaceWrite
	case "brief":
		r.BriefDigest = Hash([]byte("another brief"))
	case "native-default":
		r.Options.Effort = Selection{Kind: NativeDefault}
	case "fractional":
		r.Options.BudgetNanoseconds = int64(1500 * time.Millisecond)
	case "overflow":
		r.Options.BudgetNanoseconds = math.MaxInt64
	}
}
