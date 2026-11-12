package observability

// Health is a metadata-only sticky failure snapshot. It contains no paths,
// native errors or request values and belongs only on protected local admin.
type Health struct {
	AuditHealthy   bool   `json:"audit_healthy"`
	AuditFailures  uint64 `json:"audit_failures"`
	MetricFailures uint64 `json:"metric_failures"`
}

// Recorder owns handling of audit/metric write failures. Recording is isolated
// from task outcomes: failures become protected health/counters, never a changed
// admission decision or a fabricated accepted result.
type Recorder struct {
	audit   *Audit
	metrics *Metrics
}

func NewRecorder(audit *Audit, metrics *Metrics) (*Recorder, error) {
	if audit == nil || metrics == nil {
		return nil, ErrUnavailable
	}
	return &Recorder{audit: audit, metrics: metrics}, nil
}

func (r *Recorder) Record(event Event) {
	// Reject incomplete or unsafe observations before either sink consumes them.
	// Invalid metadata still becomes fixed protected health, never a raw log.
	if !event.validate() {
		r.metrics.metricFailures.Add(1)
		r.metrics.AuditFailed()
		return
	}
	if err := r.metrics.recordEvent(event); err != nil {
		r.metrics.metricFailures.Add(1)
	}
	if err := r.audit.Record(event); err != nil {
		r.metrics.AuditFailed()
	}
}

func (r *Recorder) Health() Health {
	auditFailures := r.metrics.auditFailures.Load()
	return Health{AuditHealthy: auditFailures == 0, AuditFailures: auditFailures, MetricFailures: r.metrics.metricFailures.Load()}
}
