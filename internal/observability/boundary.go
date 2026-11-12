package observability

import (
	"fmt"
	"io"
)

// BoundaryReason describes a rejection before HTTP request admission. These
// anonymous aggregate counters are deliberately separate from durable events.
type BoundaryReason string

const (
	BoundaryOrigin      BoundaryReason = "origin"
	BoundaryCapacity    BoundaryReason = "capacity"
	boundaryReasonCount                = 2
)

func boundaryReasons() [boundaryReasonCount]BoundaryReason {
	return [boundaryReasonCount]BoundaryReason{BoundaryOrigin, BoundaryCapacity}
}

// CountBoundaryRejection performs only fixed atomic accounting. In particular,
// rejected requests never acquire Audit's mutex or queue filesystem work outside
// the HTTP admission bound. No audit write is attempted or claimed here.
func (r *Recorder) CountBoundaryRejection(reason BoundaryReason) {
	if err := r.metrics.recordBoundary(reason); err != nil {
		r.metrics.metricFailures.Add(1)
	}
}

func (m *Metrics) recordBoundary(reason BoundaryReason) error {
	for i, candidate := range boundaryReasons() {
		if reason == candidate {
			m.boundary[i].Add(1)
			return nil
		}
	}
	return ErrUnavailable
}

func (m *Metrics) writeBoundaryCounters(w io.Writer) error {
	for i, reason := range boundaryReasons() {
		if _, err := fmt.Fprintf(w, "gateway_boundary_rejections_total{reason=%q} %d\n", reason, m.boundary[i].Load()); err != nil {
			return err
		}
	}
	return nil
}
