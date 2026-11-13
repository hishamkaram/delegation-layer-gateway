package server

import (
	"context"
	"net/http"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/observability"
)

// The protected admin handler supplies authorization. Registry and Hub remain
// the independent count owners; these dated samples are never authorization.
func (r *Runtime) metadataMetrics(w http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		r.metrics.ServeHTTP(w, request)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 5*time.Second)
	defer cancel()
	counts, err := r.store.MetadataSnapshot(ctx)
	if err != nil {
		w.Header().Set("Cache-Control", "no-store")
		http.Error(w, "metadata_unavailable", http.StatusServiceUnavailable)
		return
	}
	online := r.hub.ActiveConnections()
	r.metrics.WriteSnapshot(w, request, observability.RuntimeSnapshot{ActiveDevices: online, RegisteredDevices: counts.RegisteredDevices, AuthorizedDevices: counts.AuthorizedDevices, WSSConnections: online})
}
