package adminapi

import "net/http"

// metadata is reachable only after the instance-bound authority, request gate,
// request restrictions and bounded context have been established by ServeHTTP.
func (h *Handler) metadata(w http.ResponseWriter, r *http.Request) bool {
	switch r.URL.Path {
	case "/v1/metadata/metrics":
		if h.options.MetadataMetrics == nil {
			writeFailure(w, http.StatusNotFound, "not_found", false)
		} else if metadataRead(w, r) {
			h.options.MetadataMetrics.ServeHTTP(w, r)
		}
	case "/v1/metadata/health":
		if h.options.MetadataHealth == nil {
			writeFailure(w, http.StatusNotFound, "not_found", false)
		} else if metadataRead(w, r) {
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusOK)
			} else {
				writeJSON(w, http.StatusOK, h.options.MetadataHealth())
			}
		}
	default:
		return false
	}
	return true
}

func metadataRead(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.RawPath != "" {
		writeFailure(w, http.StatusBadRequest, "invalid_request", false)
		return false
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeFailure(w, http.StatusMethodNotAllowed, "method_not_allowed", false)
		return false
	}
	return true
}
