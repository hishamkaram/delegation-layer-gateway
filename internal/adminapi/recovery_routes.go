package adminapi

import "net/http"

func (h *Handler) recoveryRoute(w http.ResponseWriter, r *http.Request) bool {
	switch r.URL.Path {
	case "/v1/recovery/begin":
		serve(w, r, http.MethodPost, h.beginRecovery)
	case "/v1/recovery/register-root":
		serve(w, r, http.MethodPost, h.registerRecoveryRoot)
	case "/v1/recovery/routing-roster":
		serve(w, r, http.MethodPost, h.registerRoutingRecoveryRoster)
	case "/v1/recovery/seal":
		serve(w, r, http.MethodPost, h.sealRecovery)
	case "/v1/recovery/progress":
		serve(w, r, http.MethodPost, h.recoveryProgress)
	case "/v1/recovery/advance":
		serve(w, r, http.MethodPost, h.advanceRecovery)
	case "/v1/recovery/finish":
		serve(w, r, http.MethodPost, h.finishRecovery)
	case "/v1/tasks/list":
		serve(w, r, http.MethodPost, h.listAdministrativeTasks)
	case "/v1/tasks/get":
		serve(w, r, http.MethodPost, h.getAdministrativeTask)
	case "/v1/tasks/drain":
		serve(w, r, http.MethodPost, h.drainAdministrativeTask)
	case "/v1/routing/drain-target":
		serve(w, r, http.MethodPost, h.routingDrainTarget)
	case "/v1/routing/drain":
		serve(w, r, http.MethodPost, h.drainRouting)
	case "/v1/routing/permits":
		serve(w, r, http.MethodPost, h.listRoutingPermits)
	case "/v1/projects/refresh":
		serve(w, r, http.MethodPost, h.refreshProject)
	default:
		return false
	}
	return true
}
