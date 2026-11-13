package httpguard

import (
	"net"
	"net/http"
	"net/netip"
)

// ClientIP selects only a rate-limit key, never identity or authorization.
// Forwarded metadata is accepted solely from an explicitly trusted loopback
// proxy. The proxy must overwrite X-Real-IP with its actual client address.
func ClientIP(request *http.Request, trustLoopbackProxy bool) (string, error) {
	if request == nil {
		return "", ErrInvalid
	}
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		return "", ErrInvalid
	}
	peer, err := netip.ParseAddr(host)
	if err != nil || peer.Zone() != "" {
		return "", ErrInvalid
	}
	peer = peer.Unmap()
	if trustLoopbackProxy && peer.IsLoopback() {
		values := request.Header.Values("X-Real-IP")
		if len(values) != 1 {
			return "", ErrInvalid
		}
		peer, err = netip.ParseAddr(values[0])
		if err != nil || peer.Zone() != "" {
			return "", ErrInvalid
		}
	}
	return peer.Unmap().String(), nil
}
