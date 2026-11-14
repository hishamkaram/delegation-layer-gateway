package httpguard

import (
	"net/http"
	"testing"
)

func TestClientIPRequiresExplicitLoopbackProxyTrust(t *testing.T) {
	for _, test := range []struct {
		name    string
		peer    string
		trusted bool
		headers []string
		want    string
	}{
		{name: "socket-default", peer: "192.0.2.10:443", headers: []string{"198.51.100.8"}, want: "192.0.2.10"},
		{name: "loopback-not-implicitly-trusted", peer: "127.0.0.1:1234", headers: []string{"198.51.100.8"}, want: "127.0.0.1"},
		{name: "remote-cannot-spoof", peer: "192.0.2.10:443", trusted: true, headers: []string{"198.51.100.8"}, want: "192.0.2.10"},
		{name: "trusted-loopback", peer: "127.0.0.1:1234", trusted: true, headers: []string{"198.51.100.8"}, want: "198.51.100.8"},
		{name: "ipv6-loopback", peer: "[::1]:1234", trusted: true, headers: []string{"2001:db8::8"}, want: "2001:db8::8"},
		{name: "mapped-address-one-bucket", peer: "127.0.0.1:1234", trusted: true, headers: []string{"::ffff:198.51.100.8"}, want: "198.51.100.8"},
		{name: "missing-proxy-address", peer: "127.0.0.1:1234", trusted: true},
		{name: "multiple-proxy-addresses", peer: "127.0.0.1:1234", trusted: true, headers: []string{"198.51.100.8", "192.0.2.10"}},
		{name: "comma-is-not-an-address", peer: "127.0.0.1:1234", trusted: true, headers: []string{"198.51.100.8,192.0.2.10"}},
		{name: "zone-is-not-a-client-key", peer: "127.0.0.1:1234", trusted: true, headers: []string{"fe80::8%zone"}},
		{name: "malformed-peer", peer: "not-a-socket", trusted: true, headers: []string{"198.51.100.8"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := &http.Request{RemoteAddr: test.peer, Header: make(http.Header)}
			for _, value := range test.headers {
				request.Header.Add("X-Real-IP", value)
			}
			request.Header.Set("X-Forwarded-For", "203.0.113.100")
			got, err := ClientIP(request, test.trusted)
			if got != test.want || (err != nil) != (test.want == "") {
				t.Fatalf("client key=%q error=%v, want %q", got, err, test.want)
			}
		})
	}
}
