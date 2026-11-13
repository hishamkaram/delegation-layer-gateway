package deviceauth

import (
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

func validConfig(input Config) bool {
	if input.HTTPClient == nil || !visible(input.ClientID, 1024, false) || !visible(input.Audience, 4096, false) {
		return false
	}
	if !httpsURL(input.DeviceEndpoint) || !httpsURL(input.TokenEndpoint) || input.FlowTimeout < 0 || input.FlowTimeout > MaxFlowTimeout {
		return false
	}
	if len(input.Scopes) == 0 || len(input.Scopes) > 64 {
		return false
	}
	seen := make(map[string]bool, len(input.Scopes))
	for _, scope := range input.Scopes {
		if seen[scope] || !visible(scope, 128, false) || strings.ContainsAny(scope, "\"\\") {
			return false
		}
		seen[scope] = true
	}
	return true
}

func httpsURL(value string) bool {
	if len(value) == 0 || len(value) > 4096 || strings.TrimSpace(value) != value {
		return false
	}
	u, err := url.Parse(value)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.Fragment == "" && u.Opaque == ""
}

func visible(value string, limit int, spaces bool) bool {
	if len(value) == 0 || len(value) > limit || strings.TrimSpace(value) != value {
		return false
	}
	minimum := byte(33)
	if spaces {
		minimum = 32
	}
	for i := range len(value) {
		if value[i] < minimum || value[i] > 126 {
			return false
		}
	}
	return true
}

func parseResponse(body []byte, start, deadline time.Time) (oauth2.DeviceAuthResponse, error) {
	var response struct {
		DeviceCode              string          `json:"device_code"`
		UserCode                string          `json:"user_code"`
		VerificationURI         string          `json:"verification_uri"`
		VerificationURIComplete string          `json:"verification_uri_complete"`
		ExpiresIn               json.RawMessage `json:"expires_in"`
		Interval                json.RawMessage `json:"interval"`
	}
	if json.Unmarshal(body, &response) != nil || !visible(response.DeviceCode, 4096, false) || !visible(response.UserCode, 128, true) || !httpsURL(response.VerificationURI) {
		return oauth2.DeviceAuthResponse{}, ErrResponse
	}
	if response.VerificationURIComplete != "" && !sameVerificationOrigin(response.VerificationURI, response.VerificationURIComplete) {
		return oauth2.DeviceAuthResponse{}, ErrResponse
	}
	interval, valid := positiveSeconds(response.Interval, 5, maxIntervalSeconds)
	if !valid {
		return oauth2.DeviceAuthResponse{}, ErrResponse
	}
	if len(response.ExpiresIn) != 0 {
		expires, ok := positiveSeconds(response.ExpiresIn, 0, maxExpirySeconds)
		if !ok {
			return oauth2.DeviceAuthResponse{}, ErrResponse
		}
		issuerExpiry := start.Add(time.Duration(expires) * time.Second)
		if issuerExpiry.Before(deadline) {
			deadline = issuerExpiry
		}
	}
	return oauth2.DeviceAuthResponse{
		DeviceCode:              response.DeviceCode,
		UserCode:                response.UserCode,
		VerificationURI:         response.VerificationURI,
		VerificationURIComplete: response.VerificationURIComplete,
		Expiry:                  deadline,
		Interval:                interval,
	}, nil
}

func positiveSeconds(raw json.RawMessage, fallback, maximum int64) (int64, bool) {
	if len(raw) == 0 {
		return fallback, true
	}
	value, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	return value, err == nil && value > 0 && value <= maximum
}

func sameVerificationOrigin(base, complete string) bool {
	if !httpsURL(complete) {
		return false
	}
	left, err := url.Parse(base)
	if err != nil {
		return false
	}
	right, err := url.Parse(complete)
	return err == nil && strings.EqualFold(left.Host, right.Host)
}
