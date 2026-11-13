//go:build e2e

package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

const maxFaultRequestBytes = 1 << 20

var (
	errDiscardedToolResponse = errors.New("fixture discarded complete dispatch response")
	errExpectedResponseLoss  = errors.New("fixture expected response loss with completed cleanup")
)

// discardResponseTransport is an opt-in client-side fault, outside the pinned
// and bounded transport. It discards only a fully received dispatch HTTP 200;
// it never retries, mutates a request body, or changes task execution ownership.
type discardResponseTransport struct{ base http.RoundTripper }

func (d discardResponseTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	discard, err := classifyDispatchRequest(request)
	if err != nil {
		if request != nil && request.Body != nil {
			err = errors.Join(err, request.Body.Close())
		}
		return nil, err
	}
	response, err := d.base.RoundTrip(request)
	if err != nil {
		if response != nil && response.Body != nil {
			err = errors.Join(err, response.Body.Close())
		}
		return nil, err
	}
	if !discard || response == nil || response.StatusCode != http.StatusOK {
		return response, nil
	}
	if response.Body == nil {
		return nil, errors.New("fixture discard response body missing")
	}
	if err = response.Body.Close(); err != nil {
		return nil, err
	}
	return nil, errDiscardedToolResponse
}

func classifyDispatchRequest(request *http.Request) (bool, error) {
	if request == nil {
		return false, errors.New("fixture fault request missing")
	}
	if request.Method != http.MethodPost {
		return false, nil
	}
	data, err := copyFaultRequest(request)
	if err != nil {
		return false, err
	}
	var message struct {
		JSONRPC string          `json:"jsonrpc"`
		Method  string          `json:"method"`
		Params  json.RawMessage `json:"params"`
	}
	if err = json.Unmarshal(data, &message); err != nil {
		return false, err
	}
	if message.JSONRPC != "2.0" || message.Method == "" {
		return false, errors.New("fixture fault request is not JSON-RPC")
	}
	if message.Method != "tools/call" {
		return false, nil
	}
	var params struct {
		Name string `json:"name"`
	}
	if err = json.Unmarshal(message.Params, &params); err != nil {
		return false, err
	}
	if params.Name == "" {
		return false, errors.New("fixture fault tool name missing")
	}
	return params.Name == "dispatch_task", nil
}

// The wire sentinel is produced only after both the original bounded wire body
// and retained body closed successfully. SDK session cleanup is checked last;
// any failure there must remain an ordinary, possibly-sent helper failure.
func finishMCPCall(callErr, closeErr error) error {
	if closeErr == nil && errors.Is(callErr, errDiscardedToolResponse) {
		return errExpectedResponseLoss
	}
	return errors.Join(callErr, closeErr)
}

// Copy ownership is independent of the original HTTP body. The caller closes
// the untouched original whenever classification cannot safely reach the wire.
func copyFaultRequest(request *http.Request) ([]byte, error) {
	if request.Body == nil || request.GetBody == nil {
		return nil, errors.New("fixture fault request copy unavailable")
	}
	copyBody, err := request.GetBody()
	if err != nil {
		if copyBody != nil {
			err = errors.Join(err, copyBody.Close())
		}
		return nil, err
	}
	if copyBody == nil {
		return nil, errors.New("fixture fault request copy missing")
	}
	data, readErr := io.ReadAll(io.LimitReader(copyBody, maxFaultRequestBytes+1))
	closeErr := copyBody.Close()
	if len(data) > maxFaultRequestBytes {
		readErr = errors.Join(readErr, errors.New("fixture fault request limit exceeded"))
	}
	if err = errors.Join(readErr, closeErr); err != nil {
		return nil, err
	}
	return data, nil
}
