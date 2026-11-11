package mcpadapter

import (
	"bytes"
	"errors"
	"io"
	"mime"
	"net/http"
)

const maxRequestBodyBytes = 1 << 20

// replayBody retains the HTTP server's original body-close ownership.
type replayBody struct {
	io.Reader
	io.Closer
}

// singleMessage admits one JSON-RPC message after authentication and rate
// admission. The SDK still owns JSON-RPC parsing and protocol negotiation.
func singleMessage(writer http.ResponseWriter, request *http.Request) bool {
	if request.Method != http.MethodPost || request.Body == nil {
		return true
	}
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return true // Preserve the SDK's content-type rejection.
	}
	data, err := io.ReadAll(io.LimitReader(request.Body, maxRequestBodyBytes+1))
	var overflow *http.MaxBytesError
	if errors.As(err, &overflow) || len(data) > maxRequestBodyBytes {
		http.Error(writer, "request_body_too_large", http.StatusRequestEntityTooLarge)
		return false
	}
	if err != nil {
		http.Error(writer, "request_body_unavailable", http.StatusBadRequest)
		return false
	}
	trimmed := bytes.TrimLeft(data, " \t\r\n")
	if len(trimmed) > 0 && trimmed[0] == '[' {
		http.Error(writer, "batch_requests_unsupported", http.StatusBadRequest)
		return false
	}
	request.Body = replayBody{Reader: bytes.NewReader(data), Closer: request.Body}
	return true
}
