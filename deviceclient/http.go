package deviceclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"os"
	"syscall"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
)

const maxHTTPBody = 256 << 10

func httpClient(caFile string) (*http.Client, *http.Transport, error) {
	var roots *x509.CertPool
	if caFile != "" {
		data, err := boundedFile(caFile, 128<<10, publicTrustFile)
		if err != nil {
			return nil, nil, failed(ErrConfiguration, err)
		}
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(data) {
			return nil, nil, ErrConfiguration
		}
	}
	transport := &http.Transport{DialContext: (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext, MaxConnsPerHost: 4, MaxIdleConns: 4, IdleConnTimeout: 30 * time.Second, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}}
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return client, transport, nil
}

func privateRead(path string, maximum int64) ([]byte, error) {
	return boundedFile(path, maximum, func(info os.FileInfo) bool { return private(info, false) })
}

func publicTrustFile(info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && (stat.Uid == 0 || stat.Uid == uint32(os.Geteuid()))
}

func boundedFile(path string, maximum int64, acceptable func(os.FileInfo) bool) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, failed(ErrProfile, err)
	}
	info, err := file.Stat()
	if err != nil || !acceptable(info) || info.Size() > maximum {
		return nil, failed(ErrProfile, errors.Join(err, file.Close()))
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maximum+1))
	closeErr := file.Close()
	if joined := errors.Join(readErr, closeErr); joined != nil {
		return nil, failed(ErrProfile, joined)
	}
	if int64(len(data)) > maximum {
		return nil, ErrProfile
	}
	return data, nil
}

func requestJSON[T any](ctx context.Context, client *http.Client, method, address, token string, input any, output *T, strict bool) (result error) {
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil || len(encoded) > maxHTTPBody {
			return ErrConfiguration
		}
		body = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, address, body)
	if err != nil {
		return ErrConfiguration
	}
	request.Header.Set("Accept", "application/json")
	if input != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := client.Do(request)
	if err != nil {
		return failed(ErrTransport, ctx.Err())
	}
	defer func() {
		if closeErr := response.Body.Close(); closeErr != nil {
			result = errors.Join(result, ErrTransport)
		}
	}()
	data, err := io.ReadAll(io.LimitReader(response.Body, maxHTTPBody+1))
	if err != nil {
		return ErrTransport
	}
	if len(data) > maxHTTPBody {
		return ErrDiscovery
	}
	if err = checkedStatus(response.StatusCode); err != nil {
		return err
	}

	return decodeResponse(data, response.Header.Get("Content-Type"), output, strict)
}

func decodeResponse[T any](data []byte, contentType string, output *T, strict bool) error {
	content, _, err := mime.ParseMediaType(contentType)
	if err != nil || content != "application/json" {
		return ErrDiscovery
	}
	if strict {
		if protocol.DecodeStrict(data, output, maxHTTPBody) != nil {
			return ErrDiscovery
		}
	} else if json.Unmarshal(data, output) != nil {
		return ErrDiscovery
	}
	return nil
}

func checkedStatus(status int) error {
	switch status {
	case http.StatusOK:
		return nil
	case http.StatusForbidden, http.StatusUnauthorized:
		return ErrDenied
	case http.StatusConflict:
		return ErrConflict
	case http.StatusNotFound:
		return ErrUnsupported
	default:
		return ErrTransport
	}
}
