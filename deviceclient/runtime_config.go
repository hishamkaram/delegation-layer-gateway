package deviceclient

import (
	"bytes"
	"crypto/x509"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/hishamkaram/delegation-layer-gateway/internal/connector"
	"github.com/hishamkaram/delegation-layer-gateway/internal/deviceruntime"
	"github.com/hishamkaram/delegation-layer-gateway/internal/domain"
)

type runtimeConfiguration struct {
	adapter     connector.Config
	wss         url.URL
	deviceID    domain.DeviceID
	serverCA    []byte
	systemRoots *x509.CertPool
	deviceCA    []byte
}

var _ deviceruntime.Configuration = (*runtimeConfiguration)(nil)

func newRuntimeConfiguration(directory string, p profile) (runtimeConfiguration, error) {
	var result runtimeConfiguration
	executable, err := os.Stat(p.DelegateExecutable)
	if err != nil || !executable.Mode().IsRegular() || executable.Mode().Perm()&0o111 == 0 {
		return result, ErrConfiguration
	}
	selectedRoot, err := os.Stat(p.DelegateRoot)
	if err != nil || !selectedRoot.IsDir() {
		return result, ErrConfiguration
	}
	temporary := filepath.Join(directory, "runtime")
	if _, err = prepareProfileDirectory(temporary, true); err != nil {
		return result, err
	}
	endpoint, err := url.Parse(p.Descriptor.DeviceWSSURL)
	if err != nil {
		return result, ErrConfiguration
	}
	result.wss = *endpoint
	result.deviceCA = []byte(p.Descriptor.DeviceCAPEM)
	if p.PrivateCAFile != "" {
		result.serverCA, err = boundedFile(p.PrivateCAFile, 128<<10, publicTrustFile)
		if err != nil {
			return runtimeConfiguration{}, err
		}
	}
	if result.serverCA == nil {
		result.systemRoots, err = x509.SystemCertPool()
		if err != nil {
			return runtimeConfiguration{}, failed(ErrConfiguration, err)
		}
	}
	if _, err = result.Roots(); err != nil {
		return runtimeConfiguration{}, err
	}
	if _, err = result.DeviceRoots(); err != nil {
		return runtimeConfiguration{}, err
	}
	result.adapter = connector.Config{Executable: p.DelegateExecutable, TemporaryDirectory: temporary, GatewayID: domain.GatewayID(p.Descriptor.GatewayID), ProjectStore: newProfileProjects(directory), ControlTimeout: connector.DefaultControlTimeout}
	return result, nil
}
func (c *runtimeConfiguration) Adapter() connector.Config { return c.adapter }
func (c *runtimeConfiguration) DeviceID() domain.DeviceID { return c.deviceID }
func (c *runtimeConfiguration) WSSURL() *url.URL          { copy := c.wss; return &copy }
func (c *runtimeConfiguration) NetworkTimeout() time.Duration {
	return connector.DefaultControlTimeout + 5*time.Second
}

func (c *runtimeConfiguration) Roots() (*x509.CertPool, error) {
	if c.serverCA == nil {
		if c.systemRoots == nil {
			return nil, ErrConfiguration
		}
		return c.systemRoots.Clone(), nil
	}
	return runtimeTrustPool(c.serverCA)
}

func (c *runtimeConfiguration) DeviceRoots() (*x509.CertPool, error) {
	return runtimeTrustPool(c.deviceCA)
}

func runtimeTrustPool(data []byte) (*x509.CertPool, error) {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(bytes.Clone(data)) {
		return nil, ErrConfiguration
	}
	return roots, nil
}
