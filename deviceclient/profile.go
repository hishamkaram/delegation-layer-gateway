package deviceclient

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"syscall"

	"github.com/hishamkaram/delegation-layer-gateway/internal/connector"
	"github.com/hishamkaram/delegation-layer-gateway/internal/instance"
	"github.com/hishamkaram/delegation-layer-gateway/internal/protocol"
	"github.com/hishamkaram/delegation-layer-gateway/internal/selfservice/contract"
)

const (
	profileName     = "profile.json"
	maxProfileBytes = 8 << 20
)

type profile struct {
	Version             int                 `json:"schema_version"`
	Issuer              issuerEndpoints     `json:"issuer_endpoints"`
	Descriptor          contract.Descriptor `json:"descriptor"`
	DelegateExecutable  string              `json:"delegate_executable"`
	DelegateRoot        string              `json:"delegate_root"`
	DelegateRootContext string              `json:"delegate_root_context"`
	DeviceName          string              `json:"device_name"`
	PrivateCAFile       string              `json:"private_ca_file,omitempty"`
	Workspaces          []workspaceRecord   `json:"workspaces"`
	// Providers are defaults copied only when a workspace is approved.
	// Each workspace record owns its current execution ceiling.
	Providers []ProviderPolicy `json:"providers"`
	Pins      []projectRecord  `json:"pins,omitempty"`
}

// profileStore owns descriptor/local-configuration mutation, independently of
// identity.Store's key/credential lease. Readers see only committed rename data.
type profileStore struct {
	root      *os.Root
	directory *os.File
	lease     *instance.Lease
	value     *profile
	uncertain bool
}

func openProfile(directory string, create, exclusive bool) (*profileStore, error) {
	if !localPath(directory) {
		return nil, ErrProfile
	}
	info, err := prepareProfileDirectory(directory, create)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, failed(ErrProfile, err)
	}
	dir, err := root.Open(".")
	if err != nil {
		return nil, failed(ErrProfile, errors.Join(err, root.Close()))
	}
	s := &profileStore{root: root, directory: dir}
	held, err := dir.Stat()
	if err != nil || !os.SameFile(info, held) {
		return nil, failed(ErrProfile, errors.Join(err, s.Close()))
	}
	if exclusive {
		s.lease, err = instance.Acquire(filepath.Join(directory, "profile.lock"))
		if err != nil {
			kind := ErrProfile
			if errors.Is(err, instance.ErrBusy) {
				kind = ErrBusy
			}
			return nil, failed(kind, errors.Join(err, s.Close()))
		}
	}
	if err = s.load(); err != nil {
		return nil, failed(ErrProfile, errors.Join(err, s.Close()))
	}
	if s.value == nil && create {
		if err = s.checkEmpty(); err != nil {
			return nil, failed(ErrConflict, errors.Join(err, s.Close()))
		}
	}

	return s, nil
}

func prepareProfileDirectory(directory string, create bool) (os.FileInfo, error) {
	if create {
		err := os.Mkdir(directory, 0o700)
		if err != nil && !errors.Is(err, os.ErrExist) {
			return nil, failed(ErrProfile, err)
		}
		if err == nil {
			parent, openErr := os.Open(filepath.Dir(directory))
			if openErr != nil {
				return nil, failed(ErrPersistence, openErr)
			}
			if joined := errors.Join(parent.Sync(), parent.Close()); joined != nil {
				return nil, failed(ErrPersistence, joined)
			}
		}
	}
	info, err := os.Lstat(directory)
	if err != nil || !private(info, true) {
		return nil, failed(ErrProfile, err)
	}
	return info, nil
}

func (s *profileStore) checkEmpty() error {
	names, err := s.directory.ReadDir(-1)
	if err != nil {
		return err
	}
	for _, entry := range names {
		if entry.Name() != "profile.lock" {
			return ErrConflict
		}
	}
	return nil
}

func (p profile) valid() bool { return p.validBase() && validProjectRecords(p) }
func (p profile) validBase() bool {
	if p.Version != 2 || !localPath(p.DelegateExecutable) || !localPath(p.DelegateRoot) || !opaqueContext(p.DelegateRootContext) || !validName(p.DeviceName) {
		return false
	}
	if p.PrivateCAFile != "" && !localPath(p.PrivateCAFile) {
		return false
	}
	if !validWorkspaceRecords(p.Workspaces) || !validProviders(p.Providers) || validDescriptor(p.Descriptor, p.Descriptor.PublicURL) != nil {
		return false
	}
	return p.Issuer.validFor(p.Descriptor)
}

func private(info os.FileInfo, directory bool) bool {
	if info == nil {
		return false
	}
	mode := os.FileMode(0o600)
	if directory {
		mode = 0o700
	}
	if info.IsDir() != directory || info.Mode().Perm() != mode || info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || (!directory && !info.Mode().IsRegular()) {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid()) && (directory || stat.Nlink == 1)
}

func (s *profileStore) load() error {
	file, err := s.root.OpenFile(profileName, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil || !private(info, false) || info.Size() > maxProfileBytes {
		return errors.Join(ErrProfile, err, file.Close())
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxProfileBytes+1))
	closeErr := file.Close()
	if joined := errors.Join(readErr, closeErr); joined != nil {
		return joined
	}
	var current profile
	if protocol.DecodeStrict(data, &current, maxProfileBytes) != nil || !current.validBase() {
		return ErrProfile
	}

	if !validProjectRecords(current) {
		return failed(ErrProfile, connector.ErrEvidence)
	}
	if _, err := encodeProfile(current, true); err != nil {
		return err
	}
	s.value = &current
	return nil
}

func (s *profileStore) save(next profile) error { return s.savePartition(next, false) }
func (s *profileStore) savePartition(next profile, revocation bool) error {
	if s.lease == nil || s.uncertain {
		return ErrPersistence
	}
	data, err := encodeProfile(next, revocation)
	if err != nil {
		return err
	}

	var name string
	var file *os.File
	for i := 0; i < 32; i++ {
		name = ".profile-" + strconv.Itoa(i) + ".tmp"
		file, err = s.root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
		if !errors.Is(err, os.ErrExist) {
			break
		}
	}
	if err != nil {
		return failed(ErrPersistence, err)
	}
	_, writeErr := file.Write(data)
	syncErr := error(nil)
	if writeErr == nil {
		syncErr = file.Sync()
	}
	if joined := errors.Join(writeErr, syncErr, file.Close()); joined != nil {
		return failed(ErrPersistence, errors.Join(joined, s.root.Remove(name)))
	}
	if err = s.root.Rename(name, profileName); err != nil {
		return failed(ErrPersistence, errors.Join(err, s.root.Remove(name)))
	}
	s.value = &next
	if err = s.directory.Sync(); err != nil {
		s.uncertain = true
		return failed(ErrPersistence, err)
	}
	return nil
}

func (s *profileStore) Close() error {
	var leaseErr error
	if s.lease != nil {
		leaseErr = s.lease.Close()
	}
	return errors.Join(s.root.Close(), s.directory.Close(), leaseErr)
}

func pinnedProfile(options ConnectOptions, descriptor contract.Descriptor, issuer issuerEndpoints, existing *profile, random io.Reader) (profile, error) {
	next := profile{Version: 2, Descriptor: descriptor, Issuer: issuer, DelegateExecutable: options.DelegateExecutable, DelegateRoot: options.DelegateRoot, DelegateRootContext: options.DelegateRootContext, DeviceName: options.DeviceName, PrivateCAFile: options.PrivateCAFile, Providers: options.Providers}
	if existing == nil {
		if next.DeviceName == "" {
			return profile{}, ErrConfiguration
		}
		workspaces, err := initialWorkspaces(options.Workspaces, options.Providers, random)
		if err != nil {
			return profile{}, err
		}
		next.Workspaces = workspaces
		return next, nil
	}
	if !reflect.DeepEqual(existing.Descriptor, descriptor) || (issuer != (issuerEndpoints{}) && existing.Issuer != (issuerEndpoints{}) && existing.Issuer != issuer) {
		return profile{}, ErrTrustChanged
	}
	if !sameProfileSource(options, *existing) {
		return profile{}, ErrConflict
	}
	if next.DeviceName == "" {
		next.DeviceName = existing.DeviceName
	}
	if next.DeviceName != existing.DeviceName {
		return profile{}, ErrConflict
	}
	next.Workspaces = existing.Workspaces
	next.Pins = existing.Pins
	next.Issuer = existing.Issuer
	if next.Providers == nil {
		next.Providers = existing.Providers
	}
	if (options.Workspaces != nil && !sameApprovals(options.Workspaces, existing.Workspaces, existing.Providers)) || !reflect.DeepEqual(next.Providers, existing.Providers) {
		return profile{}, ErrConflict
	}
	return next, nil
}

func sameProfileSource(options ConnectOptions, existing profile) bool {
	return options.DelegateExecutable == existing.DelegateExecutable && options.DelegateRoot == existing.DelegateRoot && options.DelegateRootContext == existing.DelegateRootContext && options.PrivateCAFile == existing.PrivateCAFile
}
