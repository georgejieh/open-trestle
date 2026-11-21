package checksandbox

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// userenv and kernelbase are system DLLs; NewLazySystemDLL loads them from
// the system directory only.
var (
	userenv                        = windows.NewLazySystemDLL("userenv.dll")
	procCreateAppContainerProfile  = userenv.NewProc("CreateAppContainerProfile")
	procDeleteAppContainerProfile  = userenv.NewProc("DeleteAppContainerProfile")
	procGetAppContainerFolderPath  = userenv.NewProc("GetAppContainerFolderPath")
	kernelbase                     = windows.NewLazySystemDLL("kernelbase.dll")
	procDeriveCapabilitySidsByName = kernelbase.NewProc("DeriveCapabilitySidsFromName")
)

// toolchainCapability names the capability whose SID the toolchain and
// cache folders grant read and execute access to. Every sandbox carries it;
// only the sandbox's own package SID may write its scratch.
const toolchainCapability = "openTrestleCheckToolchains"

const procThreadAttributeSecurityCapabilities = 0x00020009

// securityCapabilities is SECURITY_CAPABILITIES.
type securityCapabilities struct {
	AppContainerSid *windows.SID
	Capabilities    *windows.SIDAndAttributes
	CapabilityCount uint32
	Reserved        uint32
}

// appContainer is a fresh AppContainer profile for one run. Its package SID
// is granted nothing outside the run's scratch.
type appContainer struct {
	name       string
	sid        *windows.SID
	capability *windows.SID
	// logon is the logon session's SID, which the sandbox's folders grant
	// because its token does not match the user; see restrictedToken.
	logon *windows.SID
	// folder is the profile's own storage, which the sandbox may write.
	folder string
}

// profilePrefix starts the name of every sandbox's AppContainer profile.
const profilePrefix = "OpenTrestle.Check."

func newAppContainer() (*appContainer, error) {
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		return nil, err
	}
	name := profilePrefix + hex.EncodeToString(random)
	name16, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	var sid *windows.SID
	result, _, _ := procCreateAppContainerProfile.Call(uintptr(unsafe.Pointer(name16)), uintptr(unsafe.Pointer(name16)), uintptr(unsafe.Pointer(name16)), 0, 0, uintptr(unsafe.Pointer(&sid)))
	if result != 0 {
		return nil, fmt.Errorf("CreateAppContainerProfile failed with 0x%08x", uint32(result))
	}
	copied, err := sid.Copy()
	_ = windows.FreeSid(sid)
	if err != nil {
		deleteProfile(name16)
		return nil, err
	}
	capability, err := capabilitySid(toolchainCapability)
	if err != nil {
		deleteProfile(name16)
		return nil, err
	}
	logon, err := logonSid()
	if err != nil {
		deleteProfile(name16)
		return nil, err
	}
	folder, err := profileFolder(copied)
	if err == nil {
		// Windows gives the package full control of its folder; it gets the
		// scratch's rights there instead (see scratchAccess).
		err = changeAccess(folder, access(copied, windows.SET_ACCESS, scratchAccess), access(logon, windows.GRANT_ACCESS, scratchAccess))
	}
	if err != nil {
		deleteProfile(name16)
		return nil, err
	}
	return &appContainer{name: name, sid: copied, capability: capability, logon: logon, folder: folder}, nil
}

// profileFolder is the storage Windows gives the AppContainer profile.
func profileFolder(sid *windows.SID) (string, error) {
	sid16, err := windows.UTF16PtrFromString(sid.String())
	if err != nil {
		return "", err
	}
	var path *uint16
	if result, _, _ := procGetAppContainerFolderPath.Call(uintptr(unsafe.Pointer(sid16)), uintptr(unsafe.Pointer(&path))); result != 0 {
		return "", fmt.Errorf("GetAppContainerFolderPath failed with 0x%08x", uint32(result))
	}
	defer windows.CoTaskMemFree(unsafe.Pointer(path))
	return windows.UTF16PtrToString(path), nil
}

func (container *appContainer) close() {
	if name16, err := windows.UTF16PtrFromString(container.name); err == nil {
		deleteProfile(name16)
	}
}

func deleteProfile(name *uint16) {
	_, _, _ = procDeleteAppContainerProfile.Call(uintptr(unsafe.Pointer(name)))
}

// sweepProfiles deletes the sandbox profiles whose folders, named after the
// profile in lower case, are older than cutoff: what runs that were killed
// left behind.
func sweepProfiles(cutoff time.Time) {
	local, err := os.UserCacheDir()
	if err != nil {
		return
	}
	entries, err := os.ReadDir(filepath.Join(local, "Packages"))
	if err != nil {
		return
	}
	for _, entry := range entries {
		if !strings.HasPrefix(strings.ToLower(entry.Name()), strings.ToLower(profilePrefix)) || !olderThan(entry, cutoff) {
			continue
		}
		if name16, err := windows.UTF16PtrFromString(entry.Name()); err == nil {
			deleteProfile(name16)
		}
	}
}

// capabilitySid derives the SID of a named capability.
func capabilitySid(name string) (*windows.SID, error) {
	name16, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	var groups, capabilities **windows.SID
	var groupCount, capabilityCount uint32
	ok, _, callErr := procDeriveCapabilitySidsByName.Call(uintptr(unsafe.Pointer(name16)),
		uintptr(unsafe.Pointer(&groups)), uintptr(unsafe.Pointer(&groupCount)),
		uintptr(unsafe.Pointer(&capabilities)), uintptr(unsafe.Pointer(&capabilityCount)))
	if ok == 0 {
		return nil, callErr
	}
	defer freeSidArray(groups, groupCount)
	defer freeSidArray(capabilities, capabilityCount)
	if capabilityCount != 1 {
		return nil, errors.New("the capability SID could not be derived")
	}
	return (*capabilities).Copy()
}

// freeSidArray frees an array of SIDs allocated with LocalAlloc, and the
// array itself.
func freeSidArray(array **windows.SID, count uint32) {
	if array == nil {
		return
	}
	for _, sid := range unsafe.Slice(array, count) {
		_, _ = windows.LocalFree(windows.Handle(unsafe.Pointer(sid)))
	}
	_, _ = windows.LocalFree(windows.Handle(unsafe.Pointer(array)))
}

// startSuspended creates the process suspended inside the AppContainer,
// with the toolchain capability, inheriting only the given handles.
func (container *appContainer) startSuspended(application, commandLine string, environment []uint16, directory string, inherit []windows.Handle) (windows.ProcessInformation, error) {
	var information windows.ProcessInformation
	attributes, err := windows.NewProcThreadAttributeList(2)
	if err != nil {
		return information, err
	}
	defer attributes.Delete()
	capability := windows.SIDAndAttributes{Sid: container.capability, Attributes: windows.SE_GROUP_ENABLED}
	capabilities := securityCapabilities{AppContainerSid: container.sid, Capabilities: &capability, CapabilityCount: 1}
	if err := attributes.Update(procThreadAttributeSecurityCapabilities, unsafe.Pointer(&capabilities), unsafe.Sizeof(capabilities)); err != nil {
		return information, err
	}
	if err := attributes.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&inherit[0]), uintptr(len(inherit))*unsafe.Sizeof(inherit[0])); err != nil {
		return information, err
	}
	startup := windows.StartupInfoEx{ProcThreadAttributeList: attributes.List()}
	startup.Cb = uint32(unsafe.Sizeof(startup))
	startup.Flags = windows.STARTF_USESTDHANDLES
	startup.StdInput, startup.StdOutput, startup.StdErr = inherit[0], inherit[1], inherit[2]
	application16, err := windows.UTF16PtrFromString(application)
	if err != nil {
		return information, err
	}
	commandLine16, err := windows.UTF16PtrFromString(commandLine)
	if err != nil {
		return information, err
	}
	directory16, err := windows.UTF16PtrFromString(directory)
	if err != nil {
		return information, err
	}
	token, err := restrictedToken(container.logon)
	if err != nil {
		return information, err
	}
	defer token.Close()
	flags := uint32(windows.CREATE_SUSPENDED | windows.CREATE_NO_WINDOW | windows.CREATE_UNICODE_ENVIRONMENT | windows.EXTENDED_STARTUPINFO_PRESENT)
	err = windows.CreateProcessAsUser(token, application16, commandLine16, nil, nil, true, flags, &environment[0], directory16, &startup.StartupInfo, &information)
	return information, err
}
