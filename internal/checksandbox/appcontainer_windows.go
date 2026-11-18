package checksandbox

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// userenv and kernelbase are system DLLs; NewLazySystemDLL loads them from
// the system directory only.
var (
	userenv                        = windows.NewLazySystemDLL("userenv.dll")
	procCreateAppContainerProfile  = userenv.NewProc("CreateAppContainerProfile")
	procDeleteAppContainerProfile  = userenv.NewProc("DeleteAppContainerProfile")
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
}

func newAppContainer() (*appContainer, error) {
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		return nil, err
	}
	name := "OpenTrestle.Check." + hex.EncodeToString(random)
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
	return &appContainer{name: name, sid: copied, capability: capability}, nil
}

func (container *appContainer) close() {
	if name16, err := windows.UTF16PtrFromString(container.name); err == nil {
		deleteProfile(name16)
	}
}

func deleteProfile(name *uint16) {
	_, _, _ = procDeleteAppContainerProfile.Call(uintptr(unsafe.Pointer(name)))
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
	flags := uint32(windows.CREATE_SUSPENDED | windows.CREATE_NO_WINDOW | windows.CREATE_UNICODE_ENVIRONMENT | windows.EXTENDED_STARTUPINFO_PRESENT)
	err = windows.CreateProcess(application16, commandLine16, nil, nil, true, flags, &environment[0], directory16, &startup.StartupInfo, &information)
	return information, err
}
