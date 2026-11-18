package checksandbox

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// allApplicationPackages is the SID that Windows grants read access to its
// own and Program Files folders.
const allApplicationPackages = "S-1-15-2-1"

// grant adds an inheritable allow entry for sid to path's DACL; Windows
// propagates it to everything below.
func grant(path string, sid *windows.SID, mask windows.ACCESS_MASK) error {
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	current, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	updated, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: mask,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}}, current)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, updated, nil)
}

// ensureReadable makes path readable and executable by every sandbox: it
// is already when its DACL grants all application packages or the
// toolchain capability; otherwise the capability is granted, once.
func ensureReadable(path string, capability *windows.SID) error {
	everyPackage, err := windows.StringToSid(allApplicationPackages)
	if err != nil {
		return err
	}
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	if grantsRead(dacl, everyPackage) || grantsRead(dacl, capability) {
		return nil
	}
	return grant(path, capability, windows.GENERIC_READ|windows.GENERIC_EXECUTE)
}

// grantsRead reports whether dacl has an allow entry for sid that grants
// reading and executing.
func grantsRead(dacl *windows.ACL, sid *windows.SID) bool {
	const (
		readAndExecute = windows.FILE_READ_DATA | windows.FILE_EXECUTE
		inheritOnlyAce = 0x08
	)
	if dacl == nil {
		return false
	}
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(dacl, index, &ace) != nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags&inheritOnlyAce != 0 {
			continue
		}
		if !(*windows.SID)(unsafe.Pointer(&ace.SidStart)).Equals(sid) {
			continue
		}
		if ace.Mask&(windows.GENERIC_READ|windows.GENERIC_ALL) != 0 || ace.Mask&readAndExecute == readAndExecute {
			return true
		}
	}
	return false
}
