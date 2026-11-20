package checksandbox

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// allApplicationPackages is the SID that Windows grants read access to its
// own and Program Files folders.
const allApplicationPackages = "S-1-15-2-1"

// scratchAccess is what the sandbox may do in its scratch: every file
// right (0x1ff), deleting and reading permissions, but not changing
// permissions or ownership, so a test cannot lock the account out of what
// it has written. A folder it creates with its own permissions from the
// start can still be locked; Windows lets every creator choose those.
const scratchAccess = windows.DELETE | windows.READ_CONTROL | windows.SYNCHRONIZE | 0x1ff

// grant adds an inheritable allow entry for sid to path's DACL; Windows
// propagates it to everything below.
func grant(path string, sid *windows.SID, mask windows.ACCESS_MASK) error {
	return changeAccess(path, sid, windows.GRANT_ACCESS, mask)
}

// revoke removes path's explicit entries for sid; Windows removes the
// entries they gave everything below.
func revoke(path string, sid *windows.SID) error {
	return changeAccess(path, sid, windows.REVOKE_ACCESS, 0)
}

func changeAccess(path string, sid *windows.SID, mode windows.ACCESS_MODE, mask windows.ACCESS_MASK) error {
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
		AccessMode:        mode,
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
// toolchain capability; otherwise the capability is granted, once, and the
// grant recorded so that RemoveToolchainGrants can take it back.
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
	if err := recordGrant(path); err != nil {
		return err
	}
	return grant(path, capability, windows.GENERIC_READ|windows.GENERIC_EXECUTE)
}

// grantsRead reports whether dacl has an allow entry for sid that grants
// reading and executing.
func grantsRead(dacl *windows.ACL, sid *windows.SID) bool {
	const readAndExecute = windows.FILE_READ_DATA | windows.FILE_EXECUTE
	for _, ace := range allowEntries(dacl, sid) {
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE == 0 &&
			(ace.Mask&(windows.GENERIC_READ|windows.GENERIC_ALL) != 0 || ace.Mask&readAndExecute == readAndExecute) {
			return true
		}
	}
	return false
}

// grantsExplicitly reports whether dacl has an allow entry for sid of its
// own rather than one inherited from a parent folder.
func grantsExplicitly(dacl *windows.ACL, sid *windows.SID) bool {
	for _, ace := range allowEntries(dacl, sid) {
		if ace.Header.AceFlags&windows.INHERITED_ACE == 0 {
			return true
		}
	}
	return false
}

// allowEntries lists dacl's allow entries for sid.
func allowEntries(dacl *windows.ACL, sid *windows.SID) []*windows.ACCESS_ALLOWED_ACE {
	if dacl == nil {
		return nil
	}
	var entries []*windows.ACCESS_ALLOWED_ACE
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(dacl, index, &ace) != nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		if (*windows.SID)(unsafe.Pointer(&ace.SidStart)).Equals(sid) {
			entries = append(entries, ace)
		}
	}
	return entries
}
