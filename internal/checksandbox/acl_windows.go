package checksandbox

import (
	"slices"
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

// grant adds inheritable allow entries for sids to path's DACL; Windows
// propagates them to everything below.
func grant(path string, mask windows.ACCESS_MASK, sids ...*windows.SID) error {
	entries := make([]windows.EXPLICIT_ACCESS, len(sids))
	for index, sid := range sids {
		entries[index] = access(sid, windows.GRANT_ACCESS, mask)
	}
	return changeAccess(path, entries...)
}

// revoke removes path's explicit entries for sids; Windows removes the
// entries they gave everything below.
func revoke(path string, sids ...*windows.SID) error {
	entries := make([]windows.EXPLICIT_ACCESS, len(sids))
	for index, sid := range sids {
		entries[index] = access(sid, windows.REVOKE_ACCESS, 0)
	}
	return changeAccess(path, entries...)
}

// access is an inheritable change of sid's access.
func access(sid *windows.SID, mode windows.ACCESS_MODE, mask windows.ACCESS_MASK) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: mask,
		AccessMode:        mode,
		Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
}

func changeAccess(path string, entries ...windows.EXPLICIT_ACCESS) error {
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	current, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	updated, err := windows.ACLFromEntries(entries, current)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, updated, nil)
}

// ensureReadable makes path readable and executable by every sandbox.
// Windows lets a sandbox read only what both its package side (all
// application packages or the toolchain capability) and its token side (a
// group its token keeps) may read. Each side path does not grant yet is
// granted, once, to the capability or the logon session, and the grant is
// recorded so that RemoveToolchainGrants can take it back. A logon session's
// grant replaces those of earlier sessions.
func ensureReadable(path string, capability, logon *windows.SID) error {
	everyPackage, err := windows.StringToSid(allApplicationPackages)
	if err != nil {
		return err
	}
	groups, err := keptGroups()
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
	var entries []windows.EXPLICIT_ACCESS
	const readAndExecute = windows.GENERIC_READ | windows.GENERIC_EXECUTE
	if !grantsRead(dacl, everyPackage) && !grantsRead(dacl, capability) {
		entries = append(entries, access(capability, windows.GRANT_ACCESS, readAndExecute))
	}
	if !slices.ContainsFunc(groups, func(group *windows.SID) bool { return grantsRead(dacl, group) }) {
		for _, earlier := range explicitLogonEntries(dacl) {
			entries = append(entries, access(earlier, windows.REVOKE_ACCESS, 0))
		}
		entries = append(entries, access(logon, windows.GRANT_ACCESS, readAndExecute))
	}
	if len(entries) == 0 {
		return nil
	}
	if err := recordGrant(path); err != nil {
		return err
	}
	return changeAccess(path, entries...)
}

// grantsRead reports whether dacl has an allow entry for sid that grants
// reading and executing.
func grantsRead(dacl *windows.ACL, sid *windows.SID) bool {
	const readAndExecute = windows.FILE_READ_DATA | windows.FILE_EXECUTE
	for _, ace := range allowEntries(dacl, sid.Equals) {
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
	for _, ace := range allowEntries(dacl, sid.Equals) {
		if ace.Header.AceFlags&windows.INHERITED_ACE == 0 {
			return true
		}
	}
	return false
}

// explicitLogonEntries lists the logon sessions that dacl has allow entries
// of its own for.
func explicitLogonEntries(dacl *windows.ACL) []*windows.SID {
	var sids []*windows.SID
	for _, ace := range allowEntries(dacl, isLogonSid) {
		if ace.Header.AceFlags&windows.INHERITED_ACE == 0 {
			sids = append(sids, aceSid(ace))
		}
	}
	return sids
}

// allowEntries lists dacl's allow entries for the SIDs that match.
func allowEntries(dacl *windows.ACL, match func(*windows.SID) bool) []*windows.ACCESS_ALLOWED_ACE {
	if dacl == nil {
		return nil
	}
	var entries []*windows.ACCESS_ALLOWED_ACE
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(dacl, index, &ace) != nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		if match(aceSid(ace)) {
			entries = append(entries, ace)
		}
	}
	return entries
}

func aceSid(ace *windows.ACCESS_ALLOWED_ACE) *windows.SID {
	return (*windows.SID)(unsafe.Pointer(&ace.SidStart))
}
