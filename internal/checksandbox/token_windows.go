package checksandbox

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	advapi32                  = windows.NewLazySystemDLL("advapi32.dll")
	procCreateRestrictedToken = advapi32.NewProc("CreateRestrictedToken")
)

// restrictedToken is this process's token with the user's SID made
// deny-only, so that the sandbox gets nothing granted to the user alone,
// such as the user's registry hive. Folders it needs grant the logon
// session's SID instead, and so does what the sandbox creates, which it
// could otherwise not open again: without that a console cannot start.
func restrictedToken(logon *windows.SID) (windows.Token, error) {
	var own windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY|windows.TOKEN_ASSIGN_PRIMARY|windows.TOKEN_ADJUST_DEFAULT, &own); err != nil {
		return 0, err
	}
	defer own.Close()
	user, err := own.GetTokenUser()
	if err != nil {
		return 0, err
	}
	disabled := windows.SIDAndAttributes{Sid: user.User.Sid}
	var restricted windows.Token
	if ok, _, err := procCreateRestrictedToken.Call(uintptr(own), 0, 1, uintptr(unsafe.Pointer(&disabled)), 0, 0, 0, 0, uintptr(unsafe.Pointer(&restricted))); ok == 0 {
		return 0, err
	}
	if err := setDefaultDacl(restricted, logon); err != nil {
		restricted.Close()
		return 0, err
	}
	return restricted, nil
}

// setDefaultDacl gives what token's processes create full control to the
// logon session and SYSTEM.
func setDefaultDacl(token windows.Token, logon *windows.SID) error {
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	dacl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		access(logon, windows.GRANT_ACCESS, windows.GENERIC_ALL), access(system, windows.GRANT_ACCESS, windows.GENERIC_ALL),
	}, nil)
	if err != nil {
		return err
	}
	// TOKEN_DEFAULT_DACL
	info := struct{ DefaultDacl *windows.ACL }{dacl}
	return windows.SetTokenInformation(token, windows.TokenDefaultDacl, (*byte)(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)))
}

// logonSid is the SID of this process's logon session. Only processes of
// that session have it.
func logonSid() (*windows.SID, error) {
	groups, err := windows.GetCurrentProcessToken().GetTokenGroups()
	if err != nil {
		return nil, err
	}
	for _, group := range groups.AllGroups() {
		if group.Attributes&windows.SE_GROUP_LOGON_ID == windows.SE_GROUP_LOGON_ID {
			return group.Sid.Copy()
		}
	}
	return nil, errors.New("this process has no logon session SID")
}

// isLogonSid reports whether sid is a logon session's SID, S-1-5-5-X-Y.
func isLogonSid(sid *windows.SID) bool {
	return sid.IdentifierAuthority() == windows.SECURITY_NT_AUTHORITY && sid.SubAuthorityCount() == windows.SECURITY_LOGON_IDS_RID_COUNT &&
		sid.SubAuthority(0) == windows.SECURITY_LOGON_IDS_RID
}

// keptGroups lists the groups enabled in this process's token; the
// sandbox's token keeps them.
func keptGroups() ([]*windows.SID, error) {
	groups, err := windows.GetCurrentProcessToken().GetTokenGroups()
	if err != nil {
		return nil, err
	}
	var enabled []*windows.SID
	for _, group := range groups.AllGroups() {
		if group.Attributes&windows.SE_GROUP_ENABLED != 0 {
			enabled = append(enabled, group.Sid)
		}
	}
	return enabled, nil
}
