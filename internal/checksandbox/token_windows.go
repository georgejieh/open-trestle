package checksandbox

import (
	"errors"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	advapi32                  = windows.NewLazySystemDLL("advapi32.dll")
	procCreateRestrictedToken = advapi32.NewProc("CreateRestrictedToken")
)

// disableMaxPrivilege is CreateRestrictedToken's DISABLE_MAX_PRIVILEGE:
// every privilege but SeChangeNotifyPrivilege is removed.
const disableMaxPrivilege = 0x1

// keptGroupSids are the groups, besides the logon session's, that the
// sandbox's token keeps: those every local account is in, which Windows'
// own folders grant.
var keptGroupSids = []string{"S-1-1-0", "S-1-5-32-545", "S-1-5-11"}

// restrictedToken is this process's token with no privileges and with the
// user's SID and every group but the kept ones (see splitGroups) made
// deny-only, so that the sandbox gets nothing granted to the user alone or
// to an administrator, such as the user's registry hive. Folders it needs
// grant the logon session's SID instead, and so does what the sandbox
// creates, which it could otherwise not open again: without that a console
// cannot start.
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
	groups, err := own.GetTokenGroups()
	if err != nil {
		return 0, err
	}
	_, denied := splitGroups(groups.AllGroups())
	disabled := []windows.SIDAndAttributes{{Sid: user.User.Sid}}
	for _, sid := range denied {
		disabled = append(disabled, windows.SIDAndAttributes{Sid: sid})
	}
	var restricted windows.Token
	ok, _, err := procCreateRestrictedToken.Call(uintptr(own), disableMaxPrivilege, uintptr(len(disabled)), uintptr(unsafe.Pointer(&disabled[0])), 0, 0, 0, 0, uintptr(unsafe.Pointer(&restricted)))
	runtime.KeepAlive(user)
	runtime.KeepAlive(groups)
	if ok == 0 {
		return 0, err
	}
	if err := setDefaultDacl(restricted, logon); err != nil {
		restricted.Close()
		return 0, err
	}
	return restricted, nil
}

// splitGroups divides a token's groups into those the sandbox's token keeps
// enabled, the logon session's and keptGroupSids, and the enabled others,
// which it makes deny-only. Integrity labels are not groups access checks
// match, and groups already deny-only stay so.
func splitGroups(groups []windows.SIDAndAttributes) (kept, denied []*windows.SID) {
	for _, group := range groups {
		if group.Attributes&windows.SE_GROUP_INTEGRITY != 0 || group.Attributes&windows.SE_GROUP_ENABLED == 0 {
			continue
		}
		if isLogonSid(group.Sid) || keptGroup(group.Sid) {
			kept = append(kept, group.Sid)
		} else {
			denied = append(denied, group.Sid)
		}
	}
	return kept, denied
}

func keptGroup(sid *windows.SID) bool {
	text := sid.String()
	for _, kept := range keptGroupSids {
		if text == kept {
			return true
		}
	}
	return false
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
	runtime.KeepAlive(logon)
	runtime.KeepAlive(system)
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

// keptGroups lists the groups the sandbox's token keeps enabled.
func keptGroups() ([]*windows.SID, error) {
	groups, err := windows.GetCurrentProcessToken().GetTokenGroups()
	if err != nil {
		return nil, err
	}
	kept, _ := splitGroups(groups.AllGroups())
	return kept, nil
}
