//go:build windows

package ownersonly

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"unsafe"
)

const (
	sidEveryone           = "*S-1-1-0"
	sidUsers              = "*S-1-5-32-545"
	sidAuthenticatedUsers = "*S-1-5-11"
	sidNetwork            = "*S-1-5-2"
)

var (
	privateRule  = Rule{Owner: OwnerCurrentUser, Others: OthersNone}
	readableRule = Rule{Owner: OwnerTrusted, Others: OthersRead}
	addableRule  = Rule{Owner: OwnerTrusted, Others: OthersReadAdd}
)

// privateRoot is a new owner-only directory, so that the objects a test
// creates in it inherit nothing from the system's temporary directory.
func privateRoot(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "root")
	if err := Mkdir(root); err != nil {
		t.Fatal(err)
	}
	return root
}

func privateFile(t *testing.T, directory, name string) string {
	t.Helper()
	path := filepath.Join(directory, name)
	file, err := CreateFile(path, os.O_WRONLY)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("content")); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func icacls(t *testing.T, path string, arguments ...string) {
	t.Helper()
	output, err := exec.Command("icacls", append([]string{path}, arguments...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("icacls %v: %v\n%s", arguments, err, output)
	}
}

func requireAccepted(t *testing.T, path string, rule Rule) {
	t.Helper()
	if err := CheckPath(path, nil, rule); err != nil {
		t.Fatalf("CheckPath(%s, %+v) = %v, want accepted", path, rule, err)
	}
}

func requireRefused(t *testing.T, path string, rule Rule) {
	t.Helper()
	if err := CheckPath(path, nil, rule); !errors.Is(err, ErrNotOwnerOnly) {
		t.Fatalf("CheckPath(%s, %+v) = %v, want ErrNotOwnerOnly", path, rule, err)
	}
}

func TestCreatedObjectsAreOwnerOnly(t *testing.T) {
	root := privateRoot(t)
	file := privateFile(t, root, "file")
	for _, path := range []string{root, file} {
		for _, rule := range []Rule{privateRule, readableRule, addableRule, {OwnerTrusted, OthersNone}} {
			requireAccepted(t, path, rule)
		}
	}
	inherited := filepath.Join(root, "inherited")
	if err := os.WriteFile(inherited, []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}
	requireAccepted(t, inherited, privateRule)
}

func TestCreateRefusesAnExistingEntry(t *testing.T) {
	root := privateRoot(t)
	file := privateFile(t, root, "file")
	if _, err := CreateFile(file, os.O_RDWR); err == nil {
		t.Fatal("CreateFile replaced an existing file")
	}
	if err := Mkdir(file); err == nil {
		t.Fatal("Mkdir succeeded over an existing file")
	}
	if _, err := CreateFile(filepath.Join(root, "file2"), os.O_RDONLY); err == nil {
		t.Fatal("CreateFile accepted a read-only flag")
	}
}

func TestReadGrantToAnotherPrincipal(t *testing.T) {
	root := privateRoot(t)
	file := privateFile(t, root, "file")
	icacls(t, file, "/grant", sidUsers+":(R)")
	requireRefused(t, file, privateRule)
	requireRefused(t, file, Rule{OwnerTrusted, OthersNone})
	requireAccepted(t, file, readableRule)
}

func TestWriteGrantsToAnotherPrincipal(t *testing.T) {
	for _, grant := range []string{"(W)", "(M)", "(F)", "(D)", "(WDAC)", "(WO)", "(WA)", "(WEA)", "(AD)", "(GW)", "(GA)"} {
		t.Run(grant, func(t *testing.T) {
			root := privateRoot(t)
			file := privateFile(t, root, "file")
			icacls(t, file, "/grant", sidEveryone+":"+grant)
			requireRefused(t, file, privateRule)
			requireRefused(t, file, readableRule)
			requireRefused(t, file, addableRule)
		})
	}
}

func TestDirectoryAddAndDeleteChildGrants(t *testing.T) {
	root := privateRoot(t)
	adding := filepath.Join(root, "adding")
	if err := Mkdir(adding); err != nil {
		t.Fatal(err)
	}
	icacls(t, adding, "/grant", sidAuthenticatedUsers+":(AD,WD)")
	requireRefused(t, adding, readableRule)
	requireAccepted(t, adding, addableRule)

	deleting := filepath.Join(root, "deleting")
	if err := Mkdir(deleting); err != nil {
		t.Fatal(err)
	}
	icacls(t, deleting, "/grant", sidAuthenticatedUsers+":(AD,DC)")
	requireRefused(t, deleting, addableRule)

	// For a file the same bits are write and append access.
	file := privateFile(t, root, "file")
	icacls(t, file, "/grant", sidAuthenticatedUsers+":(AD,WD)")
	requireRefused(t, file, addableRule)
}

func TestInheritedGrantsAreChecked(t *testing.T) {
	root := privateRoot(t)
	icacls(t, root, "/grant", sidUsers+":(OI)(CI)(R)")
	requireRefused(t, root, privateRule)
	child := filepath.Join(root, "child")
	if err := os.WriteFile(child, []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}
	requireRefused(t, child, privateRule)
	requireAccepted(t, child, readableRule)
	// An object created with its own descriptor inherits nothing.
	requireAccepted(t, privateFile(t, root, "explicit"), privateRule)
}

func TestInheritOnlyGrantsApplyOnlyToChildren(t *testing.T) {
	root := privateRoot(t)
	icacls(t, root, "/grant", sidEveryone+":(OI)(CI)(IO)(F)")
	requireAccepted(t, root, privateRule)
	child := filepath.Join(root, "child")
	if err := os.WriteFile(child, []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}
	requireRefused(t, child, readableRule)
}

func TestDenyDoesNotOffsetAGrant(t *testing.T) {
	root := privateRoot(t)
	file := privateFile(t, root, "file")
	icacls(t, file, "/deny", sidNetwork+":(F)")
	requireAccepted(t, file, privateRule)
	icacls(t, file, "/grant", sidNetwork+":(F)")
	requireRefused(t, file, privateRule)
}

func TestNullDACLIsRefused(t *testing.T) {
	root := privateRoot(t)
	file := privateFile(t, root, "file")
	name, err := syscall.UTF16PtrFromString(file)
	if err != nil {
		t.Fatal(err)
	}
	const writeDAC, protectedDACL = 0x00040000, 0x80000000
	handle, err := syscall.CreateFile(name, readControl|writeDAC, fileShareAll, nil, syscall.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	setSecurityInfo := advapi32.NewProc("SetSecurityInfo")
	status, _, _ := setSecurityInfo.Call(uintptr(handle), seFileObject, daclSecurityInfo|protectedDACL, 0, 0, 0, 0)
	_ = syscall.CloseHandle(handle)
	if status != 0 {
		t.Fatalf("SetSecurityInfo: %d", status)
	}
	opened, err := Open(file)
	if err != nil {
		t.Fatal(err)
	}
	var dacl, descriptor uintptr
	status, _, _ = procGetSecurityInfo.Call(opened.Fd(), seFileObject, daclSecurityInfo, 0, 0, uintptr(unsafe.Pointer(&dacl)), 0, uintptr(unsafe.Pointer(&descriptor)))
	_ = opened.Close()
	if status != 0 || dacl != 0 {
		t.Fatalf("the file does not have a NULL DACL: status %d", status)
	}
	_, _ = syscall.LocalFree(syscall.Handle(descriptor))
	requireRefused(t, file, privateRule)
	requireRefused(t, file, readableRule)
}

func TestSystemFolderOwners(t *testing.T) {
	windows := os.Getenv("SystemRoot")
	if windows == "" {
		t.Skip("SystemRoot is not set")
	}
	requireRefused(t, windows, Rule{OwnerCurrentUser, OthersRead})
	requireAccepted(t, windows, readableRule)
}

func TestReparsePointsAreRefused(t *testing.T) {
	root := privateRoot(t)
	target := filepath.Join(root, "target")
	if err := Mkdir(target); err != nil {
		t.Fatal(err)
	}
	junction := filepath.Join(root, "junction")
	if output, err := exec.Command("cmd", "/c", "mklink", "/J", junction, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink: %v\n%s", err, output)
	}
	requireRefused(t, junction, readableRule)
	requireAccepted(t, target, privateRule)
}

func TestCheckPathBindsTheDescribedObject(t *testing.T) {
	root := privateRoot(t)
	first := privateFile(t, root, "first")
	second := privateFile(t, root, "second")
	info, err := os.Stat(first)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckPath(first, info, privateRule); err != nil {
		t.Fatal(err)
	}
	if err := CheckPath(second, info, privateRule); !errors.Is(err, ErrNotOwnerOnly) {
		t.Fatalf("CheckPath accepted another file than info describes: %v", err)
	}
	if err := CheckPath(filepath.Join(root, "missing"), nil, privateRule); !errors.Is(err, ErrNotOwnerOnly) {
		t.Fatalf("CheckPath accepted a missing path: %v", err)
	}
}

func TestInvalidRulesAreRefused(t *testing.T) {
	root := privateRoot(t)
	for _, rule := range []Rule{{}, {OwnerCurrentUser, 0}, {0, OthersNone}, {OwnerTrusted + 1, OthersNone}, {OwnerTrusted, OthersReadAdd + 1}} {
		if err := CheckPath(root, nil, rule); err == nil {
			t.Fatalf("rule %+v accepted", rule)
		}
	}
}

func TestIdentity(t *testing.T) {
	user, err := CurrentUserSID()
	if err != nil || len(user) < 4 || user[:4] != "S-1-" {
		t.Fatalf("CurrentUserSID() = %q, %v", user, err)
	}
	groups, err := TokenGroups()
	if err != nil || len(groups) == 0 {
		t.Fatalf("TokenGroups() = %v, %v", groups, err)
	}
}

// acl builds an ACL from ACEs given as type, flags, mask and SID bytes.
func acl(aces ...[]byte) []byte {
	body := []byte{}
	for _, ace := range aces {
		body = append(body, ace...)
	}
	size := aclHeaderBytes + len(body)
	header := []byte{2, 0, byte(size), byte(size >> 8), byte(len(aces)), 0, 0, 0}
	return append(header, body...)
}

func ace(aceType, flags byte, mask uint32, sid []byte) []byte {
	size := aceHeaderBytes + 4 + len(sid)
	return append([]byte{aceType, flags, byte(size), byte(size >> 8), byte(mask), byte(mask >> 8), byte(mask >> 16), byte(mask >> 24)}, sid...)
}

func TestCheckACLStructure(t *testing.T) {
	id, err := loadIdentity()
	if err != nil {
		t.Fatal(err)
	}
	everyone := []byte{1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0}
	check := func(buffer []byte, permitted uint32) error {
		return checkACL((*byte)(unsafe.Pointer(&buffer[0])), id, permitted)
	}
	for name, test := range map[string]struct {
		acl  []byte
		want bool
	}{
		"empty":                 {acl(), true},
		"own full access":       {acl(ace(aceAllowed, 0, 0x1f01ff, id.user)), true},
		"other read attributes": {acl(ace(aceAllowed, 0, fileReadAttributes|synchronize, everyone)), true},
		"other read":            {acl(ace(aceAllowed, 0, fileReadData, everyone)), false},
		"other generic read":    {acl(ace(aceAllowed, 0, genericRead, everyone)), false},
		"other generic all":     {acl(ace(aceAllowed, 0, 0x10000000, everyone)), false},
		"other maximum allowed": {acl(ace(aceAllowed, 0, 0x02000000, everyone)), false},
		"undefined bit":         {acl(ace(aceAllowed, 0, 0x00000200, everyone)), false},
		"inherit only":          {acl(ace(aceAllowed, aceInheritOnly, 0x10000000, everyone)), true},
		"inherited":             {acl(ace(aceAllowed, 0x10, fileReadData, everyone)), false},
		"deny":                  {acl(ace(aceDenied, 0, 0x10000000, everyone)), true},
		"object allow":          {acl(ace(0x05, 0, fileReadAttributes, everyone)), false},
		"callback allow":        {acl(ace(0x09, 0, fileReadAttributes, everyone)), false},
		"count beyond size": {func() []byte {
			buffer := acl(ace(aceAllowed, 0, 0, everyone))
			buffer[4] = 2
			return buffer
		}(), false},
		"short ace": {acl([]byte{aceAllowed, 0, 2, 0}), false},
		"ace beyond acl": {func() []byte {
			buffer := acl(ace(aceAllowed, 0, 0, everyone))
			buffer[aclHeaderBytes+2] = 64
			return buffer
		}(), false},
		"sid beyond ace": {func() []byte {
			buffer := acl(ace(aceAllowed, 0, 0, everyone))
			buffer[aclHeaderBytes+8+1] = 9
			return buffer
		}(), false},
	} {
		t.Run(name, func(t *testing.T) {
			err := check(test.acl, othersNoneRights)
			if (err == nil) != test.want {
				t.Fatalf("checkACL = %v, want accepted %v", err, test.want)
			}
		})
	}
}
