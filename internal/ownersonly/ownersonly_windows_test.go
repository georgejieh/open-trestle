//go:build windows

package ownersonly

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"unsafe"
)

const (
	sidEveryone           = "*S-1-1-0"
	sidUsers              = "*S-1-5-32-545"
	sidAuthenticatedUsers = "*S-1-5-11"
	sidNetwork            = "*S-1-5-2"
	icaclsCreatorOwner    = "*S-1-3-0"
	icaclsCreatorGroup    = "*S-1-3-1"
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

// TestInheritableGrantsOnAFinalDirectoryAreRefused checks that a directory
// is not private while it would hand another principal access to entries
// later created inside it, even though the grant does not apply to the
// directory itself. A directory above another may carry such grants.
func TestInheritableGrantsOnAFinalDirectoryAreRefused(t *testing.T) {
	for _, test := range []struct {
		ace      string
		private  bool
		readable bool
	}{
		{sidEveryone + ":(OI)(CI)(IO)(F)", false, false},
		{sidUsers + ":(OI)(IO)(M)", false, false},
		{sidUsers + ":(CI)(R)", false, true},
		{icaclsCreatorGroup + ":(OI)(CI)(IO)(M)", false, false},
		{icaclsCreatorOwner + ":(OI)(CI)(IO)(F)", true, true},
	} {
		t.Run(test.ace, func(t *testing.T) {
			root := privateRoot(t)
			icacls(t, root, "/grant", test.ace)
			if test.private {
				requireAccepted(t, root, privateRule)
			} else {
				requireRefused(t, root, privateRule)
			}
			if test.readable {
				requireAccepted(t, root, Rule{OwnerTrusted, OthersRead})
			} else {
				requireRefused(t, root, Rule{OwnerTrusted, OthersRead})
			}
			requireAccepted(t, root, addableRule)
			child := filepath.Join(root, "child")
			if strings.Contains(test.ace, "(OI)") {
				if err := os.WriteFile(child, []byte("content"), 0o600); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Mkdir(child, 0o700); err != nil {
				t.Fatal(err)
			}
			if test.private {
				requireAccepted(t, child, privateRule)
			} else {
				requireRefused(t, child, privateRule)
			}
		})
	}
	// A directory created without its own descriptor below a parent whose
	// grant only files inherit carries that grant on to its files.
	parent := privateRoot(t)
	icacls(t, parent, "/grant", sidUsers+":(OI)(IO)(M)")
	plain := filepath.Join(parent, "plain")
	if err := os.Mkdir(plain, 0o700); err != nil {
		t.Fatal(err)
	}
	requireRefused(t, plain, privateRule)
	// Reading is what OthersRead permits, also for what is created inside.
	readable := privateRoot(t)
	icacls(t, readable, "/grant", sidUsers+":(OI)(CI)(RX)")
	requireAccepted(t, readable, readableRule)
	requireRefused(t, readable, privateRule)
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
	creatorOwner := []byte{1, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0}
	const objectContainer = aceObjectInherit | aceContainerInherit
	for name, test := range map[string]struct {
		acl         []byte
		inheritable uint32
		want        bool
	}{
		"empty":                       {acl(), 0, true},
		"own full access":             {acl(ace(aceAllowed, 0, 0x1f01ff, id.user)), 0, true},
		"other read attributes":       {acl(ace(aceAllowed, 0, fileReadAttributes|synchronize, everyone)), 0, true},
		"other read":                  {acl(ace(aceAllowed, 0, fileReadData, everyone)), 0, false},
		"other generic read":          {acl(ace(aceAllowed, 0, genericRead, everyone)), 0, false},
		"other generic all":           {acl(ace(aceAllowed, 0, 0x10000000, everyone)), 0, false},
		"other maximum allowed":       {acl(ace(aceAllowed, 0, 0x02000000, everyone)), 0, false},
		"undefined bit":               {acl(ace(aceAllowed, 0, 0x00000200, everyone)), 0, false},
		"inherit only, not judged":    {acl(ace(aceAllowed, aceInheritOnly|objectContainer, 0x10000000, everyone)), 0, true},
		"inherit only, judged":        {acl(ace(aceAllowed, aceInheritOnly|objectContainer, 0x10000000, everyone)), othersNoneRights, false},
		"container inherit, judged":   {acl(ace(aceAllowed, aceInheritOnly|aceContainerInherit, fileReadData, everyone)), othersNoneRights, false},
		"inheritable read, read rule": {acl(ace(aceAllowed, aceInheritOnly|objectContainer, genericRead, everyone)), othersReadRights, true},
		"inheritable creator owner":   {acl(ace(aceAllowed, aceInheritOnly|objectContainer, 0x10000000, creatorOwner)), othersNoneRights, true},
		"effective creator owner":     {acl(ace(aceAllowed, 0, 0x10000000, creatorOwner)), othersNoneRights, false},
		"inherited":                   {acl(ace(aceAllowed, 0x10, fileReadData, everyone)), 0, false},
		"deny":                        {acl(ace(aceDenied, 0, 0x10000000, everyone)), 0, true},
		"object deny":                 {acl(ace(0x06, 0, 0x10000000, everyone)), 0, false},
		"object allow":                {acl(ace(0x05, 0, fileReadAttributes, everyone)), 0, false},
		"callback allow":              {acl(ace(0x09, 0, fileReadAttributes, everyone)), 0, false},
		"count beyond size": {func() []byte {
			buffer := acl(ace(aceAllowed, 0, 0, everyone))
			buffer[4] = 2
			return buffer
		}(), 0, false},
		"short allow":         {acl([]byte{aceAllowed, 0, 4, 0}), 0, false},
		"short deny":          {acl([]byte{aceDenied, 0, 4, 0}), 0, false},
		"short inherit only":  {acl([]byte{aceAllowed, aceInheritOnly, 4, 0}), 0, false},
		"deny with a bad sid": {acl(ace(aceDenied, 0, 0, []byte{2, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0})), 0, false},
		"unaligned ace": {func() []byte {
			buffer := acl(append(ace(aceDenied, 0, 0, everyone), 0, 0))
			buffer[aclHeaderBytes+2] = 22
			return buffer
		}(), 0, false},
		"bad revision": {func() []byte {
			buffer := acl()
			buffer[0] = 3
			return buffer
		}(), 0, false},
		"ace beyond acl": {func() []byte {
			buffer := acl(ace(aceAllowed, 0, 0, everyone))
			buffer[aclHeaderBytes+2] = 64
			return buffer
		}(), 0, false},
		"sid beyond ace": {func() []byte {
			buffer := acl(ace(aceAllowed, 0, 0, everyone))
			buffer[aclHeaderBytes+8+1] = 9
			return buffer
		}(), 0, false},
		"too many subauthorities": {acl(ace(aceDenied, 0, 0, append([]byte{1, 16, 0, 0, 0, 0, 0, 5}, make([]byte, 64)...))), 0, false},
	} {
		t.Run(name, func(t *testing.T) {
			err := checkACL((*byte)(unsafe.Pointer(&test.acl[0])), id, othersNoneRights, test.inheritable)
			if (err == nil) != test.want {
				t.Fatalf("checkACL = %v, want accepted %v", err, test.want)
			}
		})
	}
	valid, _, _ := procIsValidAcl.Call(uintptr(unsafe.Pointer(&acl([]byte{aceDenied, 0, 4, 0})[0])))
	if valid != 0 {
		t.Fatal("IsValidAcl accepted a 4-byte ACE")
	}
}

func TestCheckTree(t *testing.T) {
	root := privateRoot(t)
	if err := Mkdir(filepath.Join(root, "sub")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "sub", "inherited"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	privateFile(t, root, "file")
	if err := CheckTree(root, OthersNone); err != nil {
		t.Fatalf("an owner-only tree was refused: %v", err)
	}
	deep := filepath.Join(root, "sub", "inherited")
	icacls(t, deep, "/grant", sidEveryone+":(M)")
	if err := CheckTree(root, OthersNone); !errors.Is(err, ErrNotOwnerOnly) {
		t.Fatalf("a writable entry deep in the tree was accepted: %v", err)
	}
	icacls(t, deep, "/remove:g", sidEveryone)
	target := privateRoot(t)
	Junction(t, filepath.Join(root, "sub", "junction"), target)
	if err := CheckTree(root, OthersNone); !errors.Is(err, ErrNotOwnerOnly) {
		t.Fatalf("a junction in the tree was accepted: %v", err)
	}
}

func TestCheckAncestorsAndFinalPath(t *testing.T) {
	root := privateRoot(t)
	if err := CheckAncestors(root); err != nil {
		t.Fatalf("a private chain was refused: %v", err)
	}
	icacls(t, root, "/grant", sidAuthenticatedUsers+":(AD,WD)")
	if err := CheckAncestors(root); err != nil {
		t.Fatalf("a directory others may only add to was refused as an ancestor: %v", err)
	}
	icacls(t, root, "/grant", sidAuthenticatedUsers+":(DC)")
	if err := CheckAncestors(root); !errors.Is(err, ErrNotOwnerOnly) {
		t.Fatalf("a directory others may delete children of was accepted: %v", err)
	}
	target := privateRoot(t)
	link := filepath.Join(privateRoot(t), "junction")
	Junction(t, link, target)
	if err := Mkdir(filepath.Join(link, "created")); err != nil {
		t.Fatal(err)
	}
	opened, err := Open(filepath.Join(link, "created"))
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	if err := CheckFinalPath(opened, filepath.Join(link, "created")); !errors.Is(err, ErrNotOwnerOnly) {
		t.Fatalf("a path through a junction passed the final path check: %v", err)
	}
	if err := CheckFinalPath(opened, filepath.Join(target, "created")); err != nil {
		final, finalErr := FinalPath(opened)
		t.Fatalf("the resolved path failed the final path check: %v (%q, %v)", err, final, finalErr)
	}
}

func TestOpenOrCreateFile(t *testing.T) {
	root := privateRoot(t)
	icacls(t, root, "/grant", sidUsers+":(OI)(CI)(RX)")
	path := filepath.Join(root, "lock")
	created, err := OpenOrCreateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckHandle(syscall.Handle(created.Fd()), privateRule); err != nil {
		t.Fatalf("a created file inherited access: %v", err)
	}
	_ = created.Close()
	existing, err := OpenOrCreateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = existing.Close()
	inherited := filepath.Join(root, "inherited")
	if err := os.WriteFile(inherited, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	opened, err := OpenOrCreateFile(inherited)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	if err := CheckHandle(syscall.Handle(opened.Fd()), privateRule); !errors.Is(err, ErrNotOwnerOnly) {
		t.Fatalf("an existing file others can read was reported private: %v", err)
	}
}

// Junction creates a directory junction at link that points at target.
func Junction(t *testing.T, link, target string) {
	t.Helper()
	if output, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink: %v\n%s", err, output)
	}
}
