//go:build windows

package ownersonly

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

// The trusted identities: the operating system's own accounts, which this
// package trusts as Unix code trusts root. Access held by them does not count
// as access held by another principal.
const (
	sidLocalSystem      = "S-1-5-18"
	sidAdministrators   = "S-1-5-32-544"
	sidTrustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
	// sidCreatorOwner in an inheritable ACE stands for whoever creates the
	// entry that inherits it.
	sidCreatorOwner = "S-1-3-0"
)

// Access rights, from winnt.h. For a directory, fileWriteData is the right to
// add a file, fileAppendData the right to add a subdirectory and fileExecute
// the right to traverse it.
const (
	fileReadData         = 0x00000001
	fileWriteData        = 0x00000002
	fileAppendData       = 0x00000004
	fileReadEA           = 0x00000008
	fileExecute          = 0x00000020
	fileReadAttributes   = 0x00000080
	readControl          = 0x00020000
	synchronize          = 0x00100000
	genericExecute       = 0x20000000
	genericRead          = 0x80000000
	fileFlagBackup       = 0x02000000
	fileShareAll         = syscall.FILE_SHARE_READ | syscall.FILE_SHARE_WRITE | syscall.FILE_SHARE_DELETE
	seFileObject         = 1
	ownerSecurityInfo    = 0x00000001
	daclSecurityInfo     = 0x00000004
	sddlRevision         = 1
	aceAllowed           = 0x00
	aceDenied            = 0x01
	aceObjectInherit     = 0x01
	aceContainerInherit  = 0x02
	aceInheritOnly       = 0x08
	aclRevision          = 2
	aclRevisionDS        = 4
	sidMaxSubAuthorities = 15
	aclHeaderBytes       = 8
	aceHeaderBytes       = 4
	sidHeaderBytes       = 8
	tokenOwnerClass      = 4
)

// Rights another principal may hold under each Others rule. A grant of any
// other bit is refused: GENERIC_WRITE, GENERIC_ALL, MAXIMUM_ALLOWED, DELETE,
// WRITE_DAC, WRITE_OWNER, FILE_DELETE_CHILD, the attribute and
// extended-attribute write rights and every bit without a defined meaning
// are all disallowed.
const (
	othersNoneRights    = fileReadAttributes | readControl | synchronize
	othersReadRights    = othersNoneRights | fileReadData | fileReadEA | fileExecute | genericRead | genericExecute
	othersReadAddRights = othersReadRights | fileWriteData | fileAppendData
)

// advapi32 and kernel32 are in the KnownDLLs list of supported Windows
// versions, so the loader takes them from the system directory.
var (
	advapi32                = syscall.NewLazyDLL("advapi32.dll")
	procGetSecurityInfo     = advapi32.NewProc("GetSecurityInfo")
	procConvertStringSDToSD = advapi32.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
	procIsValidAcl          = advapi32.NewProc("IsValidAcl")

	kernel32                     = syscall.NewLazyDLL("kernel32.dll")
	procGetFinalPathNameByHandle = kernel32.NewProc("GetFinalPathNameByHandleW")

	errIdentity           = errors.New("current user identity is unavailable")
	errSecurityDescriptor = errors.New("security descriptor could not be built")
	errObject             = errors.New("object could not be inspected")
	errRule               = errors.New("access rule is invalid")

	identityOnce sync.Once
	identity     processIdentity
	identityErr  error
)

// ErrNotOwnerOnly is an object whose owner or DACL allows access beyond what
// the rule permits, a reparse point, or an object whose security descriptor
// could not be read.
var ErrNotOwnerOnly = errors.New("object is not limited to its owner and the system's administrators")

// Owner is the set of owners a check accepts.
type Owner uint8

const (
	// OwnerCurrentUser accepts the current user and the default owner this
	// process gives new objects, which for an elevated administrator is the
	// Administrators group.
	OwnerCurrentUser Owner = iota + 1
	// OwnerTrusted also accepts LocalSystem, the Administrators group and
	// TrustedInstaller, which own the system's own folders.
	OwnerTrusted
)

// Others is the access a check permits to principals other than the trusted
// ones: the current user, this process's default owner, LocalSystem, the
// Administrators group and TrustedInstaller. Everyone, Authenticated Users,
// Users, INTERACTIVE, CREATOR OWNER, OWNER RIGHTS and every other SID are
// other principals.
type Others uint8

const (
	// OthersNone permits reading attributes and the owner and DACL, and
	// waiting on the object, and nothing else: the counterpart of mode 0600
	// or 0700.
	OthersNone Others = iota + 1
	// OthersRead also permits reading, listing and executing: no write
	// access, the counterpart of a mode without group or other write bits.
	OthersRead
	// OthersReadAdd also permits adding files and subdirectories to a
	// directory, but not FILE_DELETE_CHILD: the counterpart of a sticky
	// directory. An entry inside it can then be removed, renamed or replaced
	// only by a principal that its own DACL grants DELETE or WRITE_DAC, which
	// the callers check entry by entry. For a file it is OthersRead.
	OthersReadAdd
)

// Rule is what a check requires of an object's owner and DACL.
type Rule struct {
	Owner  Owner
	Others Others
}

type processIdentity struct {
	user         []byte
	owner        []byte
	userText     string
	trusted      [][]byte
	creatorOwner []byte
}

func loadIdentity() (processIdentity, error) {
	identityOnce.Do(func() { identity, identityErr = readIdentity() })
	return identity, identityErr
}

func readIdentity() (processIdentity, error) {
	token, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return processIdentity{}, errIdentity
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return processIdentity{}, errIdentity
	}
	userSID := sidBytes(user.User.Sid)
	userText, err := user.User.Sid.String()
	if err != nil || userSID == nil {
		return processIdentity{}, errIdentity
	}
	ownerSID, err := tokenOwner(token)
	if err != nil {
		return processIdentity{}, errIdentity
	}
	result := processIdentity{user: userSID, owner: ownerSID, userText: userText}
	result.trusted = [][]byte{userSID, ownerSID}
	for _, text := range []string{sidLocalSystem, sidAdministrators, sidTrustedInstaller} {
		sid, err := syscall.StringToSid(text)
		if err != nil {
			return processIdentity{}, errIdentity
		}
		result.trusted = append(result.trusted, sidBytes(sid))
	}
	creator, err := syscall.StringToSid(sidCreatorOwner)
	if err != nil {
		return processIdentity{}, errIdentity
	}
	result.creatorOwner = sidBytes(creator)
	return result, nil
}

// tokenOwner returns the default owner of objects the token creates.
func tokenOwner(token syscall.Token) ([]byte, error) {
	size := uint32(64)
	for {
		buffer := make([]byte, size)
		err := syscall.GetTokenInformation(token, tokenOwnerClass, &buffer[0], uint32(len(buffer)), &size)
		if err == nil {
			owner := sidBytes(*(**syscall.SID)(unsafe.Pointer(&buffer[0])))
			if owner == nil {
				return nil, errIdentity
			}
			return owner, nil
		}
		if err != syscall.ERROR_INSUFFICIENT_BUFFER || size <= uint32(len(buffer)) {
			return nil, errIdentity
		}
	}
}

// sidBytes copies a valid SID into Go memory.
func sidBytes(sid *syscall.SID) []byte {
	if sid == nil {
		return nil
	}
	length := syscall.GetLengthSid(sid)
	if length < sidHeaderBytes {
		return nil
	}
	return append([]byte(nil), unsafe.Slice((*byte)(unsafe.Pointer(sid)), length)...)
}

func (id processIdentity) trustedSID(sid []byte) bool {
	for _, trusted := range id.trusted {
		if string(trusted) == string(sid) {
			return true
		}
	}
	return false
}

func (id processIdentity) acceptsOwner(sid []byte, owner Owner) bool {
	switch owner {
	case OwnerCurrentUser:
		return string(sid) == string(id.user) || string(sid) == string(id.owner)
	case OwnerTrusted:
		return id.trustedSID(sid)
	}
	return false
}

// CurrentUserSID returns the current user's SID in its string form.
func CurrentUserSID() (string, error) {
	id, err := loadIdentity()
	if err != nil {
		return "", err
	}
	return id.userText, nil
}

// TokenGroups returns the SIDs of the process token's groups in string form,
// each followed by a colon and its attribute bits in hexadecimal, in token
// order. Logon-session SIDs, which change with every logon, are left out.
func TokenGroups() ([]string, error) {
	token, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return nil, errIdentity
	}
	defer token.Close()
	size := uint32(256)
	var buffer []byte
	for {
		buffer = make([]byte, size)
		err = syscall.GetTokenInformation(token, syscall.TokenGroups, &buffer[0], uint32(len(buffer)), &size)
		if err == nil {
			break
		}
		if err != syscall.ERROR_INSUFFICIENT_BUFFER || size <= uint32(len(buffer)) {
			return nil, errIdentity
		}
	}
	const logonID = 0xC0000000
	count := *(*uint32)(unsafe.Pointer(&buffer[0]))
	offset := unsafe.Sizeof(uintptr(0))
	if uintptr(count) > (uintptr(len(buffer))-offset)/unsafe.Sizeof(syscall.SIDAndAttributes{}) {
		return nil, errIdentity
	}
	entries := unsafe.Slice((*syscall.SIDAndAttributes)(unsafe.Add(unsafe.Pointer(&buffer[0]), offset)), count)
	groups := make([]string, 0, count)
	for _, entry := range entries {
		if entry.Attributes&logonID == logonID {
			continue
		}
		text, err := entry.Sid.String()
		if err != nil {
			return nil, errIdentity
		}
		groups = append(groups, text+":"+strconv.FormatUint(uint64(entry.Attributes), 16))
	}
	return groups, nil
}

// CheckHandle requires that the object handle refers to is not a reparse
// point, that its owner is one rule.Owner accepts and that its DACL grants
// other principals no right beyond those rule.Others permits. The handle
// must have READ_CONTROL and FILE_READ_ATTRIBUTES access.
//
// The DACL must be valid by IsValidAcl and by a structural check of every
// ACE and SID, and may hold only access-allowed and access-denied ACEs. A
// NULL DACL grants everyone every right and is refused. Deny ACEs are
// ignored: every allow ACE for another principal must be acceptable on its
// own, so no ordering or deny can make an unacceptable grant look
// acceptable. An allow ACE that is not inherit-only applies to the object,
// whether inherited or explicit. On a directory under OthersNone or
// OthersRead, an allow ACE that new files or subdirectories inherit is also
// judged by the rights it would give them, so a private directory cannot
// hand broader access to what is later created inside it; such an ACE for
// CREATOR OWNER names the creator of the new entry and is accepted.
// Integrity labels are not part of the DACL and are not checked.
func CheckHandle(handle syscall.Handle, rule Rule) error {
	if rule.Owner != OwnerCurrentUser && rule.Owner != OwnerTrusted || rule.Others < OthersNone || rule.Others > OthersReadAdd {
		return errRule
	}
	id, err := loadIdentity()
	if err != nil {
		return err
	}
	var information syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(handle, &information); err != nil {
		return errObject
	}
	if information.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return ErrNotOwnerOnly
	}
	directory := information.FileAttributes&syscall.FILE_ATTRIBUTE_DIRECTORY != 0
	permitted, inheritable := uint32(othersNoneRights), uint32(othersNoneRights)
	switch {
	case rule.Others == OthersRead:
		permitted, inheritable = othersReadRights, othersReadRights
	case rule.Others == OthersReadAdd && directory:
		permitted, inheritable = othersReadAddRights, 0
	case rule.Others == OthersReadAdd:
		permitted, inheritable = othersReadRights, 0
	}
	if !directory {
		inheritable = 0
	}
	var owner *syscall.SID
	var dacl *byte
	var descriptor uintptr
	status, _, _ := procGetSecurityInfo.Call(uintptr(handle), seFileObject, ownerSecurityInfo|daclSecurityInfo,
		uintptr(unsafe.Pointer(&owner)), 0, uintptr(unsafe.Pointer(&dacl)), 0, uintptr(unsafe.Pointer(&descriptor)))
	if status != 0 {
		return ErrNotOwnerOnly
	}
	defer syscall.LocalFree(syscall.Handle(descriptor))
	if owner == nil || !id.acceptsOwner(sidBytes(owner), rule.Owner) || dacl == nil {
		return ErrNotOwnerOnly
	}
	if valid, _, _ := procIsValidAcl.Call(uintptr(unsafe.Pointer(dacl))); valid == 0 {
		return ErrNotOwnerOnly
	}
	return checkACL(dacl, id, permitted, inheritable)
}

// checkACL walks an ACL within the bounds its header gives, checks the
// structure of every ACE and its SID before looking at its type, and refuses
// an allow ACE that grants an untrusted SID a right outside permitted on the
// object itself or, when inheritable is not zero, a right outside
// inheritable on the entries that inherit it.
func checkACL(acl *byte, id processIdentity, permitted, inheritable uint32) error {
	header := unsafe.Slice(acl, aclHeaderBytes)
	revision := header[0]
	size := int(uint16(header[2]) | uint16(header[3])<<8)
	count := int(uint16(header[4]) | uint16(header[5])<<8)
	if revision != aclRevision && revision != aclRevisionDS || size < aclHeaderBytes || size%4 != 0 {
		return ErrNotOwnerOnly
	}
	body := unsafe.Slice(acl, size)
	offset := aclHeaderBytes
	for index := 0; index < count; index++ {
		if offset+aceHeaderBytes > size {
			return ErrNotOwnerOnly
		}
		aceType, aceFlags := body[offset], body[offset+1]
		aceSize := int(uint16(body[offset+2]) | uint16(body[offset+3])<<8)
		if aceSize < aceHeaderBytes+4+sidHeaderBytes || aceSize%4 != 0 || offset+aceSize > size {
			return ErrNotOwnerOnly
		}
		ace := body[offset : offset+aceSize]
		offset += aceSize
		mask := uint32(ace[4]) | uint32(ace[5])<<8 | uint32(ace[6])<<16 | uint32(ace[7])<<24
		sid := ace[8:]
		sidLength := sidHeaderBytes + 4*int(sid[1])
		if sid[0] != 1 || sid[1] > sidMaxSubAuthorities || sidLength > len(sid) {
			return ErrNotOwnerOnly
		}
		sid = sid[:sidLength]
		switch aceType {
		case aceDenied:
			continue
		case aceAllowed:
		default:
			return ErrNotOwnerOnly
		}
		if aceFlags&aceInheritOnly == 0 && mask&^permitted != 0 && !id.trustedSID(sid) {
			return ErrNotOwnerOnly
		}
		if inheritable != 0 && aceFlags&(aceObjectInherit|aceContainerInherit) != 0 && mask&^inheritable != 0 &&
			!id.trustedSID(sid) && string(sid) != string(id.creatorOwner) {
			return ErrNotOwnerOnly
		}
	}
	return nil
}

// Open opens the object at path itself, not the target of a final reparse
// point, with only the access CheckHandle needs. Directories open too. The
// handle shares reading, writing and deletion, so holding it does not stop
// others from opening, changing or deleting the object.
func Open(path string) (*os.File, error) {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := syscall.CreateFile(name, readControl|fileReadAttributes|synchronize, fileShareAll, nil,
		syscall.OPEN_EXISTING, fileFlagBackup|syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(handle), path), nil
}

// CheckPath opens the object at path without following a final reparse
// point and checks it with CheckHandle. When info is not nil, the opened
// object must be the one info describes.
func CheckPath(path string, info os.FileInfo, rule Rule) error {
	file, err := Open(path)
	if err != nil {
		return ErrNotOwnerOnly
	}
	defer file.Close()
	if info != nil {
		opened, err := file.Stat()
		if err != nil || !os.SameFile(info, opened) {
			return ErrNotOwnerOnly
		}
	}
	return CheckHandle(syscall.Handle(file.Fd()), rule)
}

// privateDescriptor builds a self-relative security descriptor that makes
// the current user the owner and has a protected DACL, which inherits
// nothing from the parent, granting full access to the current user,
// LocalSystem and the Administrators group only. For a directory the ACEs
// are inheritable, so entries created inside it without a protected
// descriptor of their own inherit them. The caller frees it with LocalFree.
func privateDescriptor(directory bool) (uintptr, error) {
	id, err := loadIdentity()
	if err != nil {
		return 0, err
	}
	inherit := ""
	if directory {
		inherit = "OICI"
	}
	text := "O:" + id.userText + "D:P(A;" + inherit + ";FA;;;" + id.userText + ")(A;" + inherit + ";FA;;;SY)(A;" + inherit + ";FA;;;BA)"
	name, err := syscall.UTF16PtrFromString(text)
	if err != nil {
		return 0, errSecurityDescriptor
	}
	var descriptor uintptr
	if ok, _, _ := procConvertStringSDToSD.Call(uintptr(unsafe.Pointer(name)), sddlRevision, uintptr(unsafe.Pointer(&descriptor)), 0); ok == 0 || descriptor == 0 {
		return 0, errSecurityDescriptor
	}
	return descriptor, nil
}

// CreateFile creates a new file at path that is owner-only from the start:
// it fails if anything exists at path, including a reparse point, and the
// file is created with the descriptor privateDescriptor builds, so there is
// no moment when it has a broader DACL. A file system without ACLs ignores
// the descriptor, and callers check the result. flag must be os.O_WRONLY or os.O_RDWR; the handle can
// also read attributes and the security descriptor, and is not inherited by
// child processes.
func CreateFile(path string, flag int) (*os.File, error) {
	var access uint32
	switch flag {
	case os.O_WRONLY:
		access = syscall.GENERIC_WRITE | readControl | fileReadAttributes
	case os.O_RDWR:
		access = syscall.GENERIC_READ | syscall.GENERIC_WRITE
	default:
		return nil, &os.PathError{Op: "create", Path: path, Err: syscall.EINVAL}
	}
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "create", Path: path, Err: err}
	}
	descriptor, err := privateDescriptor(false)
	if err != nil {
		return nil, &os.PathError{Op: "create", Path: path, Err: err}
	}
	defer syscall.LocalFree(syscall.Handle(descriptor))
	attributes := syscall.SecurityAttributes{Length: uint32(unsafe.Sizeof(syscall.SecurityAttributes{})), SecurityDescriptor: descriptor}
	handle, err := syscall.CreateFile(name, access, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, &attributes,
		syscall.CREATE_NEW, syscall.FILE_ATTRIBUTE_NORMAL|syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, &os.PathError{Op: "create", Path: path, Err: err}
	}
	return os.NewFile(uintptr(handle), path), nil
}

// Mkdir creates a new directory at path that is owner-only from the start,
// with the descriptor privateDescriptor builds. Files and directories later
// created inside it without their own descriptor inherit the same access.
// It fails if anything exists at path.
func Mkdir(path string) error {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return &os.PathError{Op: "mkdir", Path: path, Err: err}
	}
	descriptor, err := privateDescriptor(true)
	if err != nil {
		return &os.PathError{Op: "mkdir", Path: path, Err: err}
	}
	defer syscall.LocalFree(syscall.Handle(descriptor))
	attributes := syscall.SecurityAttributes{Length: uint32(unsafe.Sizeof(syscall.SecurityAttributes{})), SecurityDescriptor: descriptor}
	if err := syscall.CreateDirectory(name, &attributes); err != nil {
		return &os.PathError{Op: "mkdir", Path: path, Err: err}
	}
	return nil
}

// maxTreeEntries bounds CheckTree, which refuses a larger tree.
const maxTreeEntries = 65536

// CheckTree checks every entry below root, without following reparse
// points: each must be owned by a trusted identity, must not be a reparse
// point and must grant other principals nothing beyond what rule.Others
// permits, judged as CheckHandle judges it. root itself is not checked. A
// tree of more than maxTreeEntries entries is refused.
func CheckTree(root string, others Others) error {
	rule := Rule{Owner: OwnerTrusted, Others: others}
	entries := 0
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return ErrNotOwnerOnly
		}
		if path == root {
			return nil
		}
		if entries++; entries > maxTreeEntries {
			return ErrNotOwnerOnly
		}
		info, err := entry.Info()
		if err != nil || info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
			return ErrNotOwnerOnly
		}
		return CheckPath(path, info, rule)
	})
	if err != nil {
		return ErrNotOwnerOnly
	}
	return nil
}

// CheckAncestors requires directory and every directory above it to be a
// directory, not a reparse point, owned by a trusted identity, that lets
// other principals at most read it and add entries to it. An entry of such
// a directory can be removed, renamed or replaced only by a principal that
// the entry's own DACL grants DELETE or WRITE_DAC, so the caller must check
// each entry it relies on. A directory that is empty can still be turned
// into a junction by anyone who may add entries to it; callers that create
// an entry below one confirm the created entry's path with FinalPath.
func CheckAncestors(directory string) error {
	rule := Rule{Owner: OwnerTrusted, Others: OthersReadAdd}
	for {
		info, err := os.Lstat(directory)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || CheckPath(directory, info, rule) != nil {
			return ErrNotOwnerOnly
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			return nil
		}
		directory = parent
	}
}

// FinalPath returns the path that the system resolves file's handle to, with
// every junction and symbolic link on the way resolved, as a drive-letter
// path, or as a \\server\share path for a network file.
func FinalPath(file *os.File) (string, error) {
	buffer := make([]uint16, syscall.MAX_LONG_PATH)
	length, _, _ := procGetFinalPathNameByHandle.Call(file.Fd(), uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)), 0)
	if length == 0 || length >= uintptr(len(buffer)) {
		return "", errObject
	}
	path := syscall.UTF16ToString(buffer[:length])
	const unc, local = `\\?\UNC\`, `\\?\`
	switch {
	case strings.HasPrefix(path, unc):
		return `\\` + path[len(unc):], nil
	case strings.HasPrefix(path, local):
		return path[len(local):], nil
	}
	return path, nil
}

// CheckFinalPath requires that file, opened at path, resolves to path
// itself, so no junction or symbolic link lies on the way to it. Windows
// paths are compared without regard to case.
func CheckFinalPath(file *os.File, path string) error {
	final, err := FinalPath(file)
	if err != nil || !strings.EqualFold(filepath.Clean(final), filepath.Clean(path)) {
		return ErrNotOwnerOnly
	}
	return nil
}

// OpenOrCreateFile opens the file at path for reading and writing, creating
// it owner-only, as CreateFile does, when nothing exists there. A final
// reparse point is opened as itself, not followed. The handle is not
// inherited by child processes. The caller checks an existing file with
// CheckHandle.
func OpenOrCreateFile(path string) (*os.File, error) {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	descriptor, err := privateDescriptor(false)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	defer syscall.LocalFree(syscall.Handle(descriptor))
	attributes := syscall.SecurityAttributes{Length: uint32(unsafe.Sizeof(syscall.SecurityAttributes{})), SecurityDescriptor: descriptor}
	handle, err := syscall.CreateFile(name, syscall.GENERIC_READ|syscall.GENERIC_WRITE, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, &attributes,
		syscall.OPEN_ALWAYS, syscall.FILE_ATTRIBUTE_NORMAL|syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(handle), path), nil
}

// CheckPrivateDirectoryTree checks a directory that only the current user
// may use, together with everything in it and every directory above it, for
// a directory from which code is loaded. The directory must not be a
// reparse point, must be owned by the current user, must pass CheckHandle
// with OthersNone, inheritable ACEs included, and must resolve to directory
// itself, with no junction or symbolic link on the way. The directories
// above it must pass CheckAncestors and every entry inside it CheckTree with
// OthersNone.
func CheckPrivateDirectoryTree(directory string) error {
	if !filepath.IsAbs(directory) || CheckAncestors(filepath.Dir(directory)) != nil {
		return ErrNotOwnerOnly
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrNotOwnerOnly
	}
	file, err := Open(directory)
	if err != nil {
		return ErrNotOwnerOnly
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) ||
		CheckHandle(syscall.Handle(file.Fd()), Rule{Owner: OwnerCurrentUser, Others: OthersNone}) != nil ||
		CheckFinalPath(file, directory) != nil {
		return ErrNotOwnerOnly
	}
	return CheckTree(directory, OthersNone)
}
