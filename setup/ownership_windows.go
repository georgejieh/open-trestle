//go:build windows

package setup

import (
	"os"
	"slices"
	"strings"
	"syscall"

	"github.com/georgejieh/open-trestle/internal/ownersonly"
)

// On Windows the owner and DACL of each entry are read through a handle; see
// package ownersonly. The current user, or the default owner this process
// gives new objects, must own a private entry, and only LocalSystem,
// Administrators and TrustedInstaller may also have access; other
// principals may at most read its attributes and DACL. A configuration file
// and a directory above an entry may also be owned by LocalSystem,
// Administrators or TrustedInstaller.

func fileOwnershipSupported() bool { return true }

// currentProcessIdentity names the user and the groups of the process token.
// Logon-session SIDs, which change with every logon, are left out.
func currentProcessIdentity() (string, bool) {
	user, err := ownersonly.CurrentUserSID()
	if err != nil {
		return "", false
	}
	groups, err := ownersonly.TokenGroups()
	if err != nil {
		return "", false
	}
	slices.Sort(groups)
	return "user:" + user + ";groups:[" + strings.Join(groups, " ") + "]", true
}

func checkEntry(path string, info os.FileInfo, owner ownersonly.Owner, others ownersonly.Others) bool {
	return info != nil && ownersonly.CheckPath(path, info, ownersonly.Rule{Owner: owner, Others: others}) == nil
}

func privateToProcess(path string, info os.FileInfo, _ unixPermission) bool {
	return checkEntry(path, info, ownersonly.OwnerCurrentUser, ownersonly.OthersNone)
}

func openPrivateToProcess(file *os.File, info os.FileInfo, _ unixPermission) bool {
	return file != nil && info != nil &&
		ownersonly.CheckHandle(syscall.Handle(file.Fd()), ownersonly.Rule{Owner: ownersonly.OwnerCurrentUser, Others: ownersonly.OthersNone}) == nil
}

func unwritableByOthers(path string, info os.FileInfo) bool {
	return checkEntry(path, info, ownersonly.OwnerTrusted, ownersonly.OthersRead)
}

func trustedUnwritable(path string, info os.FileInfo) bool {
	return checkEntry(path, info, ownersonly.OwnerTrusted, ownersonly.OthersRead)
}

// ancestor accepts a directory that a trusted owner holds and that no other
// principal can write, or one that lets others only add entries above a
// child that a trusted owner holds. Removing or renaming an entry takes
// DELETE on the entry or FILE_DELETE_CHILD on the directory; the directory
// grants others no FILE_DELETE_CHILD, and each entry's own check refuses
// DELETE for others. So a child owned by LocalSystem below such a
// directory, as a folder below a volume root that lets users add folders
// often is, is as safe as one the current user owns.
func ancestor(parentPath string, parent os.FileInfo, childPath string, child os.FileInfo) bool {
	if parent == nil || !parent.IsDir() {
		return false
	}
	if checkEntry(parentPath, parent, ownersonly.OwnerTrusted, ownersonly.OthersRead) {
		return true
	}
	return checkEntry(parentPath, parent, ownersonly.OwnerTrusted, ownersonly.OthersReadAdd) &&
		checkEntry(childPath, child, ownersonly.OwnerTrusted, ownersonly.OthersReadAdd)
}

func ancestorAuthority(parentPath string, parent os.FileInfo, childPath string, child os.FileInfo) bool {
	return ancestor(parentPath, parent, childPath, child)
}

func configurationAncestorAuthority(parentPath string, parent os.FileInfo, childPath string, child os.FileInfo) bool {
	return ancestor(parentPath, parent, childPath, child)
}

func createPrivateFile(path string) (*os.File, error) {
	return ownersonly.CreateFile(path, os.O_WRONLY)
}

func makePrivateDirectory(path string) error { return ownersonly.Mkdir(path) }
