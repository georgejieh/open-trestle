//go:build darwin

package scanhelper

import (
	"runtime"
	"syscall"
	"unsafe"
)

const (
	attributeBitmapCount       = 5
	attributeExtendedSecurity  = 0x00400000
	attributeOptionNoFollow    = 0x00000001
	extendedSecurityBufferSize = 4096
)

// attributeList is struct attrlist of getattrlist(2).
type attributeList struct {
	bitmapCount uint16
	reserved    uint16
	common      uint32
	volume      uint32
	directory   uint32
	file        uint32
	fork        uint32
}

// accessControlListed reports whether path, not following a final symbolic
// link, has an extended ACL with at least one entry. Such an entry can grant
// another user access that the owner and mode bits do not show.
func accessControlListed(path string) (bool, error) {
	name, err := syscall.BytePtrFromString(path)
	if err != nil {
		return false, err
	}
	list := attributeList{bitmapCount: attributeBitmapCount, common: attributeExtendedSecurity}
	buffer := make([]byte, extendedSecurityBufferSize)
	_, _, errno := syscall.Syscall6(syscall.SYS_GETATTRLIST, uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&list)),
		uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)), attributeOptionNoFollow, 0)
	runtime.KeepAlive(name)
	runtime.KeepAlive(&list)
	if errno != 0 {
		return false, errno
	}
	return hasAccessControlEntries(buffer)
}
