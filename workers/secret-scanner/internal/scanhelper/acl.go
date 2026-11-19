package scanhelper

import (
	"encoding/binary"
	"errors"
)

// getattrlist(2) on macOS returns ATTR_CMN_EXTENDED_SECURITY as a
// four-byte buffer length followed by an attribute reference (a signed
// offset from the reference and a length) to a kauth_filesec: a magic
// number, owner and group GUIDs, then the ACL, which starts with its entry
// count and flags. The reference is empty when the file has no ACL; an
// entry count of KAUTH_FILESEC_NOACL also means none. Both fields are in
// host byte order, which is little-endian on every Mac Go supports.
const (
	filesecMagic      = 0x012cc16d
	filesecNoACL      = 0xffffffff
	filesecHeaderSize = 4 + 16 + 16 + 4 + 4
	attributeHeader   = 4 + 8
)

var errExtendedSecurity = errors.New("extended security attribute is malformed")

// hasAccessControlEntries reports whether an ATTR_CMN_EXTENDED_SECURITY
// attribute buffer holds an ACL with at least one entry.
func hasAccessControlEntries(buffer []byte) (bool, error) {
	if len(buffer) < attributeHeader {
		return false, errExtendedSecurity
	}
	total := int64(binary.LittleEndian.Uint32(buffer[0:4]))
	offset := int64(int32(binary.LittleEndian.Uint32(buffer[4:8])))
	length := int64(binary.LittleEndian.Uint32(buffer[8:12]))
	if total < attributeHeader || total > int64(len(buffer)) {
		return false, errExtendedSecurity
	}
	if length == 0 {
		return false, nil
	}
	start := 4 + offset
	if offset < 0 || length < filesecHeaderSize || start+length > total {
		return false, errExtendedSecurity
	}
	filesec := buffer[start : start+length]
	if binary.LittleEndian.Uint32(filesec[0:4]) != filesecMagic {
		return false, errExtendedSecurity
	}
	count := binary.LittleEndian.Uint32(filesec[36:40])
	return count != filesecNoACL && count != 0, nil
}
