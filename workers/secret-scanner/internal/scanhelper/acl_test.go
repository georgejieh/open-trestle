package scanhelper

import (
	"encoding/binary"
	"testing"
)

// extendedSecurityBuffer is a getattrlist result as macOS returns it: the
// buffer length, an attribute reference to a kauth_filesec at offset 8 from
// the reference, and the filesec with entries of 24 bytes each.
func extendedSecurityBuffer(magic, count uint32, entries int) []byte {
	filesec := make([]byte, filesecHeaderSize+24*entries)
	binary.LittleEndian.PutUint32(filesec[0:4], magic)
	binary.LittleEndian.PutUint32(filesec[36:40], count)
	buffer := make([]byte, attributeHeader, attributeHeader+len(filesec))
	binary.LittleEndian.PutUint32(buffer[4:8], 8)
	binary.LittleEndian.PutUint32(buffer[8:12], uint32(len(filesec)))
	buffer = append(buffer, filesec...)
	binary.LittleEndian.PutUint32(buffer[0:4], uint32(len(buffer)))
	return append(buffer, make([]byte, 64)...)
}

func TestAccessControlEntriesAreReadFromTheExtendedSecurityAttribute(t *testing.T) {
	noReference := make([]byte, 64)
	binary.LittleEndian.PutUint32(noReference[0:4], attributeHeader)
	for name, test := range map[string]struct {
		buffer []byte
		want   bool
	}{
		"no extended security": {noReference, false},
		"no ACL":               {extendedSecurityBuffer(filesecMagic, filesecNoACL, 0), false},
		"empty ACL":            {extendedSecurityBuffer(filesecMagic, 0, 0), false},
		"one entry":            {extendedSecurityBuffer(filesecMagic, 1, 1), true},
		"many entries":         {extendedSecurityBuffer(filesecMagic, 128, 128), true},
	} {
		got, err := hasAccessControlEntries(test.buffer)
		if err != nil || got != test.want {
			t.Errorf("%s: got %v, %v, want %v", name, got, err, test.want)
		}
	}
}

func TestMalformedExtendedSecurityAttributesFailClosed(t *testing.T) {
	short := extendedSecurityBuffer(filesecMagic, 1, 1)
	binary.LittleEndian.PutUint32(short[8:12], filesecHeaderSize-1)
	beyond := extendedSecurityBuffer(filesecMagic, 1, 1)
	binary.LittleEndian.PutUint32(beyond[4:8], 64)
	negative := extendedSecurityBuffer(filesecMagic, 1, 1)
	binary.LittleEndian.PutUint32(negative[4:8], 0xfffffff0)
	oversized := extendedSecurityBuffer(filesecMagic, 1, 1)
	binary.LittleEndian.PutUint32(oversized[0:4], uint32(len(oversized)+1))
	for name, buffer := range map[string][]byte{
		"truncated header":   make([]byte, attributeHeader-1),
		"wrong magic":        extendedSecurityBuffer(0x12345678, 1, 1),
		"short filesec":      short,
		"reference past end": beyond,
		"negative offset":    negative,
		"length past buffer": oversized,
	} {
		if _, err := hasAccessControlEntries(buffer); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
