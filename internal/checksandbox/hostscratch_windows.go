package checksandbox

import (
	"encoding/binary"
	"io/fs"

	"golang.org/x/sys/windows"
)

// storedSize is the size of every stream of the file or folder at path:
// NTFS keeps alternate data streams beside a file's content, and a folder
// can hold them too. When the streams cannot be listed it falls back to the
// content's size; the free-space measure still counts the rest.
func storedSize(path string, entry fs.DirEntry) int64 {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return lstatSize(path, entry)
	}
	// Reading attributes is never refused for a sharing conflict, so a file
	// the command holds open is measured too.
	handle, err := windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return lstatSize(path, entry)
	}
	defer windows.CloseHandle(handle)
	for size := 4 << 10; size <= 1<<20; size *= 16 {
		buffer := make([]byte, size)
		switch err := windows.GetFileInformationByHandleEx(handle, windows.FileStreamInfo, &buffer[0], uint32(size)); err {
		case nil:
			return streamsSize(buffer)
		case windows.ERROR_HANDLE_EOF:
			// A folder without streams.
			return 0
		case windows.ERROR_MORE_DATA:
		default:
			return lstatSize(path, entry)
		}
	}
	return lstatSize(path, entry)
}

// streamsSize adds up the stream sizes of a FILE_STREAM_INFO list: each
// entry holds the offset of the next, the name's length, the stream's size
// and its allocation size, then the name.
func streamsSize(list []byte) int64 {
	var total int64
	for offset := 0; offset+24 <= len(list); {
		total += int64(binary.LittleEndian.Uint64(list[offset+8:]))
		next := binary.LittleEndian.Uint32(list[offset:])
		if next == 0 {
			break
		}
		offset += int(next)
	}
	return total
}

// volumeFree names the volume holding path and returns its free space.
func volumeFree(path string) (string, uint64, bool) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", 0, false
	}
	volume := make([]uint16, windows.MAX_PATH+1)
	if windows.GetVolumePathName(name, &volume[0], uint32(len(volume))) != nil {
		return "", 0, false
	}
	var free uint64
	if windows.GetDiskFreeSpaceEx(name, nil, nil, &free) != nil {
		return "", 0, false
	}
	return windows.UTF16ToString(volume), free, true
}
