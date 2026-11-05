//go:build windows

package main

import (
	"errors"
	"os"
	"strings"
	"syscall"
)

func openRegularInputFileNative(path string) (*os.File, error) {
	if !windowsRegularInputPath(path) {
		return nil, errors.New("input must be a regular file")
	}
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := syscall.CreateFile(
		name,
		syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_ATTRIBUTE_NORMAL|syscall.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, err
	}
	closeHandle := true
	defer func() {
		if closeHandle {
			_ = syscall.CloseHandle(handle)
		}
	}()

	fileType, err := syscall.GetFileType(handle)
	if err != nil {
		return nil, err
	}
	if fileType != syscall.FILE_TYPE_DISK {
		return nil, errors.New("input must be a regular file")
	}
	var information syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(handle, &information); err != nil {
		return nil, err
	}
	if information.FileAttributes&(syscall.FILE_ATTRIBUTE_DIRECTORY|syscall.FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
		return nil, errors.New("input must be a regular file")
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		return nil, errors.New("open regular input file")
	}
	closeHandle = false
	return file, nil
}

func windowsRegularInputPath(path string) bool {
	path = strings.ToLower(strings.ReplaceAll(path, "/", `\`))
	switch {
	case strings.HasPrefix(path, `\\.\`):
		return false
	case strings.HasPrefix(path, `\\?\`):
		path = strings.TrimPrefix(path, `\\?\`)
		if len(path) >= 3 && path[0] >= 'a' && path[0] <= 'z' && path[1] == ':' && path[2] == '\\' {
			return true
		}
		if strings.HasPrefix(path, `unc\`) {
			return !windowsNamedPipeUNCPath(path[len(`unc\`):])
		}
		return false
	case strings.HasPrefix(path, `\\`):
		return !windowsNamedPipeUNCPath(path[len(`\\`):])
	default:
		return true
	}
}

func windowsNamedPipeUNCPath(path string) bool {
	parts := strings.SplitN(path, `\`, 3)
	return len(parts) >= 2 && parts[1] == "pipe"
}
