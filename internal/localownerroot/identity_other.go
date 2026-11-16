//go:build !linux

package localownerroot

import (
	"fmt"
	"os"
)

func IdentityFromInfo(os.FileInfo) (DirectoryIdentity, error) {
	return DirectoryIdentity{}, fmt.Errorf("%w: directory identity needs Linux", ErrUnsupported)
}
