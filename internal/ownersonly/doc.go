// Package ownersonly checks and creates files and directories on Windows that
// only the current user and the system's own administrative identities can
// access. On Windows the mode bits that os.FileInfo reports say nothing about
// who may read or write a file; the owner and the discretionary access-control
// list (DACL) in its security descriptor do.
//
// The package has code only on Windows. The same file is kept in the secret
// scanner module, which cannot import this module, and a test keeps both
// copies equal.
package ownersonly
