// Package ownersonly checks and creates files and directories on Windows that
// only the current user and the system's own administrative identities can
// access. It has code only on Windows.
//
// ownersonly_windows.go is a copy of the root module's
// internal/ownersonly/ownersonly_windows.go, which this module cannot import.
// A test in the root module keeps both copies equal.
package ownersonly
