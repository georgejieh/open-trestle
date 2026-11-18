// Package thirdparty holds the patched copies of third-party modules that
// the scan guest links, with one patch per copy. The guest module replaces
// the upstream module with the copy. This package's tests check that every
// copy equals its upstream release with exactly its patch applied.
package thirdparty
