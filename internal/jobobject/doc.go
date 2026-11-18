// Package jobobject creates Windows job objects that contain a process tree:
// every process in the job is killed when the job is terminated or its last
// handle closes, including when the creating process dies. It is empty on
// other systems.
package jobobject
