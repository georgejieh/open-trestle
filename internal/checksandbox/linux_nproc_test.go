package checksandbox

import "testing"

func TestCountsHostTasksBeforeLinux514(t *testing.T) {
	for release, want := range map[string]bool{
		"4.19.0-26-amd64":                   true,
		"5.13.19":                           true,
		"5.14.0-427.el9.x86_64":             false,
		"6.18.58.1-microsoft-standard-WSL2": false,
		"10.0":                              false,
		"":                                  true,
	} {
		if got := countsHostTasks(release); got != want {
			t.Errorf("countsHostTasks(%q) = %v, want %v", release, got, want)
		}
	}
}

func TestAccountTasksCountsThisProcess(t *testing.T) {
	if count := accountTasks(); count < 1 {
		t.Fatalf("counted %d tasks of this account", count)
	}
}
