package checksandbox

import (
	"slices"
	"testing"

	"golang.org/x/sys/windows"
)

// TestSplitGroupsDeniesAdministratorsAndOtherGroups uses the groups of an
// elevated domain account, which no test here can run as.
func TestSplitGroupsDeniesAdministratorsAndOtherGroups(t *testing.T) {
	const enabled = windows.SE_GROUP_MANDATORY | windows.SE_GROUP_ENABLED_BY_DEFAULT | windows.SE_GROUP_ENABLED
	groups := []struct {
		sid        string
		attributes uint32
	}{
		{"S-1-1-0", enabled},
		{"S-1-5-32-545", enabled},
		{"S-1-5-11", enabled},
		{"S-1-5-5-0-123456", enabled | windows.SE_GROUP_LOGON_ID},
		{"S-1-5-32-544", enabled | windows.SE_GROUP_OWNER},
		{"S-1-5-21-1-2-3-513", enabled},
		{"S-1-5-4", enabled},
		{"S-1-5-114", windows.SE_GROUP_USE_FOR_DENY_ONLY},
		{"S-1-16-12288", windows.SE_GROUP_INTEGRITY | windows.SE_GROUP_INTEGRITY_ENABLED},
	}
	var list []windows.SIDAndAttributes
	for _, group := range groups {
		sid, err := windows.StringToSid(group.sid)
		if err != nil {
			t.Fatal(err)
		}
		list = append(list, windows.SIDAndAttributes{Sid: sid, Attributes: group.attributes})
	}
	kept, denied := splitGroups(list)
	if got, want := sidStrings(kept), []string{"S-1-1-0", "S-1-5-32-545", "S-1-5-11", "S-1-5-5-0-123456"}; !slices.Equal(got, want) {
		t.Errorf("kept %v, want %v", got, want)
	}
	if got, want := sidStrings(denied), []string{"S-1-5-32-544", "S-1-5-21-1-2-3-513", "S-1-5-4"}; !slices.Equal(got, want) {
		t.Errorf("denied %v, want %v", got, want)
	}
}

func sidStrings(sids []*windows.SID) []string {
	var texts []string
	for _, sid := range sids {
		texts = append(texts, sid.String())
	}
	return texts
}
