package secretscan

import "sort"

// KnownRuleID reports whether ruleID belongs to the pinned Betterleaks ruleset.
func KnownRuleID(ruleID string) bool {
	index := sort.SearchStrings(betterleaksRuleIDsV1[:], ruleID)
	return index < len(betterleaksRuleIDsV1) && betterleaksRuleIDsV1[index] == ruleID
}

// PinnedRuleIDs returns the sorted Betterleaks rule identifiers accepted by protocol v1.
func PinnedRuleIDs() []string {
	return append([]string(nil), betterleaksRuleIDsV1[:]...)
}
