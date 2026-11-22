package evidence

// Bounds caller-controlled hashing while covering large source blobs.
const maxGitBlobObjectBytes = 64 << 20

func gitTreeValuesEqual(first, second GitTree) bool {
	if (first.entries == nil) != (second.entries == nil) || first.identity != second.identity || first.gitCommitIdentity != second.gitCommitIdentity || first.treeVerificationIdentity != second.treeVerificationIdentity || first.treeAlgorithm != second.treeAlgorithm || first.treeDigest != second.treeDigest || len(first.entries) != len(second.entries) {
		return false
	}
	for i := range first.entries {
		if !gitTreeEntryValuesEqual(first.entries[i], second.entries[i]) {
			return false
		}
	}
	return true
}

func gitTreeEntryValuesEqual(first, second GitTreeEntry) bool {
	if (first.name == nil) != (second.name == nil) || first.mode != second.mode || first.kind != second.kind || first.objectAlgorithm != second.objectAlgorithm || first.objectDigest != second.objectDigest || len(first.name) != len(second.name) {
		return false
	}
	for i := range first.name {
		if first.name[i] != second.name[i] {
			return false
		}
	}
	return true
}
