package localreview

// A review set's walkthrough describes the whole set, not one member. Every
// member reviews the same change, so the per-file summary, the deterministic
// checks, style detection and the semantic-impact profile are shared; the
// secret scan and the independent verifier ran once per member, so the set
// reports their totals over the completed members, with each member's own
// account beside them.

// WalkthroughMember is one completed set member's own account: the secret
// scan of its model requests and its independent verifier's counts (absent
// when it recorded no verified set). A member whose walkthrough could not be
// read reports the secret-scan state unavailable and no verifier.
type WalkthroughMember struct {
	Member     string                `json:"member"`
	SecretScan WalkthroughSecretScan `json:"secret_scan"`
	Verifier   *WalkthroughVerifier  `json:"verifier,omitempty"`
}

// SetWalkthrough is a review set's walkthrough. Its Verified.SecretScan sums
// the completed members' scans (state scanned when every member scanned or
// prepared no request, not_run when none prepared one, unavailable when a
// member's account could not be read; the totals then cover the members that
// scanned), and Verified.Verifier sums their verifier counts with the weakest
// independence among them. Files, the deterministic checks, style detection
// and semantic impact are the first completed member's (the general review
// when it completed); missing-verification notes are the completed members'
// notes, deduplicated. VerifiedByMember lists each completed member's own
// account in member order.
type SetWalkthrough struct {
	Walkthrough
	VerifiedByMember []WalkthroughMember `json:"verified_by_member"`
}

// MemberWalkthrough is one completed member's walkthrough for
// AggregateWalkthroughs; Walkthrough is nil when the member's result carries
// none.
type MemberWalkthrough struct {
	Member      string
	Walkthrough *Walkthrough
}

// AggregateWalkthroughs builds a review set's walkthrough from its completed
// members, in member order. It returns nil when no member has a walkthrough.
func AggregateWalkthroughs(members []MemberWalkthrough) *SetWalkthrough {
	var base *Walkthrough
	for _, member := range members {
		if member.Walkthrough != nil {
			base = member.Walkthrough
			break
		}
	}
	if base == nil {
		return nil
	}
	set := &SetWalkthrough{Walkthrough: *base.clone(), VerifiedByMember: []WalkthroughMember{}}
	scan := WalkthroughSecretScan{State: SecretScanNotRun}
	unavailable, scanned := false, false
	var verifier *WalkthroughVerifier
	seen := map[MissingVerification]bool{}
	set.MissingVerification = []MissingVerification{}
	set.MissingVerificationNotListed = 0
	set.MissingVerificationIncomplete = false
	for _, member := range members {
		entry := WalkthroughMember{Member: member.Member, SecretScan: WalkthroughSecretScan{State: SecretScanUnreadable}}
		if walk := member.Walkthrough; walk != nil {
			entry.SecretScan = walk.Verified.SecretScan
			if walk.Verified.Verifier != nil {
				own := *walk.Verified.Verifier
				entry.Verifier = &own
			}
			for _, note := range walk.MissingVerification {
				if seen[note] {
					continue
				}
				seen[note] = true
				if len(set.MissingVerification) == maxWalkthroughMissing {
					set.MissingVerificationNotListed++
					continue
				}
				set.MissingVerification = append(set.MissingVerification, note)
			}
			set.MissingVerificationNotListed = max(set.MissingVerificationNotListed, walk.MissingVerificationNotListed)
			set.MissingVerificationIncomplete = set.MissingVerificationIncomplete || walk.MissingVerificationIncomplete
		}
		switch entry.SecretScan.State {
		case SecretScanScanned:
			scanned = true
			scan.Requests += entry.SecretScan.Requests
			scan.ScannedBytes += entry.SecretScan.ScannedBytes
			scan.Matches += entry.SecretScan.Matches
			scan.RedactedBytes += entry.SecretScan.RedactedBytes
		case SecretScanNotRun:
		default:
			unavailable = true
		}
		if own := entry.Verifier; own != nil {
			if verifier == nil {
				verifier = &WalkthroughVerifier{Independence: own.Independence}
			} else if independenceRank(own.Independence) < independenceRank(verifier.Independence) {
				verifier.Independence = own.Independence
			}
			verifier.Candidates = saturatingAdd(verifier.Candidates, own.Candidates)
			verifier.Verified = saturatingAdd(verifier.Verified, own.Verified)
			verifier.Rejected = saturatingAdd(verifier.Rejected, own.Rejected)
			verifier.Inconclusive = saturatingAdd(verifier.Inconclusive, own.Inconclusive)
		}
		set.VerifiedByMember = append(set.VerifiedByMember, entry)
	}
	switch {
	case unavailable:
		scan.State = SecretScanUnreadable
	case scanned:
		scan.State = SecretScanScanned
	}
	set.Verified.SecretScan = scan
	set.Verified.Verifier = verifier
	return set
}

func saturatingAdd(a, b uint16) uint16 {
	if a > ^uint16(0)-b {
		return ^uint16(0)
	}
	return a + b
}

// setScanCounts counts the members a set walkthrough's secret scan and
// verifier lines describe.
type setScanCounts struct {
	reviewers, scanUnavailable, verified int
}

func (w *SetWalkthrough) counts() setScanCounts {
	counts := setScanCounts{reviewers: len(w.VerifiedByMember)}
	for _, member := range w.VerifiedByMember {
		if member.SecretScan.State != SecretScanScanned && member.SecretScan.State != SecretScanNotRun {
			counts.scanUnavailable++
		}
		if member.Verifier != nil {
			counts.verified++
		}
	}
	return counts
}
