package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/georgejieh/open-trestle/internal/fileauthority"
)

// A small local record of the last review `trestle review`, the home screen
// or `trestle init` ran for a setup, so the home screen can show it. It is
// last-review.json in the setup folder, a protected 0600 file replaced
// atomically after each review. It holds the time, the result status, the
// number of confirmed findings and the two commit IDs: no source, finding
// text, prompt, model reply or key. A review run directly with
// `trestle local-git model-review` is not recorded.

const lastReviewContract = "open-trestle/last-review"

type lastReview struct {
	Contract   string `json:"contract"`
	Version    int    `json:"schema_version"`
	RecordedAt string `json:"recorded_at"`
	Status     string `json:"status"`
	Findings   int    `json:"findings"`
	Base       string `json:"base"`
	Head       string `json:"head"`
}

var (
	lastReviewCommit = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)
	lastReviewStatus = regexp.MustCompile(`^[a-z_]{1,32}$`)
)

func (r lastReview) valid() bool {
	_, err := time.Parse(time.RFC3339, r.RecordedAt)
	return r.Contract == lastReviewContract && r.Version == 1 && err == nil && lastReviewStatus.MatchString(r.Status) && r.Findings >= 0 && r.Findings < 1<<20 && lastReviewCommit.MatchString(r.Base) && lastReviewCommit.MatchString(r.Head)
}

// recordLastReview replaces the setup's last-review record. A failure is
// silent: the record is a convenience for the home screen, never evidence.
func recordLastReview(ctx context.Context, dir string, review lastReview) {
	review.Contract, review.Version, review.RecordedAt = lastReviewContract, 1, spendingNow().UTC().Format(time.RFC3339)
	if !review.valid() || ctx == nil {
		return
	}
	encoded, err := json.Marshal(review)
	if err != nil {
		return
	}
	_ = replaceProtectedFile(context.WithoutCancel(ctx), filepath.Join(dir, "last-review.json"), append(encoded, '\n'))
}

// readLastReview returns the setup's last-review record, or false.
func readLastReview(dir string) (lastReview, bool) {
	content, err := readSetupBootstrapFile(filepath.Join(dir, "last-review.json"))
	if err != nil {
		return lastReview{}, false
	}
	var review lastReview
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&review) != nil || decoder.Decode(&struct{}{}) != io.EOF || !review.valid() {
		return lastReview{}, false
	}
	return review, true
}

// replaceProtectedFile installs content at path through a new protected
// temporary file in the same folder and a rename, so a reader sees the old
// content or the new, never part of either. An existing entry that is not a
// regular 0600 file owned by this account, such as a symbolic link, is
// refused.
func replaceProtectedFile(ctx context.Context, path string, content []byte) error {
	if info, err := os.Lstat(path); err == nil && (!info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || !fileauthority.TrustedOwner(info)) {
		return errors.New("not a protected file")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return err
	}
	temporary := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+"."+hex.EncodeToString(suffix)+".tmp")
	if err := fileauthority.WriteNewProtectedFile(ctx, temporary, content, 65536); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	defer func() { _ = os.Remove(temporary) }()
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	return errors.Join(syncErr, directory.Close())
}
