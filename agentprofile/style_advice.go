package agentprofile

import (
	"errors"
	"fmt"
)

// ErrInvalidStyleAdvice identifies recorded style advice that no review could
// have recorded.
var ErrInvalidStyleAdvice = errors.New("invalid style advice")

// RecordedStyleAdvice is style advice as a review result or review set records
// it: a fixed recommendation for each changed language that has a style
// detector but no style declared by the base tree, and the languages withheld
// because a base style configuration file that could declare their style was
// not read (over 64 KiB, not valid UTF-8, beyond 256 files, or past the 1 MiB
// change-features document bound that routing uses).
// ConfigurationUnread counts those files. Unavailable alone marks a recorded
// change model, its snapshots or a base style configuration file that could not
// be read back, so no advice could be derived. The text is the fixed table of
// RecommendedStyle, not model output. Style advice never blocks: it is not a
// finding and never changes status, CI disposition, exit code, coverage or
// clearance. Every field is omitted from JSON when empty.
type RecordedStyleAdvice struct {
	Recommendations     []RecordedStyleRecommendation `json:"style_recommendations,omitempty"`
	Withheld            []RecordedStyleWithheld       `json:"style_withheld,omitempty"`
	ConfigurationUnread int                           `json:"style_configuration_unread,omitempty"`
	Unavailable         bool                          `json:"style_advice_unavailable,omitempty"`
}

// RecordedStyleRecommendation suggests the standard style for one changed language.
type RecordedStyleRecommendation struct {
	Language       string `json:"language"`
	ChangedFiles   int    `json:"changed_files"`
	Recommendation string `json:"recommendation"`
}

// RecordedStyleWithheld is a changed language whose declared style is unknown.
type RecordedStyleWithheld struct {
	Language     string `json:"language"`
	ChangedFiles int    `json:"changed_files"`
}

// Record projects computed advice, with the number of unread base style
// configuration files, into its recorded form.
func (a StyleAdvice) Record(unread int) RecordedStyleAdvice {
	recorded := RecordedStyleAdvice{ConfigurationUnread: unread}
	for _, value := range a.Recommendations {
		_, standard, _ := RecommendedStyle(value.Language)
		recorded.Recommendations = append(recorded.Recommendations, RecordedStyleRecommendation{Language: string(value.Language), ChangedFiles: value.ChangedFiles, Recommendation: standard})
	}
	for _, value := range a.Withheld {
		recorded.Withheld = append(recorded.Withheld, RecordedStyleWithheld{Language: string(value.Language), ChangedFiles: value.ChangedFiles})
	}
	return recorded
}

// Empty reports whether the advice records nothing.
func (a RecordedStyleAdvice) Empty() bool {
	return len(a.Recommendations) == 0 && len(a.Withheld) == 0 && a.ConfigurationUnread == 0 && !a.Unavailable
}

// Validate reports whether a review could have recorded the advice: every
// language has a style detector, each recommendation is its fixed table text,
// changed-file counts are within the change bound, recommendations and withheld
// languages are each in strict language order with no language in both, a
// withheld language comes with an unread count, and Unavailable stands alone.
// Empty advice is valid.
func (a RecordedStyleAdvice) Validate() error {
	invalid := func(detail string) error { return fmt.Errorf("%w: %s", ErrInvalidStyleAdvice, detail) }
	if a.Unavailable {
		if len(a.Recommendations) != 0 || len(a.Withheld) != 0 || a.ConfigurationUnread != 0 {
			return invalid("unavailable advice carries other advice")
		}
		return nil
	}
	if a.ConfigurationUnread < 0 {
		return invalid("negative unread count")
	}
	if len(a.Withheld) != 0 && a.ConfigurationUnread == 0 {
		return invalid("withheld language without an unread file")
	}
	seen := map[string]bool{}
	check := func(language string, changedFiles int, previous string) (string, error) {
		_, standard, ok := RecommendedStyle(Language(language))
		switch {
		case !ok:
			return "", invalid("language has no style detector")
		case seen[language] || language <= previous:
			return "", invalid("languages are not in strict order or repeat")
		case changedFiles < 1 || changedFiles > maxFeatureFiles:
			return "", invalid("changed file count out of range")
		}
		seen[language] = true
		return standard, nil
	}
	previous := ""
	for _, value := range a.Recommendations {
		standard, err := check(value.Language, value.ChangedFiles, previous)
		if err != nil {
			return err
		}
		if value.Recommendation != standard {
			return invalid("recommendation is not the fixed table text")
		}
		previous = value.Language
	}
	previous = ""
	for _, value := range a.Withheld {
		if _, err := check(value.Language, value.ChangedFiles, previous); err != nil {
			return err
		}
		previous = value.Language
	}
	return nil
}

// Lines returns the newline-terminated text lines that describe the advice:
// one per recommendation, one per withheld language, one for unread files, and
// one when the advice is unavailable.
func (a RecordedStyleAdvice) Lines() []string {
	var lines []string
	files := func(count int) string {
		if count == 1 {
			return "1 changed file"
		}
		return fmt.Sprintf("%d changed files", count)
	}
	for _, value := range a.Recommendations {
		name, _, _ := RecommendedStyle(Language(value.Language))
		lines = append(lines, fmt.Sprintf("style: no declared %s style for %s; consider %s, and commit its configuration\n", name, files(value.ChangedFiles), value.Recommendation))
	}
	for _, value := range a.Withheld {
		name, _, _ := RecommendedStyle(Language(value.Language))
		lines = append(lines, fmt.Sprintf("style: declared %s style unknown for %s; a base style configuration file that may declare it was not read, so no recommendation is made\n", name, files(value.ChangedFiles)))
	}
	if a.ConfigurationUnread > 0 {
		subject := "file was"
		if a.ConfigurationUnread != 1 {
			subject = "files were"
		}
		lines = append(lines, fmt.Sprintf("style: %d base style configuration %s not read (over 64 KiB, not valid UTF-8, beyond 256 files, or past the 1 MiB change-features bound)\n", a.ConfigurationUnread, subject))
	}
	if a.Unavailable {
		lines = append(lines, "style: advice unavailable; the recorded change or base style configuration could not be read back\n")
	}
	return lines
}
