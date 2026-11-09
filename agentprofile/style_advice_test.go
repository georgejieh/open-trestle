package agentprofile

import (
	"errors"
	"reflect"
	"testing"
)

func TestProfileRecordedStyleAdviceValidate(t *testing.T) {
	pep8 := RecordedStyleRecommendation{Language: "python", ChangedFiles: 1, Recommendation: "PEP 8, enforced with Ruff or Black"}
	prettier := RecordedStyleRecommendation{Language: "typescript", ChangedFiles: 2, Recommendation: "Prettier with ESLint"}
	for _, test := range []struct {
		name   string
		advice RecordedStyleAdvice
		valid  bool
	}{
		{"recommendations in order", RecordedStyleAdvice{Recommendations: []RecordedStyleRecommendation{pep8, prettier}}, true},
		{"withheld with unread count", RecordedStyleAdvice{Recommendations: []RecordedStyleRecommendation{prettier}, Withheld: []RecordedStyleWithheld{{Language: "python", ChangedFiles: 1}}, ConfigurationUnread: 1}, true},
		{"unread count alone", RecordedStyleAdvice{ConfigurationUnread: 2}, true},
		{"unavailable alone", RecordedStyleAdvice{Unavailable: true}, true},
		{"no advice", RecordedStyleAdvice{}, true},
		{"unknown language", RecordedStyleAdvice{Recommendations: []RecordedStyleRecommendation{{Language: "java", ChangedFiles: 1, Recommendation: "PEP 8, enforced with Ruff or Black"}}}, false},
		{"recommendation text not from the table", RecordedStyleAdvice{Recommendations: []RecordedStyleRecommendation{{Language: "python", ChangedFiles: 1, Recommendation: "PEP 8"}}}, false},
		{"withheld without unread count", RecordedStyleAdvice{Withheld: []RecordedStyleWithheld{{Language: "python", ChangedFiles: 1}}}, false},
		{"withheld unknown language", RecordedStyleAdvice{Withheld: []RecordedStyleWithheld{{Language: "kotlin", ChangedFiles: 1}}, ConfigurationUnread: 1}, false},
		{"language recommended and withheld", RecordedStyleAdvice{Recommendations: []RecordedStyleRecommendation{pep8}, Withheld: []RecordedStyleWithheld{{Language: "python", ChangedFiles: 1}}, ConfigurationUnread: 1}, false},
		{"recommendations out of order", RecordedStyleAdvice{Recommendations: []RecordedStyleRecommendation{prettier, pep8}}, false},
		{"duplicate recommendation", RecordedStyleAdvice{Recommendations: []RecordedStyleRecommendation{pep8, pep8}}, false},
		{"zero changed files", RecordedStyleAdvice{Recommendations: []RecordedStyleRecommendation{{Language: "python", Recommendation: pep8.Recommendation}}}, false},
		{"too many changed files", RecordedStyleAdvice{Recommendations: []RecordedStyleRecommendation{{Language: "python", ChangedFiles: maxFeatureFiles + 1, Recommendation: pep8.Recommendation}}}, false},
		{"negative unread count", RecordedStyleAdvice{ConfigurationUnread: -1}, false},
		{"unavailable with a recommendation", RecordedStyleAdvice{Recommendations: []RecordedStyleRecommendation{pep8}, Unavailable: true}, false},
		{"unavailable with an unread count", RecordedStyleAdvice{ConfigurationUnread: 1, Unavailable: true}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := test.advice.Validate()
			if test.valid != (err == nil) || err != nil && !errors.Is(err, ErrInvalidStyleAdvice) {
				t.Fatalf("Validate() = %v, want valid=%t", err, test.valid)
			}
		})
	}
}

func TestProfileStyleAdviceRecordUsesTheFixedTable(t *testing.T) {
	advice := StyleAdvice{Recommendations: []StyleRecommendation{{LanguageGo, 1}}, Withheld: []StyleRecommendation{{LanguagePython, 2}}}
	recorded := advice.Record(1)
	want := RecordedStyleAdvice{
		Recommendations:     []RecordedStyleRecommendation{{Language: "go", ChangedFiles: 1, Recommendation: "gofmt and Effective Go"}},
		Withheld:            []RecordedStyleWithheld{{Language: "python", ChangedFiles: 2}},
		ConfigurationUnread: 1,
	}
	if !reflect.DeepEqual(recorded, want) || recorded.Validate() != nil || recorded.Empty() || !(RecordedStyleAdvice{}).Empty() {
		t.Fatalf("Record() = %+v, want %+v", recorded, want)
	}
}
