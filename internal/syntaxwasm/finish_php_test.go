package syntaxwasm

import (
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

func TestPromotedPropertiesAreFieldsOfTheClass(t *testing.T) {
	a := testAnalyzer(t)
	source := `<?php
class Account {
    public function __construct(
        public readonly string $owner,
        private int &$balance,
        string $note = '',
    ) {
        audit($note);
    }
}
function open() {
    return new class(1) {
        public function __construct(private int $id) {}
    };
}
`
	analysis := analyze(t, a, "account.php", []byte(source))
	got := definitionFlags(analysis)
	want := map[string]flags{
		"Account.owner":   {syntaxanalysis.KindField, true},
		"Account.balance": {syntaxanalysis.KindField, false},
	}
	for name, f := range want {
		if got[name] != f {
			t.Errorf("%s: got %+v, want %+v", name, got[name], f)
		}
	}
	for name := range got {
		if strings.Contains(name, "note") || strings.HasSuffix(name, ".id") {
			t.Errorf("%s was recorded", name)
		}
	}
	// The constructor body still belongs to the constructor.
	inside := analysis.EnclosingDefinition(strings.Index(source, "audit"))
	if inside < 0 || analysis.QualifiedName(inside).Untrusted() != "Account.__construct" {
		t.Fatalf("the constructor body is enclosed by %d", inside)
	}
	for _, r := range analysis.References {
		if r.Name.Untrusted() == "audit" && analysis.QualifiedName(r.Enclosing).Untrusted() != "Account.__construct" {
			t.Fatalf("the call in the constructor is enclosed by %d", r.Enclosing)
		}
	}
}
