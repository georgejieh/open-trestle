package model

import (
	"errors"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

func TestSanitizedDispatchProofRequiresJointArtifactValidation(t *testing.T) {
	scope, _, _, contextArtifact, raw := generationContextFixture(t)
	_, receipt, requestArtifact, receiptArtifact, expected := sanitizedGenerationFixture(t, scope, contextArtifact, raw, "")
	proof, err := newGenerationDispatchProof(contextArtifact, requestArtifact, receiptArtifact, expected)
	if err != nil {
		t.Fatal(err)
	}
	if proof.ReceiptIdentity() != receipt.Identity() || proof.ValidateRequest(scope.Identity(), receipt.SanitizedRequestIdentity()) != nil {
		t.Fatal("validated proof did not bind its exact scope, request, and receipt")
	}
	if (SanitizedDispatchProof{}).ReceiptIdentity() != "" || !errors.Is((SanitizedDispatchProof{}).ValidateRequest(scope.Identity(), receipt.SanitizedRequestIdentity()), errInvalidSanitizedDispatchProof) {
		t.Fatal("zero proof acquired dispatch authority")
	}
	if proof.ValidateRequest(strings.Repeat("e", 64), receipt.SanitizedRequestIdentity()) == nil || proof.ValidateRequest(scope.Identity(), strings.Repeat("e", 64)) == nil {
		t.Fatal("proof was replayable across scope or request")
	}
	wrongExpected := expected
	wrongExpected.HelperSHA256 = strings.Repeat("e", 64)
	if forged, err := newGenerationDispatchProof(contextArtifact, requestArtifact, receiptArtifact, wrongExpected); !errors.Is(err, errInvalidSanitizedDispatchProof) || forged.ReceiptIdentity() != "" {
		t.Fatal("wrong scanner authority constructed a proof")
	}
}

func TestGenericCallersCannotCompileReceiptBearingDispatch(t *testing.T) {
	proofType := reflect.TypeOf(SanitizedDispatchProof{})
	for index := 0; index < proofType.NumField(); index++ {
		if proofType.Field(index).PkgPath == "" {
			t.Fatalf("proof field %q is externally constructible", proofType.Field(index).Name)
		}
	}
	command := exec.Command("go", "test", "./testdata/legacycaller")
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatal("legacy compile-negative fixture unexpectedly compiled")
	}
	text := string(output)
	for _, expected := range []string{
		"undefined: gateway.DispatchAuthorizedSanitizedRoute",
		"undefined: modelhandler.NewSanitizedDispatchProof",
		"cannot refer to unexported field receiptIdentity",
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("compile-negative failure omitted %q:\n%s", expected, text)
		}
	}
}
