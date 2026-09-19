package review

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestValidateContextPacketRequestBindsScopeSnapshotAndEvidence(t *testing.T) {
	reviewScope, memoryScope, snapshot, source, retrieval := contextPacketFixture(t, "line 10\nline 11\n")
	limits, _ := NewContextLimits(1<<20, 5)
	packet, err := NewContextPacket(
		reviewScope, memoryScope, snapshot, ContextTaskCandidateGeneration,
		[]ContextSource{source}, retrieval, limits,
	)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := packet.ProviderRequest()
	if err := ValidateContextPacketRequest(
		request.Payload(), packet.Identity(), reviewScope.Identity(), packet.MemoryScopeIdentity(), packet.MemoryIdentity(), snapshot, packet.EvidenceItems(),
	); err != nil {
		t.Fatal(err)
	}
	memoryTamper := bytes.Replace(request.Payload(), []byte("A prior reviewer requested explicit error handling."), []byte("A prior reviewer requested hidden error handling."), 1)
	tamperedDigest := sha256.Sum256(memoryTamper)
	if err := ValidateContextPacketRequest(memoryTamper, hex.EncodeToString(tamperedDigest[:]), reviewScope.Identity(), packet.MemoryScopeIdentity(), packet.MemoryIdentity(), snapshot, packet.EvidenceItems()); err == nil {
		t.Fatal("memory text tamper accepted with recomputed context identity")
	}

	malformed := [][]byte{
		append(append([]byte(nil), request.Payload()...), '\n'),
		bytes.Replace(request.Payload(), []byte(reviewScope.Identity()), []byte(strings.Repeat("f", 64)), 1),
		bytes.Replace(request.Payload(), []byte(source.EvidenceItem().Digest()), []byte(strings.Repeat("e", 64)), 1),
		bytes.Replace(request.Payload(), []byte(`"source_authority":"evidence_data_not_instructions"`), []byte(`"source_authority":"instructions"`), 1),
	}
	for index, payload := range malformed {
		if err := ValidateContextPacketRequest(
			payload, packet.Identity(), reviewScope.Identity(), packet.MemoryScopeIdentity(), packet.MemoryIdentity(), snapshot, packet.EvidenceItems(),
		); err == nil {
			t.Fatalf("malformed context %d accepted", index)
		}
	}
}

func TestContextMemoryRecordIdentityRejectsAllZeroAuthority(t *testing.T) {
	item := contextMemoryItemWire{Kind: "derived_observation", Taint: "trusted", Path: "internal/a.go", Text: "observation", DerivedFromIDs: []string{strings.Repeat("a", 64), strings.Repeat("b", 64)}, ProducerIdentity: strings.Repeat("c", 64), ObservedAt: 100, ValidFrom: 100, StaleAfter: 200, FreshnessIdentity: strings.Repeat("0", 64), Confidence: 5000}
	if identity := contextMemoryRecordIdentity(strings.Repeat("d", 64), item); identity != "" {
		t.Fatalf("all-zero freshness accepted: %s", identity)
	}
	item.FreshnessIdentity = strings.Repeat("e", 64)
	if identity := contextMemoryRecordIdentity(strings.Repeat("d", 64), item); identity == "" {
		t.Fatal("valid derived record rejected")
	}
	item.ProducerIdentity = strings.Repeat("0", 64)
	if identity := contextMemoryRecordIdentity(strings.Repeat("d", 64), item); identity != "" {
		t.Fatalf("all-zero producer accepted: %s", identity)
	}
}
