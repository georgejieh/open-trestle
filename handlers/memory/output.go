package memory

import (
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/internal/changecodec"
	memorycore "github.com/georgejieh/open-trestle/internal/memory"
	"github.com/georgejieh/open-trestle/internal/memorycodec"
	"strings"
	"time"
)

const (
	maximumQueries = 64
	maximumRecords = 50
)

var ErrInvalidHandler = errors.New("invalid memory retrieval handler")

// ErrInvalidResult initially shares the codec sentinel. Reassigning either exported var breaks that identity.
var ErrInvalidResult = memorycodec.ErrInvalidResult

type Item = memorycodec.Item
type Query = memorycodec.Query
type Omission = memorycodec.Omission
type Result = memorycodec.Result

func ParseResultArtifact(value, changeArtifact, baseArtifact, headArtifact artifact.Artifact) (Result, error) {
	return memorycodec.ParseResultArtifact(value, changeArtifact, baseArtifact, headArtifact)
}
func newResult(changeArtifact artifact.Artifact, change changecodec.Result, policy, retriever string, scope memorycore.Scope, at time.Time, queries []Query, omissions []Omission) (Result, error) {
	return memorycodec.NewResult(changeArtifact, change, policy, retriever, scope, at, queries, omissions)
}
func encodeResult(result Result, change changecodec.Result) ([]byte, error) {
	return memorycodec.EncodeResult(result, change)
}
func validDigest(v string) bool {
	if len(v) != 64 || v != strings.ToLower(v) || strings.Trim(v, "0") == "" {
		return false
	}
	d, e := hex.DecodeString(v)
	return e == nil && hex.EncodeToString(d) == v
}
func writeRedacted(s fmt.State, v rune, p, d string) {
	x := p
	if v == 'q' {
		x = fmt.Sprintf("%q", p)
	} else if v == 'v' && s.Flag('#') {
		x = d
	}
	_, _ = s.Write([]byte(x))
}
