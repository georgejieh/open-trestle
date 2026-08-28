package review

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/georgejieh/open-trestle/internal/config"
	"github.com/georgejieh/open-trestle/internal/evidence"
)

const maxSourceBytes = 1 << 20

// ReviewLocalFixture reviews one manifest and its declared source within a confined directory.
func ReviewLocalFixture(fixturePath string, configuration config.LocalConfig) (LocalResult, error) {
	root, err := os.OpenRoot(filepath.Dir(fixturePath))
	if err != nil {
		return LocalResult{}, failedOutcome("open fixture directory", err)
	}
	defer root.Close()

	fixture, err := loadConfinedFixture(root, filepath.Base(fixturePath), configuration)
	if err != nil {
		return LocalResult{}, err
	}
	request := fixture.Request()
	snapshot := request.Snapshot()
	result := LocalResult{
		fixtureIdentity:  fixture.Identity(),
		requestID:        request.ID(),
		snapshotIdentity: snapshot.Identity(),
		revision:         snapshot.Revision(),
	}
	ranges := snapshot.Ranges()
	if len(ranges) != 1 {
		return LocalResult{}, failedOutcomeMessage("static adapter requires exactly one source range")
	}
	sourceRange := ranges[0]
	source, err := readConfinedSource(root, sourceRange.Path())
	if err != nil {
		return LocalResult{}, newOutcomeError(OutcomeFailed, err)
	}
	if digestHex(source) != snapshot.Revision() {
		return LocalResult{}, failedOutcomeMessage("source content does not match declared revision")
	}
	if _, err := selectSourceRange(source, sourceRange); err != nil {
		return LocalResult{}, newOutcomeError(OutcomeFailed, err)
	}
	findings, items, err := reviewDebugOutputs(source, sourceRange)
	if err != nil {
		return LocalResult{}, newOutcomeError(OutcomeFailed, err)
	}
	if len(findings) == 0 {
		result.outcome = OutcomeInconclusive
		result.reason = "static debug-output rule did not match the declared range"
		return result, nil
	}
	result.outcome = OutcomeVerified
	result.finding = findings[0]
	result.evidence = items[0]
	return result, nil
}

func loadConfinedFixture(root *os.Root, fixtureName string, configuration config.LocalConfig) (Fixture, error) {
	fixtureFile, err := root.Open(fixtureName)
	if err != nil {
		return Fixture{}, failedOutcome("open fixture", err)
	}
	fixture, loadErr := LoadFixture(fixtureFile, configuration)
	closeErr := fixtureFile.Close()
	if loadErr != nil {
		return Fixture{}, loadErr
	}
	if closeErr != nil {
		return Fixture{}, failedOutcome("close fixture", closeErr)
	}
	return fixture, nil
}

func readConfinedSource(root *os.Root, sourcePath string) ([]byte, error) {
	file, err := root.Open(sourcePath)
	if err != nil {
		return nil, fmt.Errorf("open declared source %q: %w", sourcePath, err)
	}
	defer file.Close()

	content, err := io.ReadAll(io.LimitReader(file, maxSourceBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read declared source %q: %w", sourcePath, err)
	}
	if len(content) > maxSourceBytes {
		return nil, fmt.Errorf("declared source %q exceeds %d bytes", sourcePath, maxSourceBytes)
	}
	return content, nil
}

func selectSourceRange(content []byte, sourceRange evidence.SourceRange) ([]byte, error) {
	var lines []string
	if len(content) > 0 {
		lines = strings.Split(string(content), "\n")
		if content[len(content)-1] == '\n' {
			lines = lines[:len(lines)-1]
		}
	}
	if sourceRange.EndLine() > len(lines) {
		return nil, fmt.Errorf("declared range %s:%d-%d exceeds source length", sourceRange.Path(), sourceRange.StartLine(), sourceRange.EndLine())
	}
	return []byte(strings.Join(lines[sourceRange.StartLine()-1:sourceRange.EndLine()], "\n")), nil
}

func failedOutcome(operation string, err error) *OutcomeError {
	return newOutcomeError(OutcomeFailed, fmt.Errorf("%s: %w", operation, err))
}

func failedOutcomeMessage(message string) *OutcomeError {
	return newOutcomeError(OutcomeFailed, errors.New(message))
}

func digestHex(content []byte) string {
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}
