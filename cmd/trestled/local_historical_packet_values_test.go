//go:build linux

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/georgejieh/open-trestle/artifact"
)

func TestPhysicalPacketObservationExposesOnlyExactParsedValues(t *testing.T) {
	for _, mode := range []string{"intact", "malformed", "missing", "late change"} {
		t.Run(mode, func(t *testing.T) {
			fixture := newPhysicalPacketTestFixture(t)
			if mode == "malformed" {
				fixture.overwriteSecondPayloadByte(t)
			}
			if mode == "missing" {
				if err := os.Remove(filepath.Join(fixture.root, fixture.names[1])); err != nil {
					t.Fatal(err)
				}
			}
			called := false
			err := fixture.observe(t, fixture.expected, func(observations []physicalPacketObservation) error {
				called = true
				if len(observations) != 2 {
					t.Fatal("observations missing")
				}
				for i, observation := range observations {
					if observation.kind == physicalPacketIntact {
						encoded, err := artifact.Encode(observation.value)
						if err != nil || !bytes.Equal(encoded, fixture.original[i]) {
							t.Fatalf("value detached from observed bytes: %v", err)
						}
					} else if observation.value.Identity() != "" {
						t.Fatal("invalid or missing bytes exposed as artifact")
					}
				}
				if mode == "late change" {
					fixture.overwriteSecondPayloadByte(t)
				}
				return nil
			})
			if !called {
				t.Fatal("callback missing")
			}
			if mode == "late change" {
				if !errors.Is(err, errPhysicalPacketObservationUncertain) {
					t.Fatal("provisional values survived late drift")
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}
