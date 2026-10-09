package controlplane

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func TestStartupInventoryDoesNotTakeGateMu(t *testing.T) {
	inspectors := []struct {
		name    string
		inspect func(*FileRunJournal) error
	}{
		{
			name: "startup inventory",
			inspect: func(j *FileRunJournal) error {
				inventory, err := j.InspectStartupInventory(context.Background())
				if err != nil {
					return err
				}
				if inventory != (StartupInventory{}) {
					return fmt.Errorf("nonempty inventory: %+v", inventory)
				}
				return nil
			},
		},
		{
			name: "historical context packets",
			inspect: func(j *FileRunJournal) error {
				facts, err := j.InspectHistoricalContextPackets(context.Background())
				if err != nil {
					return err
				}
				if len(facts) != 0 {
					return fmt.Errorf("nonempty historical facts: %d", len(facts))
				}
				return nil
			},
		},
	}
	for _, inspector := range inspectors {
		t.Run(inspector.name, func(t *testing.T) {
			j, err := NewFileRunJournal(filepath.Join(t.TempDir(), "journal"))
			if err != nil {
				t.Fatal(err)
			}
			j.gateMu.Lock()
			gateHeld := true
			done := make(chan error, 1)
			finished := false
			defer func() {
				if gateHeld {
					j.gateMu.Unlock()
				}
				if !finished {
					select {
					case err := <-done:
						finished = true
						if err != nil {
							t.Errorf("inspection after releasing gateMu: %v", err)
						}
					case <-time.After(2 * time.Second):
						t.Error("inspector did not finish after releasing gateMu; journal left open")
					}
				}
				if finished {
					if err := j.Close(); err != nil {
						t.Errorf("close journal: %v", err)
					}
				}
			}()
			go func() { done <- inspector.inspect(j) }()
			timer := time.NewTimer(2 * time.Second)
			defer timer.Stop()
			select {
			case err := <-done:
				finished = true
				if err != nil {
					t.Errorf("inspection with gateMu held: %v", err)
				}
			case <-timer.C:
				t.Error("inspector blocked on gateMu")
			}
		})
	}
}
