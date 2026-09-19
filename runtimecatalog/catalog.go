// Package runtimecatalog composes approved task implementations into an exact review pipeline.
package runtimecatalog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"

	"github.com/georgejieh/open-trestle/controlplane"
)

var ErrInvalidPipelineCatalog = errors.New("invalid runtime pipeline catalog")

type HandlerBinding struct {
	Kind            controlplane.TaskKind
	HandlerIdentity string
}
type PipelineCatalog struct {
	identity string
	mode     controlplane.ReviewRunMode
	catalog  controlplane.TaskHandlerCatalog
	bindings []HandlerBinding
}

func NewPipelineCatalog(mode controlplane.ReviewRunMode, handlers []controlplane.TaskHandler) (PipelineCatalog, error) {
	if mode.Validate() != nil {
		return PipelineCatalog{}, ErrInvalidPipelineCatalog
	}
	expected := []controlplane.TaskKind{controlplane.TaskAcquireSource, controlplane.TaskBuildChange, controlplane.TaskInspectDeterministic, controlplane.TaskRetrieveContext, controlplane.TaskAssembleContext, controlplane.TaskGenerateCandidates, controlplane.TaskVerifyCandidates, controlplane.TaskEvaluatePublication}
	if mode == controlplane.ReviewRunRequired {
		expected = append(expected, controlplane.TaskPublishResult)
	}
	if len(handlers) != len(expected) {
		return PipelineCatalog{}, ErrInvalidPipelineCatalog
	}
	byKind := make(map[controlplane.TaskKind]controlplane.TaskHandler, len(handlers))
	for _, handler := range handlers {
		if handler == nil || handler.Kind().Validate() != nil || controlplane.ValidateHandlerIdentity(handler.HandlerIdentity()) != nil {
			return PipelineCatalog{}, ErrInvalidPipelineCatalog
		}
		if _, exists := byKind[handler.Kind()]; exists {
			return PipelineCatalog{}, ErrInvalidPipelineCatalog
		}
		byKind[handler.Kind()] = handler
	}
	ordered := make([]controlplane.TaskHandler, len(expected))
	bindings := make([]HandlerBinding, len(expected))
	for index, kind := range expected {
		handler, exists := byKind[kind]
		if !exists {
			return PipelineCatalog{}, ErrInvalidPipelineCatalog
		}
		ordered[index] = handler
		bindings[index] = HandlerBinding{kind, handler.HandlerIdentity()}
	}
	catalog, err := controlplane.NewTaskHandlerCatalog(ordered)
	if err != nil {
		return PipelineCatalog{}, ErrInvalidPipelineCatalog
	}
	value := PipelineCatalog{mode: mode, catalog: catalog, bindings: bindings}
	value.identity = deriveIdentity(value)
	return value, nil
}
func (c PipelineCatalog) Identity() string                         { return c.identity }
func (c PipelineCatalog) Mode() controlplane.ReviewRunMode         { return c.mode }
func (c PipelineCatalog) Catalog() controlplane.TaskHandlerCatalog { return c.catalog }
func (c PipelineCatalog) Bindings() []HandlerBinding {
	return append([]HandlerBinding(nil), c.bindings...)
}
func (c PipelineCatalog) Validate() error {
	if c.mode.Validate() != nil || c.catalog.Validate() != nil || len(c.bindings) == 0 || c.identity != deriveIdentity(c) {
		return ErrInvalidPipelineCatalog
	}
	previous := controlplane.TaskKind(0)
	for _, binding := range c.bindings {
		if binding.Kind <= previous || controlplane.ValidateHandlerIdentity(binding.HandlerIdentity) != nil {
			return ErrInvalidPipelineCatalog
		}
		handler, ok := c.catalog.Resolve(binding.HandlerIdentity)
		if !ok || handler.Kind() != binding.Kind {
			return ErrInvalidPipelineCatalog
		}
		previous = binding.Kind
	}
	return nil
}
func deriveIdentity(c PipelineCatalog) string {
	type wire struct {
		Kind    string `json:"kind"`
		Handler string `json:"handler"`
	}
	bindings := make([]wire, len(c.bindings))
	for i, v := range c.bindings {
		bindings[i] = wire{v.Kind.String(), v.HandlerIdentity}
	}
	sort.Slice(bindings, func(i, j int) bool { return bindings[i].Kind < bindings[j].Kind })
	encoded, _ := json.Marshal(struct {
		Contract string `json:"contract"`
		Version  int    `json:"version"`
		Mode     string `json:"mode"`
		Bindings []wire `json:"bindings"`
	}{"open-trestle/runtime-pipeline-catalog", 1, c.mode.String(), bindings})
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
