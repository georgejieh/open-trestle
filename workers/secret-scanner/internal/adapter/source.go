package adapter

import (
	"context"
	"sync/atomic"

	"github.com/betterleaks/betterleaks/sources"
)

type singleFragmentSource struct {
	content   []byte
	completed atomic.Bool
}

func newSingleFragmentSource(content []byte) *singleFragmentSource {
	return &singleFragmentSource{content: content}
}

func (s *singleFragmentSource) Fragments(ctx context.Context, yield sources.FragmentsFunc) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := yield(sources.Fragment{Raw: string(s.content), StartLine: 1}, nil); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.completed.Store(true)
	return nil
}
