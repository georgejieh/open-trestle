package main

import (
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/internal/testsupport"
)

func daemonTestGenerationSanitizer() review.GenerationRequestSanitizer {
	return testsupport.NewCleanGenerationSanitizer()
}
