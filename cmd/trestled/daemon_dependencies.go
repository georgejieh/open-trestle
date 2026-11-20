package main

import (
	"net/http"
	"reflect"
	"time"

	"github.com/georgejieh/open-trestle/internal/review"
)

type daemonDependencies struct {
	modelHTTPClient         *http.Client
	modelHTTPClientIdentity string
	clock                   interface{ Now() time.Time }
	generationSanitizer     review.GenerationRequestSanitizer
	verificationSanitizer   review.VerificationRequestSanitizer
}

func daemonNilDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	}
	return false
}
