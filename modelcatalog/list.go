package modelcatalog

import "context"

// List validates one source and performs its single bounded metadata GET
// without reading or writing any catalog, proposal or manifest file. It applies
// the same endpoint, credential-reference, size and shape rules as Refresh.
// The result is an availability observation for interactive selection only:
// it does not approve a route, prove local execution or establish privacy.
func List(ctx context.Context, source Source, allowRemote bool, resolver CredentialResolver) ([]Model, error) {
	if ctx == nil || ctx.Err() != nil || validateSource(source, allowRemote) != nil {
		return nil, ErrInvalid
	}
	snapshot, err := fetchWithCredentials(ctx, source, resolver)
	if err != nil {
		return nil, err
	}
	return snapshot.Models, nil
}
