package evidence

// NewRecordedRepositoryFile validates metadata read from a recorded source index.
// It neither proves possession of file content nor authorizes model dispatch.
func NewRecordedRepositoryFile(path, digest string, sizeBytes int) (RepositoryFile, error) {
	identity, err := repositoryFileIdentity(path, digest, sizeBytes)
	if err != nil {
		return RepositoryFile{}, err
	}
	return canonicalRepositoryFile(RepositoryFile{identity: identity, path: path, digest: digest, sizeBytes: sizeBytes})
}
