package evidence

// ValidateRepositoryAcquisitionRequest rejects non-canonical request state.
func ValidateRepositoryAcquisitionRequest(request RepositoryAcquisitionRequest) error {
	_, err := canonicalRepositoryAcquisitionRequest(request)
	return err
}
