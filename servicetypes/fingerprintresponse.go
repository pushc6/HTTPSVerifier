package servicetypes

//Used for response to a fingerprint request
type FingerprintResponse struct {
	Domain      string
	Fingerprint string
}
