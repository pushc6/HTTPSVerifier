package servicetypes

//Used for response to a fingerprint request
type FingerprintResponse struct {
	Results []DomainResult
}

//FingerprintRequest - Used for fingerprint requests duh
type FingerprintRequest struct {
	Domains []string
}

type DomainResult struct {
	Domain      string
	Fingerprint string
	Found       bool
}

type Page struct {
	Title   string
	Body    []byte
	Domains []string
	Results []FingerprintMerge
}

type FingerprintMerge struct {
	Domain            string
	RemoteFingerprint string
	LocalFingerprint  string
	Intercepted       bool
	ErrorMessage      string
}
