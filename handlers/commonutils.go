package handlers

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/pushc6/httpsverifier/servicetypes"
)

func writeResponse(w http.ResponseWriter, output interface{}) {
	encoder := json.NewEncoder(w)
	encoder.Encode(output)
}

func BuildResponse(domain string, fingerprint string, found bool) *servicetypes.FingerprintResponse {

	dr := &servicetypes.DomainResult{
		Domain:      domain,
		Fingerprint: fingerprint,
		Found:       found,
	}
	fr := &servicetypes.FingerprintResponse{
		Results: []servicetypes.DomainResult{*dr},
	}
	return fr

}
func findFingerprint(certs []*x509.Certificate, domain string) string {
	domain = removeHTTPS(domain)
	for _, val := range certs {
		for _, dnsName := range val.DNSNames {
			if strings.Contains(strings.ToLower(strings.TrimSpace(dnsName)), strings.ToLower(domain)) {
				//return the associated hex encoded sha1 value
				sha := sha1.Sum(val.Raw)
				encoded := fmt.Sprintf("%x", sha)
				return encoded
			}
		}
	}
	return ""
}
