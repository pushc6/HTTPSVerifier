package handlers

import (
	"net/http"
)

func OneOffHandler(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		resp := buildResponse(domain, "", false)
		writeResponse(w, resp)
	} else {
		fingerprint := testDomain(domain)
		resp := buildResponse(domain, fingerprint, fingerprint != "")
		writeResponse(w, resp)
	}
}

func testDomain(domain string) string {
	domain = addHTTPS(domain)
	client := &http.Client{}

	req, err := http.NewRequest("GET", domain, nil)
	if err != nil {
		return ""
	}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}

	fingerprint := findFingerprint(resp.TLS.PeerCertificates, domain)
	return fingerprint
}
