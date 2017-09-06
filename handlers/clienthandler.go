package handlers

import (
	"bufio"
	"bytes"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/pushc6/httpsverifier/servicetypes"
)

func ClientHandler(w http.ResponseWriter, r *http.Request) {
	p := &servicetypes.Page{
		Title: "Welcome!",
	}

	//Get domains to lookup
	reader, err := os.Open("lookup.txt")
	if err != nil {
		log.Fatal("Couldn't open lookup.txt")
	}
	defer reader.Close()

	fileScanner := bufio.NewScanner(reader)

	for fileScanner.Scan() {
		text := fileScanner.Text()
		p.Domains = append(p.Domains, text)
	}

	request := &servicetypes.FingerprintRequest{
		Domains: p.Domains,
	}

	client := &http.Client{}

	theReq, _ := json.Marshal(request)

	req, err := http.NewRequest("GET", "http://104.197.145.153:8080", bytes.NewBuffer(theReq))

	if err != nil {
		panic("we broke making request")
	}

	resp, err := client.Do(req)
	if err != nil {
		if err != nil {
			panic("we broke making request")
		}
	}
	response := &servicetypes.FingerprintResponse{}
	decoder := json.NewDecoder(resp.Body)
	decoder.Decode(response)

	m := make(map[string]string)

	for _, fResp := range response.Results {
		m[removeHTTPS(fResp.Domain)] = fResp.Fingerprint
	}

	l := make(map[string]string)
	errors := make(map[string]string)
	//Get client site fingerprints
	for _, domain := range request.Domains {
		domain = addHTTPS(domain)
		req2, err := http.NewRequest("GET", domain, nil)
		if err != nil {
			log.Fatal("unable to parse site: ", domain)
		}
		resp2, err := client.Do(req2)
		if err != nil {
			errors[removeHTTPS(domain)] = err.Error()
			continue
		}
		finga := findFingerprint(resp2.TLS.PeerCertificates, domain)
		l[removeHTTPS(domain)] = finga
	}

	//Merge the lists and add the fingerprints
	for key, val := range m {
		merge := &servicetypes.FingerprintMerge{
			Domain:            key,
			LocalFingerprint:  l[key],
			RemoteFingerprint: val,
			Intercepted:       l[key] != val,
			ErrorMessage:      errors[key],
		}
		p.Results = append(p.Results, *merge)
	}

	//Do this last, makes the page
	t, _ := template.ParseFiles("index.html")
	t.Execute(w, p)

}

//Duplicate code, must get rid of

func addHTTPS(url string) string {
	if !strings.Contains(strings.ToLower(url), "https://") && !strings.Contains(strings.ToLower(url), "https:\\") {
		url = "https://" + url
	}
	return url
}

func removeHTTPS(url string) string {
	if strings.Contains(strings.ToLower(url), "https://") || strings.Contains(strings.ToLower(url), "https:\\") {
		url = url[8:len(url)]
	}
	if strings.Contains(strings.ToLower(url), "www.") {
		url = url[4:len(url)]
	}
	return url
}
