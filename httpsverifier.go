package main

import (
	"bufio"
	"crypto/sha1"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/pushc6/httpsverifier/handlers"
	"github.com/pushc6/httpsverifier/servicetypes"
)

func handler(w http.ResponseWriter, r *http.Request) {
	if r.Body == nil {
		log.Println("NOTHING IN THE BODY")
	}

	decoder := json.NewDecoder(r.Body)
	domainsRequested := &servicetypes.FingerprintRequest{}
	err := decoder.Decode(domainsRequested)
	if err != nil {
		fmt.Fprintf(w, "There was a problem processing your request\n")
		fmt.Fprintf(w, "Please make requests in the following format\n\n")
		test := &servicetypes.FingerprintRequest{Domains: []string{"test.com", "buttfoundry.com"}}
		enc := json.NewEncoder(w)
		enc.Encode(test)
	}

	results := &servicetypes.FingerprintResponse{}
	for _, domain := range domainsRequested.Domains {
		domain = addHTTPS(domain)
		client := &http.Client{}
		log.Println("Request for fingerprint of domain: ", domain)
		req, err := http.NewRequest("GET", domain, nil)
		if err != nil {
			response := &servicetypes.DomainResult{
				Domain:      domain,
				Fingerprint: "",
				Found:       false,
			}
			results.Results = append(results.Results, *response)
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			response := &servicetypes.DomainResult{
				Domain:      domain,
				Fingerprint: "",
				Found:       false,
			}
			results.Results = append(results.Results, *response)
			continue
		}

		domain = removeHTTPS(domain)

		//TODO trim off the http/https/www and make it NAME.TLD

		fingerprint := findFingerprint(resp.TLS.PeerCertificates, domain)
		response := &servicetypes.DomainResult{
			Domain:      domain,
			Fingerprint: fingerprint,
			Found:       fingerprint != "",
		}
		results.Results = append(results.Results, *response)

	}
	if len(domainsRequested.Domains) != 0 {
		jsonEncoder := json.NewEncoder(w)
		jsonEncoder.Encode(results)
	}
}

func main() {
	//CLI Startup
	if len(os.Args) > 1 {
		if os.Args[1] == "1" {
			startupServer()
		} else {
			startupClient()
		}
	} else {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Press 1 for remote erver mode, or 2 for client mode (choose this if you want to see if being MITM'd): ")
		text, _ := reader.ReadString('\n')
		if "1" == strings.TrimSpace(text) {
			startupServer()
		} else {
			startupClient()
			//Load server that just shows status of pre-set URLs and\or files giving ability to add new
			//and allow them to do one-offs without adding
		}
	}
}

func startupServer() {
	http.HandleFunc("/checkCert", handlers.OneOffHandler)
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8080", nil)
}

func startupClient() {
	fmt.Println("Point your browser to http://localhost:8081 to perform a scan")
	fmt.Println("If you want to add/remove pages to be scanned update the lookup.txt file")
	fmt.Println("Press ^C to exit")
	http.HandleFunc("/", handlers.ClientHandler)
	openbrowser("http://localhost:8081")
	http.ListenAndServe(":8081", nil)
}

func loadPage(title string) (*servicetypes.Page, error) {
	filename := title + ".txt"
	body, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return &servicetypes.Page{Title: title, Body: body}, nil
}

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

func openbrowser(url string) {
	var err error

	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		err = fmt.Errorf("unsupported platform")
	}
	if err != nil {
		log.Fatal(err)
	}

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
