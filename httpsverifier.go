package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/pushc6/httpsverifier/page"
	"github.com/pushc6/httpsverifier/servicetypes"
)

func handler(w http.ResponseWriter, r *http.Request) {
	//fmt.Fprintf(w, "Checking your certificate fingerprints %s \n\n", r.URL.Path[1:])
	domainRequested := "facebook.com"
	client := &http.Client{}
	req, _ := http.NewRequest("GET", "https://facebook.com", nil)
	resp, _ := client.Do(req)
	found := false

	//TODO strip off stuff like http and www and do a wildcard search for TLD
	if r.Body == nil {
		fmt.Println("NOTHING IN THE BODY")
	}
	decoder := json.NewDecoder(r.Body)
	domainsRequested := &servicetypes.FingerprintRequest{}
	err := decoder.Decode(domainsRequested)
	if err != nil {
		fmt.Fprintf(w, "There was a problem processing your request")
	}
	for _, val := range resp.TLS.PeerCertificates {
		for _, dnsName := range val.DNSNames {

			if strings.ToLower(strings.TrimSpace(dnsName)) == strings.ToLower(domainRequested) {
				fmt.Println("dns name: ", dnsName)
				//return the associated hex encoded sha1 value
				sha := sha1.Sum(val.Raw)
				encoded := fmt.Sprintf("%x", sha)
				fmt.Println(encoded)
				response := &servicetypes.FingerprintResponse{
					Domain:      domainRequested,
					Fingerprint: encoded,
				}
				jsonEncoder := json.NewEncoder(w)
				jsonEncoder.Encode(response)
				found = true
				break
			}
			if found {
				break
			}
		}
	}
}

func verifyHandler(w http.ResponseWriter, r *http.Request) {
	title := r.URL.Path[len("/edit/"):]
	p, err := loadPage(title)
	if err != nil {
		p = &page.Page{Title: title}
	}
	t, _ := template.ParseFiles("request.html")
	t.Execute(w, p)
}

func main() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Press 1 for server mode, or 2 for client mode: ")
	text, _ := reader.ReadString('\n')
	if "1" == strings.TrimSpace(text) {
		http.HandleFunc("/", handler)
		http.HandleFunc("/verify", verifyHandler)
		http.ListenAndServe(":8080", nil)
	} else {
		//Load server that just shows status of pre-set URLs and\or files giving ability to add new
		//and allow them to do one-offs without adding
	}
}

func loadPage(title string) (*page.Page, error) {
	filename := title + ".txt"
	body, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return &page.Page{Title: title, Body: body}, nil
}
