package main

import (
	"bufio"
	"crypto/sha1"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/pushc6/httpsverifier/page"
)

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Checking your certificate fingerprints %s \n\n", r.URL.Path[1:])
	domainRequested := "facebook.com"
	client := &http.Client{}
	req, _ := http.NewRequest("GET", "https://facebook.com", nil)
	resp, _ := client.Do(req)
	found := false

	for _, val := range resp.TLS.PeerCertificates {
		for _, dnsName := range val.DNSNames {

			if strings.ToLower(strings.TrimSpace(dnsName)) == strings.ToLower(domainRequested) {
				fmt.Println("dns name: ", dnsName)
				//return the associated base64 encoded sha1 value
				sha := sha1.Sum(val.Raw)
				encoded := fmt.Sprintf("%x", sha)
				fmt.Println(encoded)
				fmt.Fprintf(w, "hex value for domain %s, is %s", domainRequested, encoded)
				found = true
				break
			}
			if found {
				break
			}
		}
		//fmt.Fprintf(w, "Certificate name %s  is: %x \n\n\n", val.DNSNames, sha1.Sum(val.Raw))
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
