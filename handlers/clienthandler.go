package handlers

import (
	"bufio"
	"bytes"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"os"

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

	req, err := http.NewRequest("GET", "http://localhost:8080/", bytes.NewBuffer(theReq))

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
	p.Results = *response
	t, _ := template.ParseFiles("index.html")
	t.Execute(w, p)

}
