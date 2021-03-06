package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pushc6/httpsverifier/servicetypes"
)

func TestHandler(t *testing.T) {
	theReq := &servicetypes.FingerprintRequest{
		Domains: []string{"https://facebook.com", "linkedin.com", "ddfsvsdvsv.com", "reddit.com"},
	}
	jReq, _ := json.Marshal(&theReq)
	fmt.Println(jReq)
	req, err := http.NewRequest("GET", "localhost:8080/blah", bytes.NewBuffer(jReq))
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	handlerTest := http.HandlerFunc(handler)

	handlerTest.ServeHTTP(rr, req)

	decoder := json.NewDecoder(rr.Body)
	fingerResponse := &servicetypes.FingerprintResponse{}
	decoder.Decode(fingerResponse)

	for _, result := range fingerResponse.Results {
		fmt.Println("Result for ", result.Domain, " is ", result.Fingerprint)
	}

	if len(fingerResponse.Results) == 0 || len(fingerResponse.Results) == 0 {
		t.Error("Either domain or fingerprint failed")
	}

}
