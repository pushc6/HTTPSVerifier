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
		DomainRequested: []string{"facebook.com"},
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

	if fingerResponse.Domain == "" || fingerResponse.Fingerprint == "" {
		t.Error("Either domain or fingerprint failed")
	}

}
