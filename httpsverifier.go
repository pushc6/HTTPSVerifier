package main

import (
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"

	"github.com/pushc6/httpsverifier/page"
)

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hi there, I love %s!", r.URL.Path[1:])
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
	http.HandleFunc("/", handler)
	http.HandleFunc("/verify", verifyHandler)
	http.ListenAndServe(":8080", nil)
}

func loadPage(title string) (*page.Page, error) {
	filename := title + ".txt"
	body, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return &page.Page{Title: title, Body: body}, nil
}
