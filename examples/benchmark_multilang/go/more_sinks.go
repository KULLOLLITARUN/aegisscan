package main

import (
	"html/template"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
)

// INTENTIONALLY VULNERABLE benchmark fixture. Do not deploy.

func search(w http.ResponseWriter, r *http.Request) {
	out, _ := exec.Command("bash", "-c", "grep "+r.FormValue("q")+" /var/log/app.log").Output()
	w.Write(out)
}

func redirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, r.URL.Query().Get("next"), http.StatusFound)
}

func profile(w http.ResponseWriter, r *http.Request) {
	t := template.Must(template.New("p").Parse(`<div>{{.}}</div>`))
	t.Execute(w, template.HTML(r.FormValue("bio")))
}

func fetch(w http.ResponseWriter, r *http.Request) {
	data, _ := os.ReadFile(filepath.Join("/srv/files", r.FormValue("name")))
	w.Write(data)
}

func upload(w http.ResponseWriter, r *http.Request) {
	f, _ := os.Open("/srv/uploads/" + r.URL.Query().Get("f"))
	defer f.Close()
}
