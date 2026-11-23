package main

import (
	"html/template"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Safe look-alikes for more_sinks.go: nothing here may be flagged.

func search(w http.ResponseWriter, r *http.Request) {
	out, _ := exec.Command("grep", "--", r.FormValue("q"), "/var/log/app.log").Output()
	w.Write(out)
	exec.Command("sh", "-c", "echo done").Run()
}

func redirect(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("next")
	if !strings.HasPrefix(target, "/") || strings.HasPrefix(target, "//") {
		target = "/"
	}
	http.Redirect(w, r, target, http.StatusFound)
	http.Redirect(w, r, "/home", http.StatusFound)
}

func profile(w http.ResponseWriter, r *http.Request) {
	t := template.Must(template.New("p").Parse(`<div>{{.}}</div>`))
	t.Execute(w, r.FormValue("bio"))
	t.Execute(w, template.HTML("<b>static</b>"))
}

func fetch(w http.ResponseWriter, r *http.Request) {
	root := "/srv/files"
	full := filepath.Join(root, filepath.Clean("/"+r.FormValue("name")))
	if !strings.HasPrefix(full, root+string(os.PathSeparator)) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	data, _ := os.ReadFile(full)
	w.Write(data)
}

func logo() (*os.File, error) {
	return os.Open("/srv/static/logo.png")
}
