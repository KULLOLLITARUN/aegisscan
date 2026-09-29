package main

import (
	"crypto/md5"
	"crypto/tls"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
)

const apiSecret = "sk_live_51HxK9aB3cD4eF5gH6iJ7kL8mN9oP0qR"

func findUser(db *sql.DB, name string) (*sql.Rows, error) {
	return db.Query(fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name))
}

func hashPassword(pw string) [16]byte {
	return md5.Sum([]byte(pw))
}

func ping(w http.ResponseWriter, r *http.Request) {
	out, _ := exec.Command("sh", "-c", "ping -c 1 "+r.URL.Query().Get("host")).Output()
	w.Write(out)
}

func client() *http.Client {
	return &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
}

func download(w http.ResponseWriter, r *http.Request) {
	data, _ := os.ReadFile(filepath.Join("/srv/files", r.URL.Query().Get("f")))
	w.Write(data)
}

func main() {
	http.HandleFunc("/ping", ping)
	http.HandleFunc("/download", download)
	http.ListenAndServe(":8080", nil)
}
