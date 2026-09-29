package main

import (
	"crypto/sha256"
	"database/sql"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

var hostRe = regexp.MustCompile(`^[A-Za-z0-9.-]{1,253}$`)

var apiSecret = os.Getenv("API_SECRET")

func findUser(db *sql.DB, name string) (*sql.Rows, error) {
	return db.Query("SELECT * FROM users WHERE name = $1", name)
}

func fingerprint(data []byte) [32]byte {
	return sha256.Sum256(data)
}

func ping(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if !hostRe.MatchString(host) {
		http.Error(w, "bad host", http.StatusBadRequest)
		return
	}
	out, _ := exec.Command("ping", "-c", "1", host).Output()
	w.Write(out)
}

func download(w http.ResponseWriter, r *http.Request) {
	root := "/srv/files"
	full := filepath.Join(root, filepath.Clean("/"+r.URL.Query().Get("f")))
	if !strings.HasPrefix(full, root+string(os.PathSeparator)) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	data, _ := os.ReadFile(full)
	w.Write(data)
}
