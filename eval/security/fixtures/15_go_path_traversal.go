// Fixture 15: download(). Reviewer should flag CWE-22.
package main

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
)

const uploadDir = "/var/uploads"

func download(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	p := filepath.Join(uploadDir, name)
	f, err := os.Open(p)
	if err != nil {
		http.Error(w, err.Error(), 404)
		return
	}
	defer f.Close()
	io.Copy(w, f)
}

func main() {
	http.HandleFunc("/download", download)
	http.ListenAndServe(":8080", nil)
}
