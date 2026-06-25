// Fixture 14: handler. Reviewer should flag CWE-78.
package main

import (
	"net/http"
	"os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("host")
	out, err := exec.Command("sh", "-c", "ping -c 1 "+target).Output()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Write(out)
}

func main() {
	http.HandleFunc("/ping", handler)
	http.ListenAndServe(":8080", nil)
}
