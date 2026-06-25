// Fixture 22: fetch(). Reviewer should flag CWE-400 / CWE-770.
package main

import (
	"io"
	"net/http"
)

func fetch(target string) ([]byte, error) {
	resp, err := http.Get(target)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}
