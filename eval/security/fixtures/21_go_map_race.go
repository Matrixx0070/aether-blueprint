// Fixture 21: Counter.Inc / Counter.Get. Reviewer should flag CWE-362 / CWE-366.
package main

import (
	"fmt"
	"net/http"
)

type Counter struct {
	hits map[string]int
}

func NewCounter() *Counter {
	return &Counter{hits: make(map[string]int)}
}

func (c *Counter) Inc(key string) {
	c.hits[key]++
}

func (c *Counter) Get(key string) int {
	return c.hits[key]
}

var counter = NewCounter()

func handler(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("k")
	go counter.Inc(key)
	fmt.Fprintf(w, "%d", counter.Get(key))
}

func main() {
	http.HandleFunc("/hit", handler)
	http.ListenAndServe(":8080", nil)
}
