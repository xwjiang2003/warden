package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8002", "listen")
	flag.Parse()

	var reqs, conns int64
	body := make([]byte, 2048)
	for i := range body {
		body[i] = 'x'
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/__count", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%d %d\n", atomic.LoadInt64(&reqs), atomic.LoadInt64(&conns))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&reqs, 1)
		w.Header().Set("Content-Type", "text/plain")
		w.Write(body)
	})

	srv := &http.Server{
		Addr:    *addr,
		Handler: mux,
		ConnState: func(c net.Conn, s http.ConnState) {
			if s == http.StateNew {
				atomic.AddInt64(&conns, 1)
			}
		},
		ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second,
	}
	log.Printf("backend on %s", *addr)
	log.Fatal(srv.ListenAndServe())
}
