// Local TLS test server for the HTTP client study: GET /json (2 KiB body), /delay?ms=N,
// serves HTTP/1.1 and h2 on 127.0.0.1:8443 (ALPN), and h1 only on :8444 (-h1only).
package main

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	body := []byte(`{"data":"` + strings.Repeat("x", 2000) + `"}`)
	mux := http.NewServeMux()
	mux.HandleFunc("/json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	})
	mux.HandleFunc("/delay", func(w http.ResponseWriter, r *http.Request) {
		ms, _ := strconv.Atoi(r.URL.Query().Get("ms"))
		time.Sleep(time.Duration(ms) * time.Millisecond)
		w.Write(body)
	})
	go func() {
		s := &http.Server{Addr: "127.0.0.1:8444", Handler: mux,
			TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){}}
		panic(s.ListenAndServeTLS("certs/leaf.pem", "certs/key.pem"))
	}()
	go func() {
		pool := x509.NewCertPool()
		ca, _ := os.ReadFile("certs/cert.pem")
		pool.AppendCertsFromPEM(ca)
		cfg := &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
		s := &http.Server{Addr: "127.0.0.1:8445", Handler: mux, TLSConfig: cfg}
		panic(s.ListenAndServeTLS("certs/leaf.pem", "certs/key.pem"))
	}()
	s := &http.Server{Addr: "127.0.0.1:8443", Handler: mux}
	panic(s.ListenAndServeTLS("certs/leaf.pem", "certs/key.pem"))
}
