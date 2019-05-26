package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"strings"
	"time"

	"fortio.org/fortio/fhttp"

	"fortio.org/fortio/log"
	"golang.org/x/crypto/acme/autocert"
)

var (
	hostnameFlag = flag.String("hostname", "", "Internet DNS name under which this server is reachable (eg myapp.mydomain.tld)")
	certDirFlag  = flag.String("certdir", "./certdir/", "Directory to save/cache certs")
)

// SimpleProxy sends incoming (https) request to localhost:8080 instead (after termination).
func SimpleProxy(w http.ResponseWriter, r *http.Request) {
	fhttp.LogRequest(r, "Fetch")
	hj, ok := w.(http.Hijacker)
	if !ok {
		log.Critf("hijacking not supported")
		return
	}
	conn, _, err := hj.Hijack()
	if err != nil {
		log.Errf("hijacking error %v", err)
		return
	}
	// Don't forget to close the connection:
	defer conn.Close() // nolint: errcheck
	url := r.URL.String()
	log.LogVf("url to %v", url)
	opts := fhttp.NewHTTPOptions("http://localhost:8080/" + url)
	opts.HTTPReqTimeOut = 5 * time.Minute
	fhttp.OnBehalfOf(opts, r)
	client := fhttp.NewClient(opts)
	if client == nil {
		return // error logged already
	}
	_, data, _ := client.Fetch()
	_, err = conn.Write(data)
	if err != nil {
		log.Errf("Error writing fetched data to %v: %v", r.RemoteAddr, err)
	}
	client.Close()
}

func main() {
	flag.Parse()
	hostname := *hostnameFlag
	if len(hostname) == 0 || strings.IndexRune(hostname, '.') < 0 {
		log.Fatalf("-hostname must be provided and not empty/invalid.")
	}
	log.Infof("Using hostname = %s", hostname)
	hostPolicy := func(ctx context.Context, host string) error {
		log.LogVf("Calling host policy cb for %s - ctx %v", host, ctx)
		if host == hostname {
			return nil
		}
		return fmt.Errorf("acme/autocert: only %s host is allowed", hostname)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/tls", fhttp.LogAndCall("tls_info", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, TLS user! Your config: %+v", r.TLS)
	}))
	mux.HandleFunc("/", SimpleProxy)

	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: hostPolicy,
		Cache:      autocert.DirCache(*certDirFlag),
	}

	s := &http.Server{
		Addr:      ":https",
		TLSConfig: m.TLSConfig(),
		Handler:   mux,
	}
	err := s.ListenAndServeTLS("", "")

	if err != nil {
		log.Fatalf("ListenAndServeTLS() failed with %v", err)
	}

}
