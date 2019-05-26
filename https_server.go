package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"strings"

	"fortio.org/fortio/log"
	"golang.org/x/crypto/acme/autocert"
)

var (
	hostnameFlag = flag.String("hostname", "", "Internet DNS name under which this server is reachable (eg myapp.mydomain.tld)")
	certDirFlag  = flag.String("certdir", "./certdir/", "Directory to save/cache certs")
)

func main() {
	log.SetLogLevel(log.Debug)
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
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, TLS user! Your config: %+v", r.TLS)
	})
	httpsSrv := http.Server{Handler: mux}
	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: hostPolicy,
		Cache:      autocert.DirCache(*certDirFlag),
	}
	httpsSrv.Addr = ":443"
	httpsSrv.TLSConfig = &tls.Config{GetCertificate: m.GetCertificate}

	go func() {
		err := httpsSrv.ListenAndServeTLS("", "")
		if err != nil {
			log.Fatalf("httpsSrv.ListendAndServeTLS() failed with %s", err)
		}
	}()

}