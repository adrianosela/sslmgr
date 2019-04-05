package main

import (
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/adrianosela/certcache"
	"github.com/adrianosela/sslmgr"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/acme/autocert"
)

func main() {
	h := mux.NewRouter()
	h.Methods(http.MethodGet).Path("/healthcheck").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Im alive!"))
	})

	ss, err := sslmgr.NewSecureServer(sslmgr.ServerConfig{
		Hostnames: []string{os.Getenv("CN_FOR_CERTIFICATE")},
		HTTPPort:  ":80",
		HTTPSPort: ":443",
		Handler:   h,
		ServeSSLFunc: func() bool {
			return strings.ToLower(os.Getenv("PROD")) == "true"
		},
		CertCache: certcache.NewLayered(
			certcache.NewLogger(),
			autocert.DirCache("."),
		),
		ReadTimeout:         5 * time.Second,
		WriteTimeout:        5 * time.Second,
		IdleTimeout:         25 * time.Second,
		GracefulnessTimeout: 5 * time.Second,
		GracefulShutdownErrHandler: func(e error) {
			log.Fatal(e)
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	ss.ListenAndServe()
}
