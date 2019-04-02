package sslmgr

import (
	"crypto/tls"
	"log"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

// SecureServer is a server which abstracts away acme/autocert's
// certificate manager
type SecureServer struct {
	server       *http.Server
	certMgr      *autocert.Manager
	serveSSLFunc func() bool
	httpsPort    string
	httpPort     string
}

// ServerConfig is the configuration type for a SecureServer
type ServerConfig struct {
	HTTPSPort    string
	HTTPPort     string
	Hostnames    []string
	Handler      http.Handler
	ServeSSLFunc func() bool
	CertCache    autocert.Cache
}

// NewSecureServer initializes a new secure server
func NewSecureServer(c ServerConfig) *SecureServer {
	// cache implementation cant be empty
	cache := c.CertCache
	if cache == nil {
		cache = autocert.DirCache(".")
	}
	// port definitions cant be empty
	httpsPort := c.HTTPSPort
	if httpsPort == "" || !strings.HasPrefix(httpsPort, ":") {
		httpsPort = ":443"
	}
	httpPort := c.HTTPSPort
	if httpPort == "" || !strings.HasPrefix(httpPort, ":") {
		httpPort = ":80"
	}
	// object definition
	return &SecureServer{
		server: &http.Server{
			ReadTimeout:  25 * time.Second,
			WriteTimeout: 25 * time.Second,
			IdleTimeout:  120 * time.Second,
			Handler:      c.Handler,
		},
		certMgr: &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(c.Hostnames...),
			Cache:      cache,
		},
		serveSSLFunc: c.ServeSSLFunc,
		httpPort:     httpPort,
		httpsPort:    httpsPort,
	}
}

// ListenAndServe starts the secure server
func (ss *SecureServer) ListenAndServe() {
	if ss.serveSSLFunc != nil && ss.serveSSLFunc() {
		ss.server.Addr = ss.httpsPort
		ss.server.TLSConfig = &tls.Config{GetCertificate: ss.certMgr.GetCertificate}
		go func() {
			err := ss.server.ListenAndServeTLS("", "")
			if err != nil {
				log.Fatalf("ListendAndServeTLS() failed with %s", err)
			}
		}()
		// allow autocert handler Let's Encrypt auth callbacks over HTTP
		ss.server.Handler = ss.certMgr.HTTPHandler(ss.server.Handler)
		// some time for OS scheduler to start SSL thread
		time.Sleep(time.Millisecond * 50)
	}
	ss.server.Addr = ss.httpPort
	err := ss.server.ListenAndServe()
	if err != nil {
		log.Fatalf("ListenAndServe() failed with %s", err)
	}
}
