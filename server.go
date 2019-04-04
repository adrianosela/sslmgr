package sslmgr

import (
	"crypto/tls"
	"errors"
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
	readTimeout  time.Duration
	writeTimeout time.Duration
	idleTimeout  time.Duration
}

// ServerConfig is the configuration type for a SecureServer
type ServerConfig struct {
	// Mandatory Fields
	Hostnames []string
	Handler   http.Handler
	// Optional Fields
	ServeSSLFunc func() bool
	CertCache    autocert.Cache
	HTTPSPort    string
	HTTPPort     string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
}

var (
	// ErrNoHostname is returned whenever a user calls NewSecureServer
	// without any hostnames in the config
	ErrNoHostname = errors.New("no hostnames provided")
	// ErrNoHandler is returned whenever a user calls NewSecureServer
	// with a nil http.Handler in the config
	ErrNoHandler = errors.New("server handler cannot be nil")
)

// NewSecureServer initializes a new secure server
func NewSecureServer(c ServerConfig) (*SecureServer, error) {
	if len(c.Hostnames) < 1 {
		return nil, ErrNoHostname
	}
	if c.Handler == nil {
		return nil, ErrNoHandler
	}
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
	httpPort := c.HTTPPort
	if httpPort == "" || !strings.HasPrefix(httpPort, ":") {
		httpPort = ":80"
	}
	readTimeout := c.ReadTimeout
	if readTimeout == time.Duration(0) {
		readTimeout = 5 * time.Second
	}
	writeTimeout := c.WriteTimeout
	if writeTimeout == time.Duration(0) {
		writeTimeout = 5 * time.Second
	}
	idleTimeout := c.IdleTimeout
	if idleTimeout == time.Duration(0) {
		idleTimeout = 5 * 25
	}

	return &SecureServer{
		server: &http.Server{
			ReadTimeout:  readTimeout,
			WriteTimeout: writeTimeout,
			IdleTimeout:  idleTimeout,
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
	}, nil
}

// ListenAndServe starts the secure server
func (ss *SecureServer) ListenAndServe() {
	// serve HTTPS by default i.e. serveSSLFunc not provided
	if ss.serveSSLFunc == nil || ss.serveSSLFunc() {
		ss.server.Addr = ss.httpsPort
		ss.server.TLSConfig = &tls.Config{GetCertificate: ss.certMgr.GetCertificate}
		go func() {
			log.Printf("[sslmgr] serving https at %s", ss.httpsPort)
			err := ss.server.ListenAndServeTLS("", "")
			if err != nil {
				log.Fatalf("[sslmgr] ListendAndServeTLS() failed with %s", err)
			}
		}()
		// allow autocert handler Let's Encrypt auth callbacks over HTTP
		ss.server.Handler = ss.certMgr.HTTPHandler(ss.server.Handler)
		// some time for OS scheduler to start SSL thread
		time.Sleep(time.Millisecond * 50)
	}
	ss.server.Addr = ss.httpPort
	log.Printf("[sslmgr] serving http at %s", ss.httpPort)
	err := ss.server.ListenAndServe()
	if err != nil {
		log.Fatalf("[sslmgr] ListenAndServe() failed with %s", err)
	}
}
