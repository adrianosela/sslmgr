package sslmgr

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

// SecureServer is a server which abstracts away acme/autocert's
// certificate manager and server configuration
type SecureServer struct {
	server                     *http.Server
	certMgr                    *autocert.Manager
	serveSSLFunc               func() bool
	httpsPort                  string
	httpPort                   string
	gracefulnessTimeout        time.Duration
	gracefulShutdownErrHandler func(error)
	testing                    bool
}

// ServerConfig holds configuration to initialize a SecureServer.
// Requied Fields: Hostnames and Handler
// Note that it is strongly recommended not to use the default CertCache
type ServerConfig struct {
	// Hostnames for which the server is allowed to serve HTTPS.
	// If the server receives an https request through a DNS name or IP
	// not contained in this list, the request will be denied
	// (REQUIRED)
	Hostnames []string

	// The server's http handler
	// (REQUIRED)
	Handler http.Handler

	// ServeSSLFunc is called to determine whether to serve HTTPS
	// or not. This function's enables users to purpusely disable
	// HTTPS i.e. for local development.
	// Default behavior is to serve HTTPS
	ServeSSLFunc func() bool

	// An implementation of the autocert.Cache interface, which autocert
	// will use to store and manage certificates. It is strongly recommended
	// to provide this field.
	// Default behavior is to store at "." in the file system
	CertCache autocert.Cache

	// Default value is ":443"
	HTTPSPort string

	// Default value is ":80"
	HTTPPort string

	// Default value is 5 seconds
	ReadTimeout time.Duration

	// Default value is 5 seconds
	WriteTimeout time.Duration

	// Default value is 25 seconds
	IdleTimeout time.Duration

	// Default value is 5 seconds
	GracefulnessTimeout time.Duration

	// GracefulShutdownErrHandler is called to handle the event of an error during
	// a graceful shutdown (accept no more connections, and wait for existing
	// ones to finish within the GracefulnessTimeout)
	// Default value is a NOP
	GracefulShutdownErrHandler func(error)
}

var (
	// ErrNoHostname is returned whenever a user calls NewSecureServer
	// without any hostnames in the config
	ErrNoHostname = errors.New("no hostnames provided")

	// ErrNoHandler is returned whenever a user calls NewSecureServer
	// with a nil http.Handler in the config
	ErrNoHandler = errors.New("server handler cannot be nil")

	// ErrNotAnInteger is returned whenever a user calls NewSecureServer with
	// port definitions which do not correspont to integers. i.e. "not a number"
	ErrNotAnInteger = errors.New("port number must be a numerical string")
)

// NewSecureServer returns a SecureServer with default configuration
func NewSecureServer(h http.Handler, hostnames ...string) (*SecureServer, error) {
	return NewServer(ServerConfig{
		Handler:   h,
		Hostnames: hostnames,
	})
}

// NewServer returns a SecureServer with the given config applied
func NewServer(c ServerConfig) (*SecureServer, error) {
	// check required fields
	if c.Hostnames == nil || len(c.Hostnames) < 1 {
		return nil, ErrNoHostname
	}
	if c.Handler == nil {
		return nil, ErrNoHandler
	}
	// cache implementation cant be empty
	if c.CertCache == nil {
		c.CertCache = autocert.DirCache(".")
	}
	// serve SSL by default
	if c.ServeSSLFunc == nil {
		c.ServeSSLFunc = func() bool {
			return true
		}
	}
	// NOP if graceful shutdown fails
	if c.GracefulShutdownErrHandler == nil {
		c.GracefulShutdownErrHandler = func(e error) { /* NOP */ }
	}
	ss := &SecureServer{
		server: &http.Server{Handler: c.Handler},
		certMgr: &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(c.Hostnames...),
			Cache:      c.CertCache,
		},
		serveSSLFunc:               c.ServeSSLFunc,
		gracefulShutdownErrHandler: c.GracefulShutdownErrHandler,
	}
	if err := ss.setPorts(c.HTTPPort, c.HTTPSPort); err != nil {
		return nil, err
	}
	ss.setTimeouts(c.ReadTimeout, c.WriteTimeout, c.IdleTimeout, c.GracefulnessTimeout)
	return ss, nil
}

// setPorts sets the http and https ports on the server
// Note: port definitions cannot be empty nor non numerical strings
func (ss *SecureServer) setPorts(httpPort, httpsPort string) error {
	if httpsPort == "" {
		httpsPort = ":443"
	}
	if _, err := strconv.Atoi(strings.TrimPrefix(httpsPort, ":")); err != nil {
		return ErrNotAnInteger
	}
	if !strings.HasPrefix(httpsPort, ":") {
		httpsPort = fmt.Sprintf(":%s", httpsPort)
	}
	if httpPort == "" {
		httpPort = ":80"
	}
	if _, err := strconv.Atoi(strings.TrimPrefix(httpPort, ":")); err != nil {
		return ErrNotAnInteger
	}
	if !strings.HasPrefix(httpPort, ":") {
		httpPort = fmt.Sprintf(":%s", httpPort)
	}
	ss.httpPort = httpPort
	ss.httpsPort = httpsPort
	return nil
}

// setTimeouts sets server operation and shutdown timeouts
func (ss *SecureServer) setTimeouts(read, write, idle, gracefulness time.Duration) {
	if read == time.Duration(0) {
		read = 5 * time.Second
	}
	if write == time.Duration(0) {
		write = 5 * time.Second
	}
	if idle == time.Duration(0) {
		idle = 25 * time.Second
	}
	if gracefulness == time.Duration(0) {
		gracefulness = 5 * time.Second
	}
	ss.server.ReadTimeout = read
	ss.server.WriteTimeout = write
	ss.server.IdleTimeout = idle
	ss.gracefulnessTimeout = gracefulness
}

// ListenAndServe starts the secure server
func (ss *SecureServer) ListenAndServe() {
	ss.startGracefulStopHandler(ss.gracefulnessTimeout, ss.gracefulShutdownErrHandler)

	if ss.serveSSLFunc() {
		ss.serveHTTPS()
	}

	ss.server.Addr = ss.httpPort
	log.Printf("[sslmgr] serving http at %s", ss.httpPort)
	if err := ss.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("[sslmgr] ListenAndServe() failed with %s", err)
	}
}

func (ss *SecureServer) serveHTTPS() {
	ss.server.Addr = ss.httpsPort
	ss.server.TLSConfig = &tls.Config{GetCertificate: ss.certMgr.GetCertificate}
	go func() {
		log.Printf("[sslmgr] serving https at %s", ss.httpsPort)
		if err := ss.server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[sslmgr] ListendAndServeTLS() failed with %s", err)
		}
	}()
	// allow autocert handler Let's Encrypt auth callbacks over HTTP
	ss.server.Handler = ss.certMgr.HTTPHandler(ss.server.Handler)
	// some time for OS scheduler to start SSL thread (before changing http.Server port)
	time.Sleep(time.Millisecond * 50)
}

func (ss *SecureServer) startGracefulStopHandler(timeout time.Duration, errHandler func(error)) {
	gracefulStop := make(chan os.Signal)
	signal.Notify(gracefulStop, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		<-gracefulStop
		log.Print("[sslmgr] shutdown signal received, draining existing connections...")
		ctx, cncl := context.WithTimeout(context.Background(), timeout)
		defer cncl()
		if err := ss.server.Shutdown(ctx); err != nil {
			log.Printf("[sslmgr] server could not be shutdown gracefully: %s", err)
			errHandler(err)
		}
		log.Print("[sslmgr] server was closed successfully with no service interruptions")
	}()
}
