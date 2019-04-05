package sslmgr

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

// SecureServer is a server which abstracts away acme/autocert's
// certificate manager
type SecureServer struct {
	server                     *http.Server
	certMgr                    *autocert.Manager
	serveSSLFunc               func() bool
	httpsPort                  string
	httpPort                   string
	readTimeout                time.Duration
	writeTimeout               time.Duration
	idleTimeout                time.Duration
	gracefulnessTimeout        time.Duration
	gracefulShutdownErrHandler func(error)
}

// ServerConfig is the configuration type for a SecureServer
type ServerConfig struct {
	// Required Fields
	Hostnames []string
	Handler   http.Handler
	// Optional Fields
	ServeSSLFunc               func() bool
	CertCache                  autocert.Cache
	HTTPSPort                  string
	HTTPPort                   string
	ReadTimeout                time.Duration
	WriteTimeout               time.Duration
	IdleTimeout                time.Duration
	GracefulnessTimeout        time.Duration
	GracefulShutdownErrHandler func(error)
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
	// check required fields
	if len(c.Hostnames) < 1 {
		return nil, ErrNoHostname
	}
	if c.Handler == nil {
		return nil, ErrNoHandler
	}
	// cache implementation cant be empty
	if c.CertCache == nil {
		c.CertCache = autocert.DirCache(".")
	}
	// port definitions cant be empty
	if c.HTTPSPort == "" || !strings.HasPrefix(c.HTTPSPort, ":") {
		c.HTTPSPort = ":443"
	}
	if c.HTTPPort == "" || !strings.HasPrefix(c.HTTPPort, ":") {
		c.HTTPPort = ":80"
	}
	// sensible timeouts
	if c.ReadTimeout == time.Duration(0) {
		c.ReadTimeout = 5 * time.Second
	}
	if c.WriteTimeout == time.Duration(0) {
		c.WriteTimeout = 5 * time.Second
	}
	if c.IdleTimeout == time.Duration(0) {
		c.IdleTimeout = 25 * time.Second
	}
	if c.GracefulnessTimeout == time.Duration(0) {
		c.GracefulnessTimeout = 5 * time.Second
	}
	// serve SSL by default
	if c.ServeSSLFunc == nil {
		c.ServeSSLFunc = func() bool {
			return true
		}
	}
	// simply log failure error if gradeful shutdown fails
	if c.GracefulShutdownErrHandler == nil {
		c.GracefulShutdownErrHandler = func(e error) { /* NOP */ }
	}
	// populate new SecureServer
	return &SecureServer{
		server: &http.Server{
			ReadTimeout:  c.ReadTimeout,
			WriteTimeout: c.WriteTimeout,
			IdleTimeout:  c.IdleTimeout,
			Handler:      c.Handler,
		},
		certMgr: &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(c.Hostnames...),
			Cache:      c.CertCache,
		},
		serveSSLFunc: c.ServeSSLFunc,
		httpPort:     c.HTTPPort,
		httpsPort:    c.HTTPSPort,
	}, nil
}

// ListenAndServe starts the secure server
func (ss *SecureServer) ListenAndServe() {
	willStopGracefully(ss.server, ss.gracefulnessTimeout, ss.gracefulShutdownErrHandler)

	if ss.serveSSLFunc() {
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
		// some time for OS scheduler to start SSL thread
		time.Sleep(time.Millisecond * 50)
	}

	ss.server.Addr = ss.httpPort
	log.Printf("[sslmgr] serving http at %s", ss.httpPort)
	if err := ss.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("[sslmgr] ListenAndServe() failed with %s", err)
	}
}

func willStopGracefully(srv *http.Server, timeout time.Duration, errHandler func(error)) {
	gracefulStop := make(chan os.Signal)
	signal.Notify(gracefulStop, syscall.SIGTERM)
	signal.Notify(gracefulStop, syscall.SIGINT)

	go func() {
		<-gracefulStop
		log.Print("[sslmgr] shutdown signal received, draining existent connections...")
		ctx, cncl := context.WithTimeout(context.Background(), timeout)
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("[sslmgr] server could not be shutdown gracefully: %s", err)
			errHandler(err)
		}
		cncl()
		log.Print("[sslmgr] server was closed successfully with no service interruptions")
	}()
}
