package sslmgr

import (
	"errors"
	"net/http"
	"syscall"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
)

func TestSecureServer(t *testing.T) {
	Convey("Test NewSecureServer()", t, func() {
		Convey("Test Required Field - Hostnames nil", func() {
			ss, err := NewSecureServer(ServerConfig{
				Handler: http.NotFoundHandler(),
			})
			So(ss, ShouldBeNil)
			So(err, ShouldEqual, ErrNoHostname)
		})
		Convey("Test Required Field - Hostnames empty", func() {
			ss, err := NewSecureServer(ServerConfig{
				Handler:   http.NotFoundHandler(),
				Hostnames: []string{},
			})
			So(ss, ShouldBeNil)
			So(err, ShouldEqual, ErrNoHostname)
		})
		Convey("Test Required Field - Handler", func() {
			ss, err := NewSecureServer(ServerConfig{
				Hostnames: []string{"yourdomain.io"},
			})
			So(ss, ShouldBeNil)
			So(err, ShouldEqual, ErrNoHandler)
		})
		Convey("Test Required Fields Suffice", func() {
			ss, err := NewSecureServer(ServerConfig{
				Handler:   http.NotFoundHandler(),
				Hostnames: []string{"yourdomain.io"},
			})
			So(ss, ShouldNotBeNil)
			So(err, ShouldBeNil)
		})
		Convey("Test Default Values Are Applied", func() {
			ss, err := NewSecureServer(ServerConfig{
				Handler:   http.NotFoundHandler(),
				Hostnames: []string{"yourdomain.io"},
			})
			So(err, ShouldBeNil)
			So(ss, ShouldNotBeNil)
			So(ss.certMgr, ShouldNotBeNil)
			So(ss.serveSSLFunc, ShouldNotBeNil)
			So(ss.serveSSLFunc(), ShouldEqual, true)
			So(ss.httpPort, ShouldEqual, ":80")
			So(ss.httpsPort, ShouldEqual, ":443")
			So(ss.server.ReadTimeout, ShouldEqual, 5*time.Second)
			So(ss.server.IdleTimeout, ShouldEqual, 25*time.Second)
			So(ss.server.WriteTimeout, ShouldEqual, 5*time.Second)
			So(ss.gracefulnessTimeout, ShouldEqual, 5*time.Second)
			So(ss.gracefulShutdownErrHandler, ShouldNotBeNil)
			So(func() {
				ss.gracefulShutdownErrHandler(errors.New("Hello World"))
			}, ShouldNotPanic)
		})
		Convey("Test Port Address Correction", func() {
			ss, err := NewSecureServer(ServerConfig{
				Handler:   http.NotFoundHandler(),
				Hostnames: []string{"yourdomain.io"},
				HTTPPort:  "80",
				HTTPSPort: "443",
			})
			So(err, ShouldBeNil)
			So(ss, ShouldNotBeNil)
			So(ss.httpPort, ShouldEqual, ":80")
			So(ss.httpsPort, ShouldEqual, ":443")
		})
		Convey("Test HTTP Port Address Failure", func() {
			ss, err := NewSecureServer(ServerConfig{
				Handler:   http.NotFoundHandler(),
				Hostnames: []string{"yourdomain.io"},
				HTTPPort:  "not an int",
			})
			So(ss, ShouldBeNil)
			So(err, ShouldEqual, ErrNotAnInteger)
		})
		Convey("Test HTTPS Port Address Failure", func() {
			ss, err := NewSecureServer(ServerConfig{
				Handler:   http.NotFoundHandler(),
				Hostnames: []string{"yourdomain.io"},
				HTTPSPort: "not an int",
			})
			So(ss, ShouldBeNil)
			So(err, ShouldEqual, ErrNotAnInteger)
		})
	})
	Convey("Test startGracefulStopHandler()", t, func() {
		Convey("Test startGracefulStopHandler Does Not Panic", func() {
			ss, err := NewSecureServer(ServerConfig{
				Handler:   http.NotFoundHandler(),
				Hostnames: []string{"yourdomain.io"},
			})
			So(ss, ShouldNotBeNil)
			So(err, ShouldBeNil)
			So(func() {
				ss.startGracefulStopHandler(5*time.Second, func(e error) { /* NOP */ })
				syscall.Signal(syscall.SIGINT).Signal()
			}, ShouldNotPanic)
		})
	})
	Convey("Test serveHTTPS()", t, func() {
		Convey("Test serveHTTPS Does Not Panic", func() {
			ss, err := NewSecureServer(ServerConfig{
				Handler:   http.NotFoundHandler(),
				Hostnames: []string{"yourdomain.io"},
			})
			So(ss, ShouldNotBeNil)
			So(err, ShouldBeNil)
			So(func() {
				ss.testing = true
				ss.serveHTTPS()
				syscall.Signal(syscall.SIGINT).Signal()
			}, ShouldNotPanic)
			So(ss.server.Addr, ShouldEqual, ":443")
		})
	})
}
