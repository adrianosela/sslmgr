# Simple Secure Server

[![Go Report Card](https://goreportcard.com/badge/github.com/adrianosela/sslmgr)](https://goreportcard.com/report/github.com/adrianosela/sslmgr)
[![Documentation](https://godoc.org/github.com/adrianosela/sslmgr?status.svg)](https://godoc.org/github.com/adrianosela/sslmgr)
[![GitHub issues](https://img.shields.io/github/issues/adrianosela/sslmgr.svg)](https://github.com/adrianosela/sslmgr/issues)
[![license](https://img.shields.io/github/license/adrianosela/sslmgr.svg)](https://github.com/adrianosela/sslmgr/blob/master/LICENSE)
[![Mentioned in Awesome Go](https://awesome.re/mentioned-badge.svg)](https://github.com/avelino/awesome-go#security)


#### With Default Values:

```
ss, err := sslmgr.NewSecureServer(handler, "yourhostname.com")
if err != nil {
	log.Fatal(err)
}
ss.ListenAndServe()
```

**Note:** This option uses the file system as the certificate cache. If your use case does not have a persistent file system, you should provide a value for CertCache in the [ServerConfig](https://godoc.org/github.com/adrianosela/sslmgr#ServerConfig) as shown below.


#### With Optional Values:

(Using the [certcache](https://godoc.org/github.com/adrianosela/certcache) library to define a cache)

```
ss, err := sslmgr.NewServer(sslmgr.ServerConfig{
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
```
