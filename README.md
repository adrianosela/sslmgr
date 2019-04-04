# Simple Secure Server

[![Go Report Card](https://goreportcard.com/badge/github.com/adrianosela/sslmgr)](https://goreportcard.com/report/github.com/adrianosela/sslmgr)
[![Documentation](https://godoc.org/github.com/adrianosela/sslmgr?status.svg)](https://godoc.org/github.com/adrianosela/sslmgr)
[![GitHub issues](https://img.shields.io/github/issues/adrianosela/sslmgr.svg)](https://github.com/adrianosela/sslmgr/issues)
[![license](https://img.shields.io/github/license/adrianosela/sslmgr.svg)](https://github.com/adrianosela/certcache/blob/master/LICENSE)


#### With Default Values:

```
ss := sslmgr.NewSecureServer(sslmgr.ServerConfig{
		Hostnames: []string{"yourhostname.com"},
		Handler:   h,
})

ss.ListenAndServe()
```

**Note:** This option uses the file system as the certificate cache. If your use case does not have a persistent file system, you should provide a value for CertCache in the [ServerConfig](https://godoc.org/github.com/adrianosela/sslmgr#ServerConfig) as shown below.


#### With Optional Values:

(Using the [certcache](https://godoc.org/github.com/adrianosela/certcache) library to define a cache)

```
ss := sslmgr.NewSecureServer(sslmgr.ServerConfig{
		Hostnames: []string{"yourhostname.com"},
		Handler:   h,
		HTTPPort:  ":80",
		HTTPSPort: ":443",
		ReadTimeout: 10 * time.Second(),
		WriteTimeout: 10 * time.Second(),
		IdleTimeout: 25 * time.Second(),
		ServeSSLFunc: func() bool {
			return strings.ToLower(os.Getenv("PROD")) == "true"
		},
		CertCache: certcache.NewFirestore(os.Getenv("FIREBASE_CREDS_PATH"), os.Getenv("FIREBASE_PROJ_ID")),
})

ss.ListenAndServe()
```