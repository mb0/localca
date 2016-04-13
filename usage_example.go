// Copyright 2016 Martin Schnabel. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build ignore

package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/mb0/localca"
)

var caPEM = `-----BEGIN CERTIFICATE-----
MIIBizCCATCgAwIBAgIQBPZLnXSQ1TCc4eZ+kH1vPjAKBggqhkjOPQQDAjATMREw
DwYDVQQKEwhsb2NhbCBjYTAeFw0xNTExMTUyMDIxNTdaFw0yNzExMTIyMDIxNTda
MBMxETAPBgNVBAoTCGxvY2FsIGNhMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
7ZA3G/MUVlnfYsb8ivlOEM7Le0pszB4WnUwJsTfZPI0WP2o4NUXE3LG6nAFBpx87
3Jk0HBSCkCnkElK20CcM+6NmMGQwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQI
MAYBAf8CAQAwHQYDVR0OBBYEFHfz2ea8P0WuncKwCg9XKdH5DvXuMB8GA1UdIwQY
MBaAFHfz2ea8P0WuncKwCg9XKdH5DvXuMAoGCCqGSM49BAMCA0kAMEYCIQCXZblL
vRDiXHTCsEjf8GQzy7zGG7LOs6QVWZIATej3awIhANce/r74STRVvm4BFRyVle4v
AnlNhK3vJZBJNAI3rWkK
-----END CERTIFICATE-----`

var keyPEM = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIFD4OqTfG5FXSKwQPL9wKA3zPIwBYt7LC4H9JAE/5yAtoAoGCCqGSM49
AwEHoUQDQgAE7ZA3G/MUVlnfYsb8ivlOEM7Le0pszB4WnUwJsTfZPI0WP2o4NUXE
3LG6nAFBpx873Jk0HBSCkCnkElK20CcM+w==
-----END EC PRIVATE KEY-----`

func main() {
	// read pem encoded key and ca certificate
	key, err := localca.ReadKey(keyPEM)
	if err != nil {
		log.Fatal(err)
	}
	ca, err := localca.Read(nil, key, caPEM)
	if err != nil {
		log.Fatal(err)
	}

	// start a http server on port 8080 that serves the ca certificate
	go http.ListenAndServe(":8080", ca)

	// listen and sign new certificates on demand
	ln, err := localca.Listen(":4443", ca, nil)
	if err != nil {
		log.Fatal(err)
	}

	// ready to serve
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello local http2 client")
	})
	srv := &http.Server{Addr: ":4443"}
	err = srv.Serve(ln)
	if err != nil {
		log.Fatal(err)
	}
}
