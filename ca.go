// Copyright 2016 Martin Schnabel. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package localca is a simple solution for using https or http2 in your local area network.
package localca

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"sync"
)

// CA represents a self-signed certificate authority.
// It can be used to generate new server certificates.
type CA struct {
	key Key
	pem []byte
	crt *x509.Certificate

	mu   sync.RWMutex
	conf Config
	srv  *tls.Certificate
}

// Read returns a CA from an existing certificate in PEM format.
func Read(conf *Config, key Key, caPEM []byte) (ca *CA, err error) {
	ca = &CA{key: key, pem: caPEM, conf: DefaultConfig}
	if conf != nil {
		ca.conf = *conf
	}
	b, _ := pem.Decode(ca.pem)
	ca.crt, err = x509.ParseCertificate(b.Bytes)
	if err != nil {
		return nil, err
	}
	return ca, nil
}

// New returns a new self-signed certificate authority.
func New(conf *Config, key Key) (ca *CA, err error) {
	ca = &CA{key: key, conf: DefaultConfig}
	if conf != nil {
		ca.conf = *conf
	}
	// fill in the template
	tmpl := &ca.conf.CATmpl
	tmpl.SubjectKeyId = key.SubjectKeyID()
	ca.conf.fillTmpl(tmpl)
	// create a self-signed certificate authority
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl,
		&key.PublicKey, key.PrivateKey)
	if err != nil {
		return nil, err
	}
	ca.crt, err = x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	ca.pem = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return ca, nil
}

// NewCert returns a new server certificate including names.
func (ca *CA) NewCert(names ...string) (*tls.Certificate, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	return ca.newCert(names...)
}

func (ca *CA) newCert(names ...string) (*tls.Certificate, error) {
	// create an elliptic key
	k, err := NewKey()
	if err != nil {
		return nil, err
	}
	// fill in the names
	ca.conf.fillNames(names)
	tmpl := ca.conf.CertTmpl // local shallow copy
	tmpl.AuthorityKeyId = ca.crt.SubjectKeyId
	tmpl.SubjectKeyId = k.SubjectKeyID()
	ca.conf.fillTmpl(&tmpl)
	// create and sign a server certificate with an already established CA
	// (normally one use a certificate signing request, but because both
	// signer and signee are the same party here we do it directly)
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, ca.crt,
		&k.PublicKey, ca.key.PrivateKey)
	if err != nil {
		return nil, err
	}
	pem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	cert, err := tls.X509KeyPair(pem, k.PEM)
	if err != nil {
		return nil, err
	}
	ca.srv = &cert
	ca.srv.Leaf, err = x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

// CertFor returns a server certificate for addr.
// It will auto-generate a new certificate if addr was not already included.
func (ca *CA) CertFor(addr string) (cert *tls.Certificate, err error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if addr == "" || ca.conf.hasName(addr) {
		return ca.srv, nil
	}
	return ca.newCert(addr)
}

// ServeHTTP serves the CA certificate as PEM file to HTTP GET requests.
func (ca *CA) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	io.Copy(w, bytes.NewReader(ca.pem))
}

// PEM returns the pem encoded ca certificate as io.Reader.
func (ca *CA) PEM() io.Reader {
	return bytes.NewReader(ca.pem)
}
