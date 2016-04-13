// Copyright 2016 Martin Schnabel. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package localca

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"time"
)

// DefaultConfig is a minimal default configuration.
// A shallow copy is used as default configuration for the New and Read.
var DefaultConfig = Config{
	CATmpl: x509.Certificate{
		Subject: pkix.Name{
			Organization: []string{"local ca"},
		},
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:           true,
		MaxPathLenZero: true,
	},
	CertTmpl: x509.Certificate{
		Subject: pkix.Name{
			Organization: []string{"local cert"},
		},
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	},
	Valid: 12 * 365 * 24 * time.Hour,
}

// Config holds templates for generating a certificate authority and server certificates.
// The fields SerialNumber, SubjectKeyId and AuthorityKeyId are always regenerated.
// The fields NotBefore and NotAfter are generated if not specified
type Config struct {
	CATmpl   x509.Certificate
	CertTmpl x509.Certificate
	Valid    time.Duration // default duration for NotAfter
}

// fillTmpl checks and sets NotBefore, NotAfter and SerialNumber on t
func (c *Config) fillTmpl(t *x509.Certificate) {
	if t.NotBefore.IsZero() {
		t.NotBefore = time.Now().Add(-time.Hour)
	}
	if t.NotAfter.IsZero() {
		t.NotAfter = t.NotBefore.Add(c.Valid + time.Hour)
	}
	t.SerialNumber, _ = rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

// fillNames adds DNS names and IP addresses to the server template
func (c *Config) fillNames(names []string) {
	FillNames(&c.CertTmpl, names)
}

// FillNames adds DNS names and IP addresses to the certificate template t
func FillNames(t *x509.Certificate, names []string) {
	dns := t.DNSNames
	ips := t.IPAddresses
	for _, str := range names {
		if ip := net.ParseIP(str); ip != nil {
			ips = append(ips, ip)
		} else {
			dns = append(dns, str)
		}
	}
	t.DNSNames = dns
	t.IPAddresses = ips
	if t.Subject.CommonName == "" {
		if len(dns) > 0 {
			t.Subject.CommonName = dns[0]
		} else if len(ips) > 0 {
			t.Subject.CommonName = ips[0].String()
		}
	}
}

// hasName returns whether name is a known DNS name or IP address
func (c *Config) hasName(name string) bool {
	t := &c.CertTmpl
	if name == t.Subject.CommonName {
		return true
	}
	if ip := net.ParseIP(name); ip != nil {
		for _, o := range t.IPAddresses {
			if ip.Equal(o) {
				return true
			}
		}
		return false
	}
	for _, o := range t.DNSNames {
		if name == o {
			return true
		}
	}
	return false
}
