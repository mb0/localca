// Copyright 2016 Martin Schnabel. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package localca

import (
	"crypto/tls"
	"net"
	"time"
)

// Listener is a TCP TLS net.Listener that signs certificates for all requested DNS names and IPs.
// TCP keep-alive is set to 3 min, as is the default listener in net/http.
type Listener struct {
	*net.TCPListener
	*tls.Config
	ca *CA
}

// Listen returns a new TCP listener at addr using ca to sign new certificates and optionally additinal config.
// The GetCertificate field of the tls.Config will be set to provide the certificates to clients and generate them for new DNS names.
func Listen(addr string, ca *CA, config *tls.Config) (*Listener, error) {
	_, err := ca.NewCert()
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	if config == nil {
		config = &tls.Config{}
	}
	if config.NextProtos == nil {
		config.NextProtos = []string{"h2", "http/1.1"}
	}
	l := &Listener{Config: config, TCPListener: ln.(*net.TCPListener), ca: ca}
	config.GetCertificate = func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
		return l.ca.CertFor(hi.ServerName)
	}
	return l, nil
}

// Accept accepts new TLS connections and regenerates the server certificate for connections to new local IPs.
func (l *Listener) Accept() (net.Conn, error) {
	c, err := l.AcceptTCP()
	if err != nil {
		return nil, err
	}
	switch addr := c.LocalAddr().(type) {
	case *net.TCPAddr:
		_, err = l.ca.CertFor(addr.IP.String())
		if err != nil {
			return nil, err
		}
	}
	c.SetKeepAlive(true)
	c.SetKeepAlivePeriod(3 * time.Minute)

	return tls.Server(c, l.Config), nil
}
