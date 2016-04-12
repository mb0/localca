// Copyright 2016 Martin Schnabel. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package localca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
)

// Key represents the same ECDSA both PEM encoded and as structure.
type Key struct {
	PEM []byte
	*ecdsa.PrivateKey
}

// NewKey returns a new ECDSA 256bit key.
func NewKey() (Key, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Key{}, err
	}
	// marshal the key in DER format
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return Key{}, err
	}
	// encode the key to pem
	return Key{pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), k}, nil
}

// ReadKey reads a PEM encoded ECDSA key.
func ReadKey(keyPEM []byte) (Key, error) {
	b, _ := pem.Decode(keyPEM)
	key, err := x509.ParseECPrivateKey(b.Bytes)
	if err != nil {
		return Key{keyPEM, nil}, err
	}
	return Key{keyPEM, key}, nil
}

// SubjectKeyID creates new subject key id used for certificates.
func (k Key) SubjectKeyID() []byte {
	id := sha1.Sum(elliptic.Marshal(k.Curve, k.X, k.Y))
	return id[:]
}
