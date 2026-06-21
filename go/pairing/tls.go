package pairing

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"time"
)

// Identity is an agent's self-signed TLS certificate and its pinning fingerprint.
type Identity struct {
	CertPEM []byte // PEM-encoded certificate
	KeyPEM  []byte // PEM-encoded EC private key
	CertDER []byte // raw DER of the leaf certificate
	FP      string // lowercase-hex SHA-256 of CertDER (PROTOCOL.md §3.3)
}

// Fingerprint computes the pinning fingerprint of a DER certificate:
// lowercasehex(SHA-256(DER)) (PROTOCOL.md §3.3).
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// NewIdentity generates a fresh self-signed ECDSA P-256 certificate (PROTOCOL.md §5.1).
// validity controls the certificate lifetime; pass a long duration since pinning,
// not expiry, is the trust anchor.
func NewIdentity(commonName string, validity time.Duration) (*Identity, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return &Identity{
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		CertDER: der,
		FP:      Fingerprint(der),
	}, nil
}

// TLSCertificate returns the identity as a tls.Certificate for serving.
func (id *Identity) TLSCertificate() (tls.Certificate, error) {
	return tls.X509KeyPair(id.CertPEM, id.KeyPEM)
}
