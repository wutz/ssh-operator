// Package sshgateway holds the parts of the SSH gateway that do not touch the
// cluster: key handling, the sshd configuration of sandboxes, and the sshpiper
// Pipes that route connections to them.
package sshgateway

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// MinRSABits is the smallest RSA key accepted in an authorized key.
const MinRSABits = 2048

// GenerateEd25519 returns a new ed25519 key: the private key in OpenSSH PEM
// form and the public key as an authorized_keys line.
func GenerateEd25519() (privatePEM []byte, authorizedKey string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("generate ed25519 key: %w", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return nil, "", fmt.Errorf("marshal private key: %w", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, "", fmt.Errorf("encode public key: %w", err)
	}
	return pem.EncodeToMemory(block), AuthorizedKeyLine(sshPub), nil
}

// PublicKeyOf returns the public key of an OpenSSH PEM private key.
func PublicKeyOf(privatePEM []byte) (ssh.PublicKey, error) {
	signer, err := ssh.ParsePrivateKey(privatePEM)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	return signer.PublicKey(), nil
}

// AuthorizedKeyLine formats a public key as one authorized_keys line without
// options and without the trailing newline.
func AuthorizedKeyLine(key ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}

// NormalizeAuthorizedKey checks one public key of a route and returns it in
// canonical form. Keys with options (from=, command=, ...) and certificates are
// rejected: a route grants a plain login and nothing more. DSA keys and RSA keys
// shorter than MinRSABits are rejected as well.
func NormalizeAuthorizedKey(line string) (string, error) {
	if strings.ContainsAny(line, "\r\n") {
		return "", errors.New("a key must be a single line")
	}
	key, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return "", fmt.Errorf("parse key: %w", err)
	}
	if len(options) > 0 {
		return "", errors.New("key options are not allowed")
	}
	if len(bytes.TrimSpace(rest)) > 0 {
		return "", errors.New("unexpected data after the key")
	}
	if _, ok := key.(*ssh.Certificate); ok {
		return "", errors.New("certificates are not allowed")
	}
	if key.Type() == "ssh-dss" {
		return "", errors.New("DSA keys are not allowed")
	}
	if ck, ok := key.(ssh.CryptoPublicKey); ok {
		if rk, ok := ck.CryptoPublicKey().(*rsa.PublicKey); ok && rk.N.BitLen() < MinRSABits {
			return "", fmt.Errorf("RSA keys must have at least %d bits", MinRSABits)
		}
	}
	return AuthorizedKeyLine(key), nil
}

// KnownHostsLine returns the known_hosts entry that pins key for the sshd at
// addr (host:port), in the form the SSH client checks it against.
func KnownHostsLine(addr string, key ssh.PublicKey) string {
	return knownhosts.Normalize(addr) + " " + AuthorizedKeyLine(key)
}

// KnownHostsData is KnownHostsLine base64-encoded, the form sshpiper's
// known_hosts_data takes.
func KnownHostsData(addr string, key ssh.PublicKey) string {
	return base64.StdEncoding.EncodeToString([]byte(KnownHostsLine(addr, key) + "\n"))
}
