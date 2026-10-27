package sshgateway

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestNormalizeAuthorizedKey(t *testing.T) {
	_, ed, err := GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	weakRSA, err := ssh.NewPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		in      string
		wantErr string
	}{
		{name: "plain ed25519 key", in: ed},
		{name: "key with comment is canonicalised", in: ed + " alice@laptop"},
		{name: "forced command option", in: `command="id" ` + ed, wantErr: "options"},
		{name: "from option", in: `from="10.0.0.0/8" ` + ed, wantErr: "options"},
		{name: "embedded newline", in: ed + "\n" + ed, wantErr: "single line"},
		{name: "not a key", in: "ssh-ed25519 AAAA", wantErr: "parse key"},
		{name: "empty", in: "", wantErr: "parse key"},
		{name: "rsa below minimum", in: AuthorizedKeyLine(weakRSA), wantErr: "at least"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeAuthorizedKey(tt.in)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("NormalizeAuthorizedKey() error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeAuthorizedKey() error = %v", err)
			}
			if strings.Contains(got, " alice") || strings.Contains(got, "\n") {
				t.Fatalf("NormalizeAuthorizedKey() = %q, want canonical form without comment", got)
			}
		})
	}
}

func TestNormalizeAuthorizedKeyRejectsCertificates(t *testing.T) {
	_, ed, err := GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(ed))
	if err != nil {
		t.Fatal(err)
	}
	signerPriv := mustSigner(t)
	cert := &ssh.Certificate{Key: pub, CertType: ssh.UserCert, ValidBefore: ssh.CertTimeInfinity}
	if err := cert.SignCert(rand.Reader, signerPriv); err != nil {
		t.Fatal(err)
	}
	line := string(ssh.MarshalAuthorizedKey(cert))
	if _, err := NormalizeAuthorizedKey(strings.TrimSpace(line)); err == nil ||
		!strings.Contains(err.Error(), "certificates") {
		t.Fatalf("NormalizeAuthorizedKey(cert) error = %v, want certificates rejected", err)
	}
}

func mustSigner(t *testing.T) ssh.Signer {
	t.Helper()
	pemBytes, _, err := GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestGenerateEd25519RoundTrip(t *testing.T) {
	privPEM, line, err := GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := PublicKeyOf(privPEM)
	if err != nil {
		t.Fatal(err)
	}
	if got := AuthorizedKeyLine(pub); got != line {
		t.Fatalf("PublicKeyOf() = %q, want the generated public key %q", got, line)
	}
	if !strings.HasPrefix(line, "ssh-ed25519 ") {
		t.Fatalf("public key = %q, want an ssh-ed25519 line", line)
	}
}

func TestKnownHostsData(t *testing.T) {
	_, line, err := GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		addr     string
		wantHost string
	}{
		{addr: testBackend, wantHost: "sb-ssh.forge-a.svc"},
		{addr: "sb-ssh.forge-a.svc:2222", wantHost: "[sb-ssh.forge-a.svc]:2222"},
	}
	for _, tt := range tests {
		raw, err := base64.StdEncoding.DecodeString(KnownHostsData(tt.addr, pub))
		if err != nil {
			t.Fatal(err)
		}
		want := tt.wantHost + " " + line + "\n"
		if string(raw) != want {
			t.Fatalf("KnownHostsData(%s) = %q, want %q", tt.addr, raw, want)
		}
	}
}
