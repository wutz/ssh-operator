package sshgateway

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"sigs.k8s.io/yaml"
)

func hostKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	_, line, err := GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func clientKey(t *testing.T) string {
	t.Helper()
	_, line, err := GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	return line
}

func route(ns, name string, created time.Time, rules ...Rule) Route {
	return Route{Namespace: ns, Name: name, Created: created, Rules: rules}
}

// testBackend is the SSH address of the backend the specs route to, and
// testBackendUser the account they forward as on it. testPrivateKey is the
// file the gateway logs in with.
const (
	testBackend     = "app.project-a.svc:22"
	testBackendUser = "agent"
	testPrivateKey  = "/etc/sshgateway/identity/ssh-privatekey"
)

func TestBuildConfigForRule(t *testing.T) {
	key := clientKey(t)
	host := hostKey(t)
	rule := Rule{
		Usernames:      []string{"alice", "alice-ro"},
		AuthorizedKeys: []string{key + " alice@laptop"},
		Backend:        testBackend,
		BackendUser:    testBackendUser,
		HostKey:        host,
	}
	plan := Build(testPrivateKey, []Route{route("project-a", "sb", time.Unix(1, 0), rule)})

	if len(plan.Problems) != 0 {
		t.Fatalf("Problems = %v, want none", plan.Problems)
	}
	if plan.Config.Version != ConfigVersion {
		t.Errorf("version = %q, want %q", plan.Config.Version, ConfigVersion)
	}
	if len(plan.Config.Pipes) != 1 {
		t.Fatalf("got %d pipes, want 1", len(plan.Config.Pipes))
	}
	p := plan.Config.Pipes[0]

	if len(p.From) != 2 {
		t.Fatalf("got %d from entries, want one per username", len(p.From))
	}
	for _, f := range p.From {
		if f.AuthorizedKeysData != base64.StdEncoding.EncodeToString([]byte(key+"\n")) {
			t.Errorf("from %s authorized_keys_data = %q, want the base64 of the canonical key", f.Username, f.AuthorizedKeysData)
		}
	}

	if p.To.Host != testBackend || p.To.Username != testBackendUser {
		t.Errorf("to = %+v, want host and backend user", p.To)
	}
	khLine, err := base64.StdEncoding.DecodeString(p.To.KnownHostsData)
	if err != nil || !strings.HasPrefix(string(khLine), "app.project-a.svc ssh-ed25519 ") {
		t.Errorf("known_hosts_data = %q (%v), want a base64 known_hosts line for the backend", p.To.KnownHostsData, err)
	}
	if p.To.PrivateKey != testPrivateKey {
		t.Errorf("private_key = %q, want %q", p.To.PrivateKey, testPrivateKey)
	}
}

func TestMarshalIsSSHPiperYAML(t *testing.T) {
	rule := Rule{
		Usernames:      []string{"alice"},
		AuthorizedKeys: []string{clientKey(t)},
		Backend:        testBackend,
		BackendUser:    testBackendUser,
		HostKey:        hostKey(t),
	}
	plan := Build(testPrivateKey, []Route{route("project-a", "sb", time.Unix(1, 0), rule)})

	out, err := plan.Config.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	wants := []string{`version: "1.0"`, "pipes:", "from:", "username: alice", "to:", "private_key: " + testPrivateKey}
	for _, want := range wants {
		if !strings.Contains(text, want) {
			t.Errorf("config lacks %q:\n%s", want, text)
		}
	}

	var back Config
	if err := yaml.Unmarshal(out, &back); err != nil {
		t.Fatalf("config does not read back: %v", err)
	}
	if len(back.Pipes) != 1 || back.Pipes[0].To.Host != testBackend {
		t.Errorf("read back %+v, want the planned pipe", back)
	}
}

func TestBuildEmptyConfigHasNoPipes(t *testing.T) {
	out, err := Build(testPrivateKey, nil).Config.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "pipes: []") {
		t.Fatalf("config = %s, want an empty pipes list", out)
	}
}

func TestBuildOneRouteRejectsAllOnProblem(t *testing.T) {
	good := Rule{
		Usernames:      []string{"a"},
		AuthorizedKeys: []string{clientKey(t)},
		Backend:        "x.ns.svc:22",
		BackendUser:    testBackendUser,
		HostKey:        hostKey(t),
	}
	badKey := Rule{
		Usernames:      []string{"b"},
		AuthorizedKeys: []string{`command="id" ` + clientKey(t)},
		Backend:        "y.ns.svc:22",
		BackendUser:    testBackendUser,
		HostKey:        hostKey(t),
	}
	plan := Build(testPrivateKey, []Route{route("ns", "r", time.Unix(1, 0), good, badKey)})

	if len(plan.Config.Pipes) != 0 {
		t.Fatalf("got %d pipes, want none: a route is served all or nothing", len(plan.Config.Pipes))
	}
	p, ok := plan.Problems["ns/r"]
	if !ok || p.Reason != ReasonInvalidAuthorizedKeys {
		t.Fatalf("Problems[ns/r] = %+v, want %s", p, ReasonInvalidAuthorizedKeys)
	}
}

func TestBuildBackendProblems(t *testing.T) {
	key := clientKey(t)
	tests := []struct {
		name   string
		rule   Rule
		reason string
	}{
		{
			name:   "no backend",
			rule:   Rule{Usernames: []string{"a"}, AuthorizedKeys: []string{key}, HostKey: hostKey(t)},
			reason: ReasonBackendNotFound,
		},
		{
			name: "no host key",
			rule: Rule{
				Usernames:      []string{"a"},
				AuthorizedKeys: []string{key},
				Backend:        "x.ns.svc:22",
				BackendUser:    testBackendUser,
			},
			reason: ReasonHostKeyNotFound,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan := Build(testPrivateKey, []Route{route("ns", "r", time.Unix(1, 0), tt.rule)})
			if got := plan.Problems["ns/r"].Reason; got != tt.reason {
				t.Fatalf("reason = %q, want %q", got, tt.reason)
			}
		})
	}
}

func TestBuildUsernameFirstCreatedWins(t *testing.T) {
	older := route("ns-a", "old", time.Unix(10, 0), Rule{
		Usernames:      []string{"shared"},
		AuthorizedKeys: []string{clientKey(t)},
		Backend:        "a.ns.svc:22",
		BackendUser:    testBackendUser,
		HostKey:        hostKey(t),
	})
	newer := route("ns-b", "new", time.Unix(20, 0), Rule{
		Usernames:      []string{"shared"},
		AuthorizedKeys: []string{clientKey(t)},
		Backend:        "b.ns.svc:22",
		BackendUser:    testBackendUser,
		HostKey:        hostKey(t),
	})
	// The list order must not matter: the older route keeps the username.
	plan := Build(testPrivateKey, []Route{newer, older})

	if len(plan.Config.Pipes) != 1 || plan.Config.Pipes[0].To.Host != "a.ns.svc:22" {
		t.Fatalf("pipes = %+v, want only the older route's pipe", plan.Config.Pipes)
	}
	if got := plan.Problems["ns-b/new"].Reason; got != ReasonUsernameConflict {
		t.Fatalf("newer route reason = %q, want %s", got, ReasonUsernameConflict)
	}
}
