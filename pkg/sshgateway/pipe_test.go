package sshgateway

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/wutz/sshgateway/internal/naming"
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

// testBackend is the SSH address of the backend the specs route to.
const testBackend = "sb-ssh.project-a.svc:22"

func TestBuildPipeForRule(t *testing.T) {
	key := clientKey(t)
	host := hostKey(t)
	rule := Rule{
		Usernames:      []string{"alice", "alice-ro"},
		AuthorizedKeys: []string{key + " alice@laptop"},
		Backend:        testBackend,
		HostKey:        host,
	}
	plan := Build("sshgateway-system", "main", []Route{route("project-a", "sb", time.Unix(1, 0), rule)})

	if len(plan.Problems) != 0 {
		t.Fatalf("Problems = %v, want none", plan.Problems)
	}
	if len(plan.Pipes) != 1 {
		t.Fatalf("got %d pipes, want 1", len(plan.Pipes))
	}
	p := plan.Pipes[0]
	if p.GetName() != "project-a.sb.0" || p.GetNamespace() != "sshgateway-system" {
		t.Fatalf("pipe = %s/%s, want sshgateway-system/project-a.sb.0", p.GetNamespace(), p.GetName())
	}
	if p.GetLabels()[naming.LabelSSHGateway] != "main" {
		t.Errorf("gateway label = %q, want main", p.GetLabels()[naming.LabelSSHGateway])
	}
	if p.GetAnnotations()[naming.AnnotationSSHRoute] != "project-a/sb" {
		t.Errorf("route annotation = %q", p.GetAnnotations()[naming.AnnotationSSHRoute])
	}

	froms, _, _ := unstructured.NestedSlice(p.Object, "spec", "from")
	if len(froms) != 2 {
		t.Fatalf("got %d from entries, want one per username", len(froms))
	}
	for _, f := range froms {
		m := f.(map[string]any)
		if m["authorized_keys_data"] != key {
			t.Errorf("from %v authorized_keys_data = %q, want the canonical key", m["username"], m["authorized_keys_data"])
		}
		if _, ok := m["htpasswd_data"]; ok {
			t.Errorf("from %v must not carry password data", m["username"])
		}
	}

	to, _, _ := unstructured.NestedMap(p.Object, "spec", "to")
	if to["host"] != testBackend || to["username"] != SandboxUser {
		t.Errorf("to = %v, want host and sandbox user", to)
	}
	khData, _ := to["known_hosts_data"].(string)
	khLine, err := base64.StdEncoding.DecodeString(khData)
	if err != nil || !strings.HasPrefix(string(khLine), "sb-ssh.project-a.svc ssh-ed25519 ") {
		t.Errorf("known_hosts_data = %q (%v), want a base64 known_hosts line for the backend", khData, err)
	}
	secret, _, _ := unstructured.NestedString(to, "private_key_secret", "name")
	if secret != naming.SSHIdentitySecretName {
		t.Errorf("private_key_secret = %q, want %q", secret, naming.SSHIdentitySecretName)
	}
	if p.GetAnnotations()["sshpiper.com/no_ca_publickey"] != "true" {
		t.Errorf("pipe must disable CA public key lookup")
	}
}

func TestBuildOneRouteRejectsAllOnProblem(t *testing.T) {
	good := Rule{
		Usernames:      []string{"a"},
		AuthorizedKeys: []string{clientKey(t)},
		Backend:        "x.ns.svc:22",
		HostKey:        hostKey(t),
	}
	badKey := Rule{
		Usernames:      []string{"b"},
		AuthorizedKeys: []string{`command="id" ` + clientKey(t)},
		Backend:        "y.ns.svc:22",
		HostKey:        hostKey(t),
	}
	plan := Build("gw", "main", []Route{route("ns", "r", time.Unix(1, 0), good, badKey)})

	if len(plan.Pipes) != 0 {
		t.Fatalf("got %d pipes, want none: a route is served all or nothing", len(plan.Pipes))
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
			name:   "no host key",
			rule:   Rule{Usernames: []string{"a"}, AuthorizedKeys: []string{key}, Backend: "x.ns.svc:22"},
			reason: ReasonHostKeyNotFound,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan := Build("gw", "main", []Route{route("ns", "r", time.Unix(1, 0), tt.rule)})
			if got := plan.Problems["ns/r"].Reason; got != tt.reason {
				t.Fatalf("reason = %q, want %q", got, tt.reason)
			}
		})
	}
}

func TestBuildUsernameFirstCreatedWins(t *testing.T) {
	older := route("ns-a", "old", time.Unix(10, 0), Rule{
		Usernames: []string{"shared"}, AuthorizedKeys: []string{clientKey(t)}, Backend: "a.ns.svc:22", HostKey: hostKey(t),
	})
	newer := route("ns-b", "new", time.Unix(20, 0), Rule{
		Usernames: []string{"shared"}, AuthorizedKeys: []string{clientKey(t)}, Backend: "b.ns.svc:22", HostKey: hostKey(t),
	})
	// The list order must not matter: the older route keeps the username.
	plan := Build("gw", "main", []Route{newer, older})

	if len(plan.Pipes) != 1 || plan.Pipes[0].GetAnnotations()[naming.AnnotationSSHRoute] != "ns-a/old" {
		t.Fatalf("pipes = %v, want only the older route's pipe", plan.Pipes)
	}
	if got := plan.Problems["ns-b/new"].Reason; got != ReasonUsernameConflict {
		t.Fatalf("newer route reason = %q, want %s", got, ReasonUsernameConflict)
	}
}

func TestPipeNameHashesLongNames(t *testing.T) {
	long := strings.Repeat("r", 250)
	name := PipeName("project-namespace-with-long-name", long, 0)
	if len(name) > 253 {
		t.Fatalf("PipeName() has %d characters, want at most 253", len(name))
	}
	if !strings.HasPrefix(name, "ssh-") {
		t.Fatalf("PipeName() = %q, want the hashed form", name)
	}
	if PipeName("ns", "short", 1) != "ns.short.1" {
		t.Fatalf("short names keep their readable form")
	}
}
