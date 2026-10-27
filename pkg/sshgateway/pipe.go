package sshgateway

import (
	"cmp"
	"crypto/sha256"
	"fmt"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/wutz/ssh-operator/internal/naming"
)

// PipeGVK is the sshpiper Pipe kind, served by the sshpiper kubernetes plugin.
var PipeGVK = schema.GroupVersionKind{Group: "sshpiper.com", Version: "v1beta1", Kind: "Pipe"}

// SandboxUser is the login every routed connection is forwarded as. The client
// username selects the route; inside the sandbox it is always this account.
const SandboxUser = "sandbox"

// Reasons of a route that cannot be served. They are the reasons of the
// Accepted and ResolvedRefs conditions of the route.
const (
	ReasonBackendNotFound       = "BackendNotFound"
	ReasonHostKeyNotFound       = "HostKeyNotFound"
	ReasonInvalidAuthorizedKeys = "InvalidAuthorizedKeys"
	ReasonUsernameConflict      = "UsernameConflict"
)

// Route is an SSHRoute as the gateway plans it. Backends are resolved by the
// caller, so this package never reads the cluster.
type Route struct {
	Namespace string
	Name      string
	// Created orders routes: the route created first keeps a contested username.
	Created time.Time
	Rules   []Rule
}

// Rule is one SSHRouteRule with its backend resolved.
type Rule struct {
	Usernames      []string
	AuthorizedKeys []string
	// Backend is the host:port of the sshd the rule forwards to.
	Backend string
	// HostKey is the host key of that sshd; nil when the backend has none.
	HostKey ssh.PublicKey
}

// Problem explains why a route cannot be served.
type Problem struct {
	Reason  string
	Message string
}

// Plan is the desired state of one gateway: its Pipes and the problems of the
// routes left out of them, keyed by "namespace/name".
type Plan struct {
	Pipes    []*unstructured.Unstructured
	Problems map[string]Problem
}

// Build plans the Pipes of a gateway in namespace from its routes. A route is
// served only if all its rules are: any problem rejects the whole route.
func Build(namespace, gateway string, routes []Route) Plan {
	plan := Plan{Problems: map[string]Problem{}}
	ordered := slices.Clone(routes)
	slices.SortStableFunc(ordered, func(a, b Route) int {
		return cmp.Or(a.Created.Compare(b.Created), strings.Compare(key(a), key(b)))
	})

	claimed := map[string]bool{}
	for _, route := range ordered {
		if p, ok := check(route, claimed); ok {
			plan.Problems[key(route)] = p
			continue
		}
		for _, rule := range route.Rules {
			for _, u := range rule.Usernames {
				claimed[u] = true
			}
		}
		for i, rule := range route.Rules {
			plan.Pipes = append(plan.Pipes, pipe(namespace, gateway, route, i, rule))
		}
	}
	return plan
}

// check returns the problem of a route, if any, given the usernames already
// claimed by older routes. claimed is not modified.
func check(route Route, claimed map[string]bool) (Problem, bool) {
	seen := map[string]bool{}
	for _, rule := range route.Rules {
		if rule.Backend == "" {
			return Problem{ReasonBackendNotFound, "the backend Service does not exist"}, true
		}
		if rule.HostKey == nil {
			return Problem{ReasonHostKeyNotFound, "the backend has no SSH host key"}, true
		}
		for _, k := range rule.AuthorizedKeys {
			if _, err := NormalizeAuthorizedKey(k); err != nil {
				return Problem{ReasonInvalidAuthorizedKeys, fmt.Sprintf("authorized key: %v", err)}, true
			}
		}
		for _, u := range rule.Usernames {
			if claimed[u] || seen[u] {
				return Problem{ReasonUsernameConflict, fmt.Sprintf("username %q is used by another route", u)}, true
			}
			seen[u] = true
		}
	}
	return Problem{}, false
}

func key(route Route) string { return route.Namespace + "/" + route.Name }

// PipeName is the name of the Pipe of a rule of a route. Names that would
// exceed the length limit of object names are hashed.
func PipeName(namespace, route string, rule int) string {
	name := fmt.Sprintf("%s.%s.%d", namespace, route, rule)
	if len(name) <= 253 {
		return name
	}
	sum := sha256.Sum256([]byte(name))
	return fmt.Sprintf("ssh-%x", sum[:16])
}

func pipe(namespace, gateway string, route Route, index int, rule Rule) *unstructured.Unstructured {
	froms := make([]any, 0, len(rule.Usernames))
	keys := make([]string, 0, len(rule.AuthorizedKeys))
	for _, k := range rule.AuthorizedKeys {
		// Keys were checked by check, so this cannot fail.
		canonical, _ := NormalizeAuthorizedKey(k)
		keys = append(keys, canonical)
	}
	for _, u := range rule.Usernames {
		froms = append(froms, map[string]any{
			"username":             u,
			"authorized_keys_data": strings.Join(keys, "\n"),
		})
	}
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": PipeGVK.GroupVersion().String(),
		"kind":       PipeGVK.Kind,
		"metadata": map[string]any{
			"name":      PipeName(route.Namespace, route.Name, index),
			"namespace": namespace,
			"labels": map[string]any{
				naming.LabelManagedBy:  naming.ManagedBy,
				naming.LabelSSHGateway: gateway,
			},
			"annotations": map[string]any{
				naming.AnnotationSSHRoute: key(route),
				naming.AnnotationSSHRule:  fmt.Sprint(index),
				// The identity key has no certificate, so sshpiper must not look for one.
				"sshpiper.com/no_ca_publickey": naming.LiteralTrue,
			},
		},
		"spec": map[string]any{
			"from": froms,
			"to": map[string]any{
				"host":             rule.Backend,
				"username":         SandboxUser,
				"known_hosts_data": KnownHostsData(rule.Backend, rule.HostKey),
				"private_key_secret": map[string]any{
					"name": naming.SSHIdentitySecretName,
				},
			},
		},
	}}
	return obj
}
