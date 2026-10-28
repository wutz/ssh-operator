package sshgateway

import (
	"cmp"
	"encoding/base64"
	"fmt"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"sigs.k8s.io/yaml"
)

// ConfigKey is the key of the sshpiper configuration in the ConfigMap of a gateway.
const ConfigKey = "sshpiperd.yaml"

// ConfigVersion is the version of the configuration format of sshpiper's yaml
// plugin.
const ConfigVersion = "1.0"

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
	// BackendUser is the account the connection is forwarded as on the backend.
	// The client username selects the route; the backend sees this account.
	BackendUser string
	// HostKey is the host key of that sshd; nil when the backend has none.
	HostKey ssh.PublicKey
}

// Problem explains why a route cannot be served.
type Problem struct {
	Reason  string
	Message string
}

// Config is the configuration of sshpiper's yaml plugin: the routing table of a
// gateway. The plugin reads it on every connection.
type Config struct {
	Version string       `json:"version"`
	Pipes   []ConfigPipe `json:"pipes"`
}

// ConfigPipe admits the logins of its From entries and forwards them to To.
type ConfigPipe struct {
	From []ConfigFrom `json:"from"`
	To   ConfigTo     `json:"to"`
}

// ConfigFrom admits one client username with the keys that may log in as it.
type ConfigFrom struct {
	Username string `json:"username"`
	// AuthorizedKeysData is the base64 of the authorized_keys the username accepts.
	AuthorizedKeysData string `json:"authorized_keys_data"`
}

// ConfigTo is the backend a login is forwarded to.
type ConfigTo struct {
	Host     string `json:"host"`
	Username string `json:"username"`
	// KnownHostsData is the base64 of the known_hosts line that pins the host key of the backend.
	KnownHostsData string `json:"known_hosts_data"`
	// PrivateKey is the file of the key the gateway logs in to the backend with.
	PrivateKey string `json:"private_key"`
}

// Plan is the desired state of one gateway: its configuration and the problems
// of the routes left out of it, keyed by "namespace/name".
type Plan struct {
	Config   Config
	Problems map[string]Problem
}

// Build plans the configuration of a gateway from its routes. privateKey is the
// file the gateway logs in to backends with. A route is served only if all its
// rules are: any problem rejects the whole route.
func Build(privateKey string, routes []Route) Plan {
	plan := Plan{Config: Config{Version: ConfigVersion, Pipes: []ConfigPipe{}}, Problems: map[string]Problem{}}
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
		for _, rule := range route.Rules {
			plan.Config.Pipes = append(plan.Config.Pipes, pipe(rule, privateKey))
		}
	}
	return plan
}

// Marshal returns the configuration as the YAML file sshpiper's yaml plugin reads.
func (c Config) Marshal() ([]byte, error) {
	return yaml.Marshal(c)
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

// pipe is the configuration of one rule of a route.
func pipe(rule Rule, privateKey string) ConfigPipe {
	keys := make([]string, 0, len(rule.AuthorizedKeys))
	for _, k := range rule.AuthorizedKeys {
		// Keys were checked by check, so this cannot fail.
		canonical, _ := NormalizeAuthorizedKey(k)
		keys = append(keys, canonical)
	}
	authorized := base64.StdEncoding.EncodeToString([]byte(strings.Join(keys, "\n") + "\n"))

	froms := make([]ConfigFrom, 0, len(rule.Usernames))
	for _, u := range rule.Usernames {
		froms = append(froms, ConfigFrom{Username: u, AuthorizedKeysData: authorized})
	}
	return ConfigPipe{
		From: froms,
		To: ConfigTo{
			Host:           rule.Backend,
			Username:       rule.BackendUser,
			KnownHostsData: KnownHostsData(rule.Backend, rule.HostKey),
			PrivateKey:     privateKey,
		},
	}
}
