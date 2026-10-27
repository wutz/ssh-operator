package controller

import (
	"context"
	"testing"

	v1 "github.com/wutz/ssh-operator/api/v1alpha1"
)

func TestAdmits(t *testing.T) {
	const gwNS = "forgeai-system"
	all := v1.SSHListener{
		Name:          sshPortName,
		AllowedRoutes: &v1.AllowedRoutes{Namespaces: &v1.RouteNamespaces{From: v1.RouteNamespacesAll}},
	}
	cases := []struct {
		name     string
		listener v1.SSHListener
		routeNS  string
		want     bool
	}{
		{"default admits the gateway namespace", v1.SSHListener{Name: "ssh"}, gwNS, true},
		{"default refuses other namespaces", v1.SSHListener{Name: "ssh"}, "forge-agents", false},
		{"all admits any namespace", all, "forge-agents", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Neither case reads the cluster, so no client is needed.
			got, err := admits(context.Background(), nil, tc.listener, gwNS, tc.routeNS)
			if err != nil {
				t.Fatalf("admits: %v", err)
			}
			if got != tc.want {
				t.Errorf("admits(%s) = %v, want %v", tc.routeNS, got, tc.want)
			}
		})
	}
}
