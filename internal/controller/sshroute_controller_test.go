/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"encoding/base64"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	v1 "github.com/wutz/sshgateway/api/v1alpha1"
	"github.com/wutz/sshgateway/internal/naming"
	"github.com/wutz/sshgateway/pkg/sshgateway"
)

// The route specs use their own project namespace: the project reconciler owns
// the namespaces of the projects it reconciles, and this one is not a project.
const (
	sshProject = "ssh"
	sshNS      = "project-" + sshProject
)

// createSSHBackend creates a backend the way a platform does: a Service that
// exposes an sshd on port 22, and the Secret with the sshd host key. The Service
// selects no pod; the gateway only reads the Service and its Secret.
func createSSHBackend(name string) {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: sshNS, Name: name},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"app": name},
			Ports: []corev1.ServicePort{{
				Name: sshPortName, Port: 22, TargetPort: intstr.FromInt32(22), Protocol: corev1.ProtocolTCP,
			}},
		},
	}
	Expect(k8sClient.Create(ctx, svc)).To(Succeed())

	priv, _, err := sshgateway.GenerateEd25519()
	Expect(err).NotTo(HaveOccurred())
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: sshNS, Name: naming.SSHHostKeySecret(svc.Name),
		},
		Data: map[string][]byte{sshgateway.SSHHostKeyKey: priv},
	}
	Expect(k8sClient.Create(ctx, sec)).To(Succeed())
}

// newSSHRoute is a route in the route specs' namespace that logs username in to the
// backend Service, with the given authorized keys, through the platform gateway.
func newSSHRoute(name, username, backend string, keys ...string) *v1.SSHRoute {
	return &v1.SSHRoute{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: sshNS},
		Spec: v1.SSHRouteSpec{
			ParentRefs: []v1.ParentReference{{Name: sshGatewayName}},
			Rules: []v1.SSHRouteRule{{
				Matches:        []v1.SSHRouteMatch{{Username: username}},
				AuthorizedKeys: keys,
				BackendRefs:    []v1.SSHBackendRef{{Name: backend, Username: "agent"}},
			}},
		},
	}
}

// routeCondition is the condition of the route named name on the platform
// gateway, or nil.
func routeCondition(name, typ string) *metav1.Condition {
	route := &v1.SSHRoute{}
	if err := k8sClient.Get(ctx, client.ObjectKey{Namespace: sshNS, Name: name}, route); err != nil {
		return nil
	}
	for _, p := range route.Status.Parents {
		if p.ControllerName == v1.SSHGatewayControllerName {
			return meta.FindStatusCondition(p.Conditions, typ)
		}
	}
	return nil
}

// routeReason is the reason of a route condition, or "" while it is missing.
func routeReason(name, typ string) func() string {
	return func() string {
		c := routeCondition(name, typ)
		if c == nil {
			return ""
		}
		return c.Reason
	}
}

var _ = Describe("SSH route controller", Ordered, func() {
	const backend = "route-agent"
	var keys string

	BeforeAll(func() {
		ensureSSHGateway()
		Expect(client.IgnoreAlreadyExists(k8sClient.Create(ctx, &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: sshNS},
		}))).To(Succeed())
		createSSHBackend(backend)

		_, pub, err := sshgateway.GenerateEd25519()
		Expect(err).NotTo(HaveOccurred())
		keys = pub
	})

	It("attaches a route and writes one pipe per rule", func() {
		route := newSSHRoute("agent-login", "route-alice", backend, keys)
		Expect(k8sClient.Create(ctx, route)).To(Succeed())

		Eventually(routeReason("agent-login", v1.SSHConditionAccepted), timeout, interval).Should(Equal(v1.SSHReasonAccepted))
		Eventually(routeReason("agent-login", v1.SSHConditionResolvedRefs), timeout, interval).Should(Equal("ResolvedRefs"))

		var pipes []sshgateway.ConfigPipe
		Eventually(func() []sshgateway.ConfigPipe {
			config, err := gatewayConfig()
			if err != nil {
				return nil
			}
			pipes = pipesAdmitting(config, "route-alice")
			return pipes
		}, timeout, interval).Should(HaveLen(1))
		Expect(pipes[0].To.Host).To(Equal("route-agent.project-ssh.svc:22"))
		Expect(pipes[0].To.Username).To(Equal("agent"))
		Expect(pipes[0].From).To(HaveLen(1))
		Expect(pipes[0].From[0].AuthorizedKeysData).To(Equal(base64.StdEncoding.EncodeToString([]byte(keys + "\n"))))
	})

	It("rejects a route whose authorized key carries options", func() {
		route := newSSHRoute("bad-key", "bad-key-user", backend, `command="true" `+keys)
		Expect(k8sClient.Create(ctx, route)).To(Succeed())

		Eventually(routeReason("bad-key", v1.SSHConditionAccepted), timeout, interval).Should(Equal(v1.SSHReasonInvalidAuthorizedKeys))
		// An unreadable configuration counts as served, so the spec cannot pass on it.
		Consistently(func() bool {
			config, err := gatewayConfig()
			if err != nil {
				return true
			}
			return len(pipesAdmitting(config, "bad-key-user")) > 0
		}, 2*time.Second, interval).Should(BeFalse())
	})

	It("reports a backend that does not exist", func() {
		route := newSSHRoute("no-backend", "missing-user", "absent", keys)
		Expect(k8sClient.Create(ctx, route)).To(Succeed())

		Eventually(routeReason("no-backend", v1.SSHConditionResolvedRefs), timeout, interval).Should(Equal(v1.SSHReasonBackendNotFound))
	})

	It("gives a username claimed by an older route to the older route", func() {
		route := newSSHRoute("claim-again", "route-alice", backend, keys)
		Expect(k8sClient.Create(ctx, route)).To(Succeed())

		Eventually(routeReason("claim-again", v1.SSHConditionAccepted), timeout, interval).Should(Equal(v1.SSHReasonUsernameConflict))
		Eventually(routeReason("agent-login", v1.SSHConditionAccepted), timeout, interval).Should(Equal(v1.SSHReasonAccepted))
	})
})

// gatewayConfig reads the sshpiper configuration of the platform gateway from
// its ConfigMap.
func gatewayConfig() (sshgateway.Config, error) {
	cm := &corev1.ConfigMap{}
	if err := k8sClient.Get(ctx, client.ObjectKey{
		Namespace: configNamespace, Name: naming.SSHGatewayName(sshGatewayName),
	}, cm); err != nil {
		return sshgateway.Config{}, err
	}
	config := sshgateway.Config{}
	err := yaml.Unmarshal([]byte(cm.Data[sshgateway.ConfigKey]), &config)
	return config, err
}

// pipesAdmitting returns the pipes of config that admit username.
func pipesAdmitting(config sshgateway.Config, username string) []sshgateway.ConfigPipe {
	var out []sshgateway.ConfigPipe
	for _, pipe := range config.Pipes {
		for _, from := range pipe.From {
			if from.Username == username {
				out = append(out, pipe)
				break
			}
		}
	}
	return out
}
