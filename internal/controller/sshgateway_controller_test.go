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
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "github.com/wutz/sshgateway/api/v1alpha1"
	"github.com/wutz/sshgateway/internal/naming"
	"github.com/wutz/sshgateway/pkg/sshgateway"
)

const (
	sshClassName   = "sshgateway"
	sshGatewayName = "main"
)

// ensureSSHGateway creates the gateway class and the platform gateway that the
// route specs attach to. Specs share one gateway: the gateway namespace is
// served by one sshpiper, and a second gateway there is rejected.
func ensureSSHGateway() {
	class := &v1.SSHGatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: sshClassName},
		Spec:       v1.SSHGatewayClassSpec{ControllerName: v1.SSHGatewayControllerName},
	}
	ExpectWithOffset(1, client.IgnoreAlreadyExists(k8sClient.Create(ctx, class))).To(Succeed())

	gw := sshGatewayObject(sshGatewayName)
	ExpectWithOffset(1, client.IgnoreAlreadyExists(k8sClient.Create(ctx, gw))).To(Succeed())
}

// sshGatewayObject is a gateway of the gateway namespace that admits routes
// from every namespace, as a platform operator would configure it.
func sshGatewayObject(name string) *v1.SSHGateway {
	return &v1.SSHGateway{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: configNamespace},
		Spec: v1.SSHGatewaySpec{
			GatewayClassName: sshClassName,
			Listeners: []v1.SSHListener{{
				Name: sshPortName, Port: 2222,
				AllowedRoutes: &v1.AllowedRoutes{Namespaces: &v1.RouteNamespaces{From: v1.RouteNamespacesAll}},
			}},
			ServiceType: corev1.ServiceTypeClusterIP,
		},
	}
}

// gatewayCondition is the condition of the platform gateway named name, or nil.
func gatewayCondition(name, typ string) *metav1.Condition {
	gw := &v1.SSHGateway{}
	if err := k8sClient.Get(ctx, client.ObjectKey{Namespace: configNamespace, Name: name}, gw); err != nil {
		return nil
	}
	return meta.FindStatusCondition(gw.Status.Conditions, typ)
}

var _ = Describe("SSH gateway controller", Ordered, func() {
	It("serves the platform gateway with an sshpiper Deployment and a host key", func() {
		ensureSSHGateway()
		name := naming.SSHGatewayName(sshGatewayName)

		deploy := &appsv1.Deployment{}
		Eventually(func() error {
			return k8sClient.Get(ctx, client.ObjectKey{Namespace: configNamespace, Name: name}, deploy)
		}, timeout, interval).Should(Succeed())
		args := deploy.Spec.Template.Spec.Containers[0].Args
		// sshpiper forwards logins to backends only: no forwarding of any kind.
		Expect(args).To(ContainElements("--disable-local-forwarding", "--disable-remote-forwarding", sshpiperPluginPath))
		Expect(deploy.Spec.Template.Spec.SecurityContext.RunAsNonRoot).To(HaveValue(BeTrue()))

		svc := &corev1.Service{}
		Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: configNamespace, Name: name}, svc)).To(Succeed())
		Expect(svc.Spec.Ports).To(HaveLen(1))
		Expect(svc.Spec.Ports[0].Port).To(BeEquivalentTo(2222))

		sec := &corev1.Secret{}
		Eventually(func() error {
			return k8sClient.Get(ctx, client.ObjectKey{
				Namespace: configNamespace, Name: naming.SSHHostKeySecret(name),
			}, sec)
		}, timeout, interval).Should(Succeed())
		Expect(sec.Data).To(HaveKey(sshgateway.SSHHostKeyKey))

		Eventually(func() metav1.ConditionStatus {
			c := gatewayCondition(sshGatewayName, v1.SSHConditionAccepted)
			if c == nil {
				return ""
			}
			return c.Status
		}, timeout, interval).Should(Equal(metav1.ConditionTrue))
		Expect(gatewayCondition(sshGatewayName, v1.SSHConditionProgrammed)).NotTo(BeNil())
	})

	It("does not serve a second gateway of the gateway namespace", func() {
		ensureSSHGateway()
		second := sshGatewayObject("second")
		Expect(client.IgnoreAlreadyExists(k8sClient.Create(ctx, second))).To(Succeed())
		DeferCleanup(func() {
			Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, second))).To(Succeed())
		})

		Eventually(func() string {
			c := gatewayCondition("second", v1.SSHConditionAccepted)
			if c == nil {
				return ""
			}
			return c.Reason
		}, timeout, interval).Should(Equal(v1.SSHReasonInvalid))
		Expect(gatewayCondition("second", v1.SSHConditionReady).Status).To(Equal(metav1.ConditionFalse))
	})
})
