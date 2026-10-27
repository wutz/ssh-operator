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
	"context"
	"net"
	"strconv"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v1alpha1 "github.com/wutz/ssh-operator/api/v1alpha1"
	"github.com/wutz/ssh-operator/internal/naming"
	"github.com/wutz/ssh-operator/pkg/sshgateway"
)

// sshPortName names the SSH port of sshd and of the sshpiperd Service.
const sshPortName = "ssh"

// sshPort is the port sshd listens on in the sidecar of a sandbox.
const sshPort = 22

// sshpiperdPluginPath runs the kubernetes plugin of sshpiperd, which serves the
// Pipes of the namespace its ServiceAccount runs in. The image keeps the plugin
// off PATH, so it is named by its path.
const sshpiperdPluginPath = "/sshpiperd/plugins/kubernetes"

const (
	// sshpiperdServerKeyDir is where the gateway's host key is mounted.
	sshpiperdServerKeyDir = "/etc/sshpiperd"
	// sshpiperdUID runs sshpiperd without root. The host key is group-readable
	// through the fsGroup, so this user can read it.
	sshpiperdUID int64 = 65532
	// sshpiperdConfigVolume is the volume holding the host key.
	sshpiperdConfigVolume = "server-key"
)

// SSHGatewayReconciler serves an SSHGateway with sshpiperd. The Pipes it writes
// are sshpiperd's routing table, one per rule of each attached SSHRoute.
type SSHGatewayReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	// PlatformNamespace is where the platform keeps the SSH identity and where
	// SSHGateways are served.
	PlatformNamespace string
	// GatewayImage is the sshpiperd image that serves the gateways.
	GatewayImage string
}

// +kubebuilder:rbac:groups=forgeai.wutz.dev,resources=sshgateways,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=forgeai.wutz.dev,resources=sshgateways/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=forgeai.wutz.dev,resources=sshgateways/finalizers,verbs=update
// +kubebuilder:rbac:groups=forgeai.wutz.dev,resources=sshgatewayclasses,verbs=get;list;watch
// +kubebuilder:rbac:groups=forgeai.wutz.dev,resources=sshroutes,verbs=get;list;watch
// +kubebuilder:rbac:groups=sshpiper.com,resources=pipes,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=services;serviceaccounts;secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles;rolebindings,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch

// Reconcile serves the SSHGateway if it is the one of the platform namespace,
// and writes the Deployment, Service and Pipes that serve it.
func (r *SSHGatewayReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	gw := &v1alpha1.SSHGateway{}
	if err := r.Get(ctx, req.NamespacedName, gw); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !gw.DeletionTimestamp.IsZero() {
		// The owned objects are garbage collected with the gateway.
		return ctrl.Result{}, nil
	}
	ours, err := ownsClass(ctx, r.Client, gw.Spec.GatewayClassName)
	if err != nil {
		return ctrl.Result{}, err
	}
	if !ours {
		return ctrl.Result{}, nil
	}

	orig := gw.DeepCopy()
	if err := r.program(ctx, gw); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.Status().Patch(ctx, gw, client.MergeFrom(orig)); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// program makes the cluster serve gw and sets its status to what it did.
func (r *SSHGatewayReconciler) program(ctx context.Context, gw *v1alpha1.SSHGateway) error {
	log := logf.FromContext(ctx)
	gen := gw.Generation

	if gw.Namespace != r.PlatformNamespace {
		r.reject(gw, v1alpha1.SSHReasonNotPlatformNamespace, "SSHGateways are served in the platform namespace only")
		return nil
	}
	served, err := servedGateway(ctx, r.Client, r.PlatformNamespace)
	if err != nil {
		return err
	}
	if served == nil || served.Name != gw.Name {
		r.reject(gw, v1alpha1.SSHReasonInvalid, "the platform namespace is served by another SSHGateway")
		return nil
	}
	if len(gw.Spec.Listeners) == 0 {
		r.reject(gw, v1alpha1.SSHReasonInvalid, "the SSHGateway has no listener")
		return nil
	}
	listener := gw.Spec.Listeners[0]

	plan, attached, err := planSSHGateway(ctx, r.Client, r.PlatformNamespace, gw)
	if err != nil {
		return err
	}

	name := naming.SSHGatewayName(gw.Name)
	hostKey, err := r.ensureHostKey(ctx, gw, naming.SSHHostKeySecret(name))
	if err != nil {
		return err
	}
	if _, err := ensureSSHIdentity(ctx, r.Client, r.PlatformNamespace); err != nil {
		return err
	}

	objs := []client.Object{
		sshpiperdServiceAccount(gw, name),
		sshpiperdRole(gw, name),
		sshpiperdRoleBinding(gw, name),
		sshpiperdService(gw, name, listener.Port),
		sshpiperdDeployment(gw, name, r.GatewayImage, listener.Port, hostKey.Name),
	}
	for _, obj := range objs {
		if err := controllerutil.SetControllerReference(gw, obj, r.Scheme); err != nil {
			return err
		}
		if err := apply(ctx, r.Client, obj); err != nil {
			return err
		}
	}

	keep := map[string]bool{}
	for _, p := range plan.Pipes {
		if err := controllerutil.SetControllerReference(gw, p, r.Scheme); err != nil {
			return err
		}
		if err := apply(ctx, r.Client, p); err != nil {
			return err
		}
		keep[p.GetName()] = true
	}
	if err := r.prunePipes(ctx, gw, keep); err != nil {
		return err
	}

	deploy := &appsv1.Deployment{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: name}, deploy); err != nil {
		return err
	}
	addresses, err := r.addresses(ctx, gw, name, listener.Port)
	if err != nil {
		return err
	}

	gw.Status.Addresses = addresses
	gw.Status.Listeners = []v1alpha1.SSHListenerStatus{{Name: listener.Name, AttachedRoutes: attached}}
	setSSHCondition(&gw.Status.Conditions, gen, v1alpha1.SSHConditionAccepted, metav1.ConditionTrue,
		v1alpha1.SSHReasonAccepted, "the SSHGateway is served")
	setSSHCondition(&gw.Status.Conditions, gen, v1alpha1.SSHConditionProgrammed, metav1.ConditionTrue,
		v1alpha1.SSHReasonProgrammed, "sshpiperd is configured with the routes")
	if deploy.Status.AvailableReplicas > 0 {
		setSSHCondition(&gw.Status.Conditions, gen, v1alpha1.SSHConditionReady, metav1.ConditionTrue,
			v1alpha1.SSHReasonReady, "sshpiperd accepts connections")
	} else {
		setSSHCondition(&gw.Status.Conditions, gen, v1alpha1.SSHConditionReady, metav1.ConditionFalse,
			v1alpha1.SSHReasonNotReady, "sshpiperd has no available replica")
	}
	log.V(1).Info("Programmed SSHGateway", "sshgateway", gw.Name, "pipes", len(plan.Pipes), "routes", attached)
	return nil
}

// reject sets the status of a gateway that does not serve.
func (r *SSHGatewayReconciler) reject(gw *v1alpha1.SSHGateway, reason, message string) {
	gen := gw.Generation
	gw.Status.Listeners = nil
	setSSHCondition(&gw.Status.Conditions, gen, v1alpha1.SSHConditionAccepted, metav1.ConditionFalse, reason, message)
	setSSHCondition(&gw.Status.Conditions, gen, v1alpha1.SSHConditionProgrammed, metav1.ConditionFalse,
		v1alpha1.SSHReasonInvalid, "the SSHGateway is not served")
	setSSHCondition(&gw.Status.Conditions, gen, v1alpha1.SSHConditionReady, metav1.ConditionFalse,
		v1alpha1.SSHReasonNotReady, "the SSHGateway is not served")
}

// ensureHostKey returns the Secret holding the sshpiperd host key, generating the
// key once: clients pin it, so a new key would fail them all.
func (r *SSHGatewayReconciler) ensureHostKey(ctx context.Context, gw *v1alpha1.SSHGateway, name string) (*corev1.Secret, error) {
	sec := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: gw.Namespace, Name: name}}
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, sec, func() error {
		if err := controllerutil.SetControllerReference(gw, sec, r.Scheme); err != nil {
			return err
		}
		sec.Labels = map[string]string{
			naming.LabelManagedBy: naming.ManagedBy,
			naming.LabelComponent: naming.ComponentSSHGateway,
		}
		sec.Type = corev1.SecretTypeOpaque
		if len(sec.Data[sshgateway.SSHHostKeyKey]) == 0 {
			priv, _, err := sshgateway.GenerateEd25519()
			if err != nil {
				return err
			}
			sec.Data = map[string][]byte{sshgateway.SSHHostKeyKey: priv}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return sec, nil
}

// prunePipes deletes the Pipes of gw that no longer match a rule of a route.
func (r *SSHGatewayReconciler) prunePipes(ctx context.Context, gw *v1alpha1.SSHGateway, keep map[string]bool) error {
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(sshgateway.PipeGVK.GroupVersion().WithKind(sshgateway.PipeGVK.Kind + "List"))
	if err := r.List(ctx, list, client.InNamespace(gw.Namespace), client.MatchingLabels{
		naming.LabelManagedBy:  naming.ManagedBy,
		naming.LabelSSHGateway: gw.Name,
	}); err != nil {
		return err
	}
	for i := range list.Items {
		p := &list.Items[i]
		if keep[p.GetName()] || !metav1.IsControlledBy(p, gw) {
			continue
		}
		if err := r.Delete(ctx, p); client.IgnoreNotFound(err) != nil {
			return err
		}
	}
	return nil
}

// addresses are the host:port the gateway's Service is reachable at.
func (r *SSHGatewayReconciler) addresses(ctx context.Context, gw *v1alpha1.SSHGateway, name string, port int32) ([]string, error) {
	svc := &corev1.Service{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: name}, svc); err != nil {
		return nil, err
	}
	var out []string
	for _, ing := range svc.Status.LoadBalancer.Ingress {
		host := ing.IP
		if host == "" {
			host = ing.Hostname
		}
		if host != "" {
			out = append(out, net.JoinHostPort(host, strconv.Itoa(int(port))))
		}
	}
	return out, nil
}

// SetupWithManager watches the gateways, the objects it owns, and what routes
// are planned from: routes, classes, sandbox backends and namespace labels.
func (r *SSHGatewayReconciler) SetupWithManager(mgr ctrl.Manager) error {
	pipe := &unstructured.Unstructured{}
	pipe.SetGroupVersionKind(sshgateway.PipeGVK)
	all := func(ctx context.Context, _ client.Object) []reconcile.Request {
		return gatewayRequests(ctx, mgr.GetClient())
	}
	return ctrl.NewControllerManagedBy(mgr).
		Named("sshgateway").
		For(&v1alpha1.SSHGateway{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.Service{}).
		Owns(&corev1.Secret{}).
		Owns(pipe).
		Watches(&v1alpha1.SSHGateway{}, handler.EnqueueRequestsFromMapFunc(all)).
		Watches(&v1alpha1.SSHGatewayClass{}, handler.EnqueueRequestsFromMapFunc(all)).
		Watches(&v1alpha1.SSHRoute{}, handler.EnqueueRequestsFromMapFunc(all)).
		Watches(&corev1.Service{}, handler.EnqueueRequestsFromMapFunc(all), builder.WithPredicates(sandboxBackends())).
		Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(all), builder.WithPredicates(sandboxBackends())).
		Watches(&corev1.Namespace{}, handler.EnqueueRequestsFromMapFunc(all)).
		Complete(r)
}

func sshpiperdMeta(gw *v1alpha1.SSHGateway, name string) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		Namespace: gw.Namespace,
		Name:      name,
		Labels:    sshpiperdLabels(gw),
	}
}

// sshpiperdLabels select the sshpiperd pods of gw.
func sshpiperdLabels(gw *v1alpha1.SSHGateway) map[string]string {
	return map[string]string{
		naming.LabelManagedBy:  naming.ManagedBy,
		naming.LabelComponent:  naming.ComponentSSHGateway,
		naming.LabelSSHGateway: gw.Name,
	}
}

func sshpiperdServiceAccount(gw *v1alpha1.SSHGateway, name string) *corev1.ServiceAccount {
	return &corev1.ServiceAccount{ObjectMeta: sshpiperdMeta(gw, name)}
}

// sshpiperdRole lets the kubernetes plugin list the Pipes and read the platform
// identity key, and nothing else.
func sshpiperdRole(gw *v1alpha1.SSHGateway, name string) *rbacv1.Role {
	return &rbacv1.Role{
		ObjectMeta: sshpiperdMeta(gw, name),
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{sshgateway.PipeGVK.Group},
				Resources: []string{"pipes"},
				Verbs:     []string{"get", "list", "watch"},
			},
			{
				APIGroups:     []string{""},
				Resources:     []string{"secrets"},
				ResourceNames: []string{naming.SSHIdentitySecretName},
				Verbs:         []string{"get"},
			},
		},
	}
}

func sshpiperdRoleBinding(gw *v1alpha1.SSHGateway, name string) *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		ObjectMeta: sshpiperdMeta(gw, name),
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: name},
		Subjects:   []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Name: name, Namespace: gw.Namespace}},
	}
}

func sshpiperdService(gw *v1alpha1.SSHGateway, name string, port int32) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: sshpiperdMeta(gw, name),
		Spec: corev1.ServiceSpec{
			Type:     gw.Spec.ServiceType,
			Selector: sshpiperdLabels(gw),
			Ports: []corev1.ServicePort{{
				Name:       sshPortName,
				Port:       port,
				TargetPort: intstr.FromInt32(port),
				Protocol:   corev1.ProtocolTCP,
			}},
		},
	}
}

// sshpiperdDeployment runs sshpiperd with the kubernetes plugin, which serves the
// Pipes of its own namespace. It runs unprivileged, without forwarding.
func sshpiperdDeployment(gw *v1alpha1.SSHGateway, name, image string, port int32, hostKeySecret string) *appsv1.Deployment {
	labels := sshpiperdLabels(gw)
	return &appsv1.Deployment{
		ObjectMeta: sshpiperdMeta(gw, name),
		Spec: appsv1.DeploymentSpec{
			Replicas: new(int32(1)),
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					ServiceAccountName: name,
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot: new(true),
						RunAsUser:    new(sshpiperdUID),
						FSGroup:      new(sshpiperdUID),
					},
					Containers: []corev1.Container{{
						Name:  "sshpiperd",
						Image: image,
						Args: []string{
							"--port", strconv.Itoa(int(port)),
							"--server-key", sshpiperdServerKeyDir + "/" + sshgateway.SSHHostKeyKey,
							"--disable-local-forwarding",
							"--disable-remote-forwarding",
							"--log-level", "info",
							sshpiperdPluginPath,
						},
						Ports: []corev1.ContainerPort{{Name: sshPortName, ContainerPort: port, Protocol: corev1.ProtocolTCP}},
						VolumeMounts: []corev1.VolumeMount{{
							Name:      sshpiperdConfigVolume,
							MountPath: sshpiperdServerKeyDir,
							ReadOnly:  true,
						}},
						SecurityContext: &corev1.SecurityContext{
							AllowPrivilegeEscalation: new(false),
							Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
						},
					}},
					Volumes: []corev1.Volume{{
						Name: sshpiperdConfigVolume,
						VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{
							SecretName:  hostKeySecret,
							DefaultMode: new(int32(0o440)),
						}},
					}},
				},
			},
		},
	}
}
