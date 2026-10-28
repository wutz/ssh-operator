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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v1alpha1 "github.com/wutz/sshgateway/api/v1alpha1"
	"github.com/wutz/sshgateway/internal/naming"
	"github.com/wutz/sshgateway/pkg/sshgateway"
)

// sshPortName names the SSH port of sshd and of the sshpiper Service.
const sshPortName = "ssh"

// sshPort is the port of the sshd behind a backend Service when the backend
// names none.
const sshPort = 22

// sshpiperPluginPath runs the yaml plugin of sshpiper, which routes logins by
// the config file it is given. The image keeps the plugin off PATH, so it is
// named by its path. The yaml plugin ships in the "full" image.
const sshpiperPluginPath = "/sshpiperd/plugins/yaml"

const (
	// sshpiperServerKeyDir is where the gateway's host key is mounted.
	sshpiperServerKeyDir = "/etc/sshpiper"
	// sshpiperConfigDir is where the routing table is mounted.
	sshpiperConfigDir = "/etc/sshgateway/config"
	// sshpiperIdentityDir is where the platform identity key is mounted. The
	// gateway logs in to backends with it.
	sshpiperIdentityDir = "/etc/sshgateway/identity"
	// sshpiperUID runs sshpiper without root. The mounted files are
	// group-readable through the fsGroup, so this user can read them.
	sshpiperUID int64 = 65532

	sshpiperServerKeyVolume = "server-key"
	sshpiperConfigVolume    = "config"
	sshpiperIdentityVolume  = "identity"
)

// sshpiperIdentityFile is the file of the platform identity key in sshpiperIdentityDir.
const sshpiperIdentityFile = sshPrivateKeyKey

// SSHGatewayReconciler serves an SSHGateway with sshpiper. The configuration it
// writes is sshpiper's routing table, one pipe per rule of each attached SSHRoute.
type SSHGatewayReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	// GatewayNamespace is where the platform keeps the SSH identity and where
	// SSHGateways are served.
	GatewayNamespace string
	// GatewayImage is the sshpiper image that serves the gateways.
	GatewayImage string
}

// +kubebuilder:rbac:groups=sshgateway.wutz.dev,resources=sshgateways,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=sshgateway.wutz.dev,resources=sshgateways/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=sshgateway.wutz.dev,resources=sshgateways/finalizers,verbs=update
// +kubebuilder:rbac:groups=sshgateway.wutz.dev,resources=sshgatewayclasses,verbs=get;list;watch
// +kubebuilder:rbac:groups=sshgateway.wutz.dev,resources=sshroutes,verbs=get;list;watch
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=services;secrets;configmaps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch

// Reconcile serves the SSHGateway if it is the one of the gateway namespace,
// and writes the Deployment, Service and ConfigMap that serve it.
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

	if gw.Namespace != r.GatewayNamespace {
		r.reject(gw, v1alpha1.SSHReasonNotGatewayNamespace, "SSHGateways are served in the gateway namespace only")
		return nil
	}
	served, err := servedGateway(ctx, r.Client, r.GatewayNamespace)
	if err != nil {
		return err
	}
	if served == nil || served.Name != gw.Name {
		r.reject(gw, v1alpha1.SSHReasonInvalid, "the gateway namespace is served by another SSHGateway")
		return nil
	}
	if len(gw.Spec.Listeners) == 0 {
		r.reject(gw, v1alpha1.SSHReasonInvalid, "the SSHGateway has no listener")
		return nil
	}
	listener := gw.Spec.Listeners[0]

	plan, attached, err := planSSHGateway(ctx, r.Client, r.GatewayNamespace, gw)
	if err != nil {
		return err
	}
	config, err := plan.Config.Marshal()
	if err != nil {
		return err
	}

	name := naming.SSHGatewayName(gw.Name)
	hostKey, err := r.ensureHostKey(ctx, gw, naming.SSHHostKeySecret(name))
	if err != nil {
		return err
	}
	if _, err := ensureSSHIdentity(ctx, r.Client, r.GatewayNamespace); err != nil {
		return err
	}

	objs := []client.Object{
		sshpiperService(gw, name, listener.Port),
		sshpiperConfigMap(gw, name, config),
		sshpiperDeployment(gw, name, r.GatewayImage, listener.Port, hostKey.Name),
	}
	for _, obj := range objs {
		if err := controllerutil.SetControllerReference(gw, obj, r.Scheme); err != nil {
			return err
		}
		if err := apply(ctx, r.Client, obj); err != nil {
			return err
		}
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
		v1alpha1.SSHReasonProgrammed, "sshpiper is configured with the routes")
	if deploy.Status.AvailableReplicas > 0 {
		setSSHCondition(&gw.Status.Conditions, gen, v1alpha1.SSHConditionReady, metav1.ConditionTrue,
			v1alpha1.SSHReasonReady, "sshpiper accepts connections")
	} else {
		setSSHCondition(&gw.Status.Conditions, gen, v1alpha1.SSHConditionReady, metav1.ConditionFalse,
			v1alpha1.SSHReasonNotReady, "sshpiper has no available replica")
	}
	log.V(1).Info("Programmed SSHGateway", "sshgateway", gw.Name, "pipes", len(plan.Config.Pipes), "routes", attached)
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

// ensureHostKey returns the Secret holding the sshpiper host key, generating the
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
// are planned from: routes, classes, backend Services and host key Secrets, and
// namespace labels.
func (r *SSHGatewayReconciler) SetupWithManager(mgr ctrl.Manager) error {
	all := func(ctx context.Context, _ client.Object) []reconcile.Request {
		return gatewayRequests(ctx, mgr.GetClient())
	}
	// A backend change re-plans every gateway, since a route is served by the
	// gateways it attaches to. Objects no route names are ignored.
	backend := func(ctx context.Context, obj client.Object) []reconcile.Request {
		if len(backendRequests(ctx, mgr.GetClient(), obj)) == 0 {
			return nil
		}
		return gatewayRequests(ctx, mgr.GetClient())
	}
	return ctrl.NewControllerManagedBy(mgr).
		Named("sshgateway").
		For(&v1alpha1.SSHGateway{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.Service{}).
		Owns(&corev1.Secret{}).
		Owns(&corev1.ConfigMap{}).
		Watches(&v1alpha1.SSHGateway{}, handler.EnqueueRequestsFromMapFunc(all)).
		Watches(&v1alpha1.SSHGatewayClass{}, handler.EnqueueRequestsFromMapFunc(all)).
		Watches(&v1alpha1.SSHRoute{}, handler.EnqueueRequestsFromMapFunc(all)).
		Watches(&corev1.Service{}, handler.EnqueueRequestsFromMapFunc(backend)).
		Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(backend)).
		Watches(&corev1.Namespace{}, handler.EnqueueRequestsFromMapFunc(all)).
		Complete(r)
}

func sshpiperMeta(gw *v1alpha1.SSHGateway, name string) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		Namespace: gw.Namespace,
		Name:      name,
		Labels:    sshpiperLabels(gw),
	}
}

// sshpiperLabels select the sshpiper pods of gw.
func sshpiperLabels(gw *v1alpha1.SSHGateway) map[string]string {
	return map[string]string{
		naming.LabelManagedBy:  naming.ManagedBy,
		naming.LabelComponent:  naming.ComponentSSHGateway,
		naming.LabelSSHGateway: gw.Name,
	}
}

func sshpiperService(gw *v1alpha1.SSHGateway, name string, port int32) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: sshpiperMeta(gw, name),
		Spec: corev1.ServiceSpec{
			Type:     gw.Spec.ServiceType,
			Selector: sshpiperLabels(gw),
			Ports: []corev1.ServicePort{{
				Name:       sshPortName,
				Port:       port,
				TargetPort: intstr.FromInt32(port),
				Protocol:   corev1.ProtocolTCP,
			}},
		},
	}
}

// sshpiperConfigMap holds the routing table of gw: the sshpiper configuration
// the yaml plugin reads on every connection.
func sshpiperConfigMap(gw *v1alpha1.SSHGateway, name string, config []byte) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: sshpiperMeta(gw, name),
		Data:       map[string]string{sshgateway.ConfigKey: string(config)},
	}
}

// sshpiperDeployment runs sshpiper with the yaml plugin, which routes logins by
// the ConfigMap of the gateway. It runs unprivileged, without forwarding, and
// has no API access: it reads only its mounted files.
func sshpiperDeployment(gw *v1alpha1.SSHGateway, name, image string, port int32, hostKeySecret string) *appsv1.Deployment {
	labels := sshpiperLabels(gw)
	return &appsv1.Deployment{
		ObjectMeta: sshpiperMeta(gw, name),
		Spec: appsv1.DeploymentSpec{
			Replicas: new(int32(1)),
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					AutomountServiceAccountToken: new(false),
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot: new(true),
						RunAsUser:    new(sshpiperUID),
						FSGroup:      new(sshpiperUID),
					},
					Containers: []corev1.Container{{
						Name:  "sshpiper",
						Image: image,
						Args: []string{
							"--port", strconv.Itoa(int(port)),
							"--server-key", sshpiperServerKeyDir + "/" + sshgateway.SSHHostKeyKey,
							"--disable-local-forwarding",
							"--disable-remote-forwarding",
							"--log-level", "info",
							sshpiperPluginPath,
							"--config", sshpiperConfigDir + "/" + sshgateway.ConfigKey,
							// The config is a read-only mount that the fsGroup makes
							// group-readable, which the plugin's 0400 check refuses.
							"--no-check-perm",
						},
						Ports: []corev1.ContainerPort{{Name: sshPortName, ContainerPort: port, Protocol: corev1.ProtocolTCP}},
						VolumeMounts: []corev1.VolumeMount{
							{Name: sshpiperServerKeyVolume, MountPath: sshpiperServerKeyDir, ReadOnly: true},
							{Name: sshpiperConfigVolume, MountPath: sshpiperConfigDir, ReadOnly: true},
							{Name: sshpiperIdentityVolume, MountPath: sshpiperIdentityDir, ReadOnly: true},
						},
						SecurityContext: &corev1.SecurityContext{
							AllowPrivilegeEscalation: new(false),
							Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
						},
					}},
					Volumes: []corev1.Volume{
						{
							Name: sshpiperServerKeyVolume,
							VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{
								SecretName:  hostKeySecret,
								DefaultMode: new(int32(0o440)),
							}},
						},
						{
							Name: sshpiperConfigVolume,
							VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
								LocalObjectReference: corev1.LocalObjectReference{Name: naming.SSHGatewayName(gw.Name)},
								DefaultMode:          new(int32(0o440)),
							}},
						},
						{
							Name: sshpiperIdentityVolume,
							VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{
								SecretName:  naming.SSHIdentitySecretName,
								DefaultMode: new(int32(0o440)),
								Items: []corev1.KeyToPath{{
									Key:  sshPrivateKeyKey,
									Path: sshpiperIdentityFile,
								}},
							}},
						},
					},
				},
			},
		},
	}
}
