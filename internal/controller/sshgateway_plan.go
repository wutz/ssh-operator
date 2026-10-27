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
	"cmp"
	"context"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v1 "github.com/wutz/ssh-operator/api/v1alpha1"
	"github.com/wutz/ssh-operator/internal/naming"
	"github.com/wutz/ssh-operator/pkg/sshgateway"
)

// Gateways and routes are planned together. The Pipes of a gateway are the
// routes attached to it, and the status of a route is the plan's verdict on it,
// so both controllers run the same functions over the same cluster state.

// sshReasonResolvedRefs is the reason of a ResolvedRefs condition that holds.
const sshReasonResolvedRefs = "ResolvedRefs"

// parentVerdict is what one parentRef of an SSHRoute means for the route.
type parentVerdict struct {
	gateway types.NamespacedName
	// managed is false when the parent is not an SSHGateway of this controller.
	managed bool
	// gw is the SSHGateway the parent names, once it is found.
	gw *v1.SSHGateway
	// reason and message say why the route does not attach; empty when it does.
	reason  string
	message string
}

// sandboxGVK is the kind of the agent-sandbox objects the platform creates. The
// owner of a sandbox's SSH Service is one of them.
var sandboxGVK = schema.GroupVersionKind{Group: "agents.x-k8s.io", Version: "v1beta1", Kind: "Sandbox"}

// parentGateway is the SSHGateway a parentRef names. Gateways live in the
// platform namespace, which is the default.
func parentGateway(ref v1.ParentReference, platformNamespace string) types.NamespacedName {
	ns := platformNamespace
	if ref.Namespace != nil {
		ns = *ref.Namespace
	}
	return types.NamespacedName{Namespace: ns, Name: ref.Name}
}

// resolveParent works out whether route may attach to the gateway ref names.
func resolveParent(ctx context.Context, c client.Reader, platformNamespace string, route *v1.SSHRoute, ref v1.ParentReference) (parentVerdict, error) {
	v := parentVerdict{gateway: parentGateway(ref, platformNamespace), managed: true}
	gw := &v1.SSHGateway{}
	if err := c.Get(ctx, v.gateway, gw); err != nil {
		if apierrors.IsNotFound(err) {
			v.reason, v.message = v1.SSHReasonNoMatchingParent, "the SSHGateway does not exist"
			return v, nil
		}
		return parentVerdict{}, err
	}
	ours, err := ownsClass(ctx, c, gw.Spec.GatewayClassName)
	if err != nil {
		return parentVerdict{}, err
	}
	if !ours {
		return parentVerdict{}, nil
	}
	v.gw = gw
	if gw.Namespace != platformNamespace {
		v.reason, v.message = v1.SSHReasonNoMatchingParent, "SSHGateways are served in the platform namespace only"
		return v, nil
	}
	served, err := servedGateway(ctx, c, platformNamespace)
	if err != nil {
		return parentVerdict{}, err
	}
	if served == nil || served.Name != gw.Name {
		v.reason, v.message = v1.SSHReasonNoMatchingParent, "the platform namespace is served by another SSHGateway"
		return v, nil
	}
	if len(gw.Spec.Listeners) == 0 {
		v.reason, v.message = v1.SSHReasonNoMatchingParent, "the SSHGateway has no listener"
		return v, nil
	}
	listener := gw.Spec.Listeners[0]
	if ref.SectionName != nil && *ref.SectionName != listener.Name {
		v.reason, v.message = v1.SSHReasonNoMatchingParent, fmt.Sprintf("the SSHGateway has no listener %q", *ref.SectionName)
		return v, nil
	}
	ok, err := admits(ctx, c, listener, gw.Namespace, route.Namespace)
	if err != nil {
		return parentVerdict{}, err
	}
	if !ok {
		v.reason = v1.SSHReasonNotAllowedByListeners
		v.message = fmt.Sprintf("the listener does not admit routes from namespace %q", route.Namespace)
	}
	return v, nil
}

// admits reports whether listener accepts routes from routeNS to a gateway in
// gwNS. The default is Same: only routes of the gateway's namespace.
func admits(ctx context.Context, c client.Reader, listener v1.SSHListener, gwNS, routeNS string) (bool, error) {
	if listener.AllowedRoutes == nil || listener.AllowedRoutes.Namespaces == nil {
		return routeNS == gwNS, nil
	}
	namespaces := listener.AllowedRoutes.Namespaces
	switch namespaces.From {
	case v1.RouteNamespacesAll:
		return true, nil
	case v1.RouteNamespacesSelector:
		if namespaces.Selector == nil {
			return false, nil
		}
		selector, err := metav1.LabelSelectorAsSelector(namespaces.Selector)
		if err != nil {
			return false, nil
		}
		ns := &corev1.Namespace{}
		if err := c.Get(ctx, types.NamespacedName{Name: routeNS}, ns); err != nil {
			return false, client.IgnoreNotFound(err)
		}
		return selector.Matches(labels.Set(ns.Labels)), nil
	default:
		return routeNS == gwNS, nil
	}
}

// ownsClass reports whether the SSHGatewayClass named class is served by this
// controller. A missing class is not ours.
func ownsClass(ctx context.Context, c client.Reader, class string) (bool, error) {
	sc := &v1.SSHGatewayClass{}
	if err := c.Get(ctx, types.NamespacedName{Name: class}, sc); err != nil {
		return false, client.IgnoreNotFound(err)
	}
	return sc.Spec.ControllerName == v1.SSHGatewayControllerName, nil
}

// servedGateway is the SSHGateway that serves the platform namespace: the first
// created of the gateways of this controller. One sshpiperd serves every Pipe
// in its namespace, so a second gateway would also serve the first one's routes.
func servedGateway(ctx context.Context, c client.Reader, platformNamespace string) (*v1.SSHGateway, error) {
	list := &v1.SSHGatewayList{}
	if err := c.List(ctx, list, client.InNamespace(platformNamespace)); err != nil {
		return nil, err
	}
	slices.SortFunc(list.Items, func(a, b v1.SSHGateway) int {
		return cmp.Or(
			a.CreationTimestamp.Compare(b.CreationTimestamp.Time),
			strings.Compare(a.Name, b.Name),
		)
	})
	for i := range list.Items {
		gw := &list.Items[i]
		if !gw.DeletionTimestamp.IsZero() {
			continue
		}
		ours, err := ownsClass(ctx, c, gw.Spec.GatewayClassName)
		if err != nil {
			return nil, err
		}
		if ours {
			return gw, nil
		}
	}
	return nil, nil
}

// planSSHGateway plans the Pipes of gw from the SSHRoutes attached to it. It
// also returns how many routes are attached.
func planSSHGateway(ctx context.Context, c client.Reader, platformNamespace string, gw *v1.SSHGateway) (sshgateway.Plan, int32, error) {
	routes := &v1.SSHRouteList{}
	if err := c.List(ctx, routes); err != nil {
		return sshgateway.Plan{}, 0, err
	}
	key := types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name}
	var attached []sshgateway.Route
	for i := range routes.Items {
		route := &routes.Items[i]
		ok, err := attaches(ctx, c, platformNamespace, route, key)
		if err != nil {
			return sshgateway.Plan{}, 0, err
		}
		if !ok {
			continue
		}
		rules, err := resolveRules(ctx, c, route)
		if err != nil {
			return sshgateway.Plan{}, 0, err
		}
		attached = append(attached, sshgateway.Route{
			Namespace: route.Namespace,
			Name:      route.Name,
			Created:   route.CreationTimestamp.Time,
			Rules:     rules,
		})
	}
	return sshgateway.Build(gw.Namespace, gw.Name, attached), int32(len(attached)), nil
}

// attaches reports whether route attaches to the gateway key through one of its parents.
func attaches(ctx context.Context, c client.Reader, platformNamespace string, route *v1.SSHRoute, gateway types.NamespacedName) (bool, error) {
	if !route.DeletionTimestamp.IsZero() {
		return false, nil
	}
	for _, ref := range route.Spec.ParentRefs {
		if parentGateway(ref, platformNamespace) != gateway {
			continue
		}
		v, err := resolveParent(ctx, c, platformNamespace, route, ref)
		if err != nil {
			return false, err
		}
		if v.managed && v.reason == "" {
			return true, nil
		}
	}
	return false, nil
}

// resolveRules resolves the backend and host key of each rule of route. A rule
// whose backend is missing keeps an empty backend, which sshgateway.Build reports.
func resolveRules(ctx context.Context, c client.Reader, route *v1.SSHRoute) ([]sshgateway.Rule, error) {
	rules := make([]sshgateway.Rule, 0, len(route.Spec.Rules))
	for _, r := range route.Spec.Rules {
		rule := sshgateway.Rule{AuthorizedKeys: r.AuthorizedKeys}
		for _, m := range r.Matches {
			rule.Usernames = append(rule.Usernames, m.Username)
		}
		if len(r.BackendRefs) > 0 {
			addr, key, err := resolveBackend(ctx, c, route.Namespace, r.BackendRefs[0])
			if err != nil {
				return nil, err
			}
			rule.Backend, rule.HostKey = addr, key
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

// resolveBackend finds the SSH Service of the sandbox ref names, in namespace,
// and the host key the sandbox presents. Only Services owned by a sandbox are
// backends: the gateway logs in to a backend with the platform key.
func resolveBackend(ctx context.Context, c client.Reader, namespace string, ref v1.SSHBackendRef) (string, ssh.PublicKey, error) {
	svc := &corev1.Service{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: naming.SSHServiceName(ref.Name)}, svc); err != nil {
		return "", nil, client.IgnoreNotFound(err)
	}
	if !ownedBySandbox(svc) {
		return "", nil, nil
	}
	port := ref.Port
	if port == 0 {
		port = sshPort
	}
	addr := net.JoinHostPort(fmt.Sprintf("%s.%s.svc", svc.Name, namespace), strconv.Itoa(int(port)))

	sec := &corev1.Secret{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: naming.SSHHostKeySecret(svc.Name)}, sec); err != nil {
		return addr, nil, client.IgnoreNotFound(err)
	}
	key, err := sshgateway.PublicKeyOf(sec.Data[sshgateway.SSHHostKeyKey])
	if err != nil {
		// An unreadable host key is no host key: the route reports HostKeyNotFound.
		return addr, nil, nil
	}
	return addr, key, nil
}

// ownedBySandbox reports whether svc is the Service of a sandbox.
func ownedBySandbox(svc *corev1.Service) bool {
	for _, ref := range svc.OwnerReferences {
		if ref.Kind == sandboxGVK.Kind && ref.APIVersion == sandboxGVK.GroupVersion().String() {
			return true
		}
	}
	return false
}

// setCondition sets one condition, keeping its transition time when the status is unchanged.
func setSSHCondition(conds *[]metav1.Condition, generation int64, typ string, status metav1.ConditionStatus, reason, message string) {
	meta.SetStatusCondition(conds, metav1.Condition{
		Type: typ, Status: status, Reason: reason, Message: message, ObservedGeneration: generation,
	})
}

// sandboxBackends keeps the Services and Secrets of sandboxes: the backends and
// host keys that routes resolve.
func sandboxBackends() predicate.Predicate {
	return predicate.NewPredicateFuncs(func(o client.Object) bool {
		return o.GetLabels()[naming.LabelComponent] == naming.ComponentSandbox
	})
}

// gatewayRequests requests a reconcile of every SSHGateway.
func gatewayRequests(ctx context.Context, c client.Client) []reconcile.Request {
	list := &v1.SSHGatewayList{}
	if err := c.List(ctx, list); err != nil {
		logf.FromContext(ctx).Error(err, "Failed to list SSHGateways")
		return nil
	}
	reqs := make([]reconcile.Request, 0, len(list.Items))
	for i := range list.Items {
		reqs = append(reqs, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&list.Items[i])})
	}
	return reqs
}

// routeRequests requests a reconcile of every SSHRoute.
func routeRequests(ctx context.Context, c client.Client) []reconcile.Request {
	list := &v1.SSHRouteList{}
	if err := c.List(ctx, list); err != nil {
		logf.FromContext(ctx).Error(err, "Failed to list SSHRoutes")
		return nil
	}
	reqs := make([]reconcile.Request, 0, len(list.Items))
	for i := range list.Items {
		reqs = append(reqs, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&list.Items[i])})
	}
	return reqs
}
