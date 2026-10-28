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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v1alpha1 "github.com/wutz/sshgateway/api/v1alpha1"
	"github.com/wutz/sshgateway/pkg/sshgateway"
)

// SSHRouteReconciler reports, for each parent gateway of an SSHRoute, whether the
// gateway accepted the route and whether its backends resolve. The gateway
// reconciler writes the routes themselves.
type SSHRouteReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	// GatewayNamespace is where SSHGateways are served.
	GatewayNamespace string
}

// +kubebuilder:rbac:groups=sshgateway.wutz.dev,resources=sshroutes,verbs=get;list;watch
// +kubebuilder:rbac:groups=sshgateway.wutz.dev,resources=sshroutes/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=sshgateway.wutz.dev,resources=sshroutes/finalizers,verbs=update

// Reconcile writes the status of the route on each parent gateway of this
// controller. Statuses of other controllers are kept.
func (r *SSHRouteReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	route := &v1alpha1.SSHRoute{}
	if err := r.Get(ctx, req.NamespacedName, route); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !route.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	plans := map[types.NamespacedName]sshgateway.Plan{}
	var ours []v1alpha1.RouteParentStatus
	for _, ref := range route.Spec.ParentRefs {
		v, err := resolveParent(ctx, r.Client, r.GatewayNamespace, route, ref)
		if err != nil {
			return ctrl.Result{}, err
		}
		if !v.managed {
			continue
		}
		ps := v1alpha1.RouteParentStatus{
			ParentRef:      ref,
			ControllerName: v1alpha1.SSHGatewayControllerName,
		}
		if v.reason != "" {
			setSSHCondition(&ps.Conditions, route.Generation, v1alpha1.SSHConditionAccepted,
				metav1.ConditionFalse, v.reason, v.message)
			ours = append(ours, ps)
			continue
		}
		plan, ok := plans[v.gateway]
		if !ok {
			plan, _, err = planSSHGateway(ctx, r.Client, r.GatewayNamespace, v.gw)
			if err != nil {
				return ctrl.Result{}, err
			}
			plans[v.gateway] = plan
		}
		routeConditions(&ps.Conditions, route.Generation, plan.Problems[route.Namespace+"/"+route.Name])
		ours = append(ours, ps)
	}

	orig := route.DeepCopy()
	route.Status.Parents = mergeParents(route.Status.Parents, ours)
	return ctrl.Result{}, r.Status().Patch(ctx, route, client.MergeFrom(orig))
}

// routeConditions sets the Accepted and ResolvedRefs conditions of a route
// attached to a gateway, given the problem the plan found with it, if any.
func routeConditions(conds *[]metav1.Condition, gen int64, problem sshgateway.Problem) {
	switch problem.Reason {
	case "":
		setSSHCondition(conds, gen, v1alpha1.SSHConditionAccepted, metav1.ConditionTrue,
			v1alpha1.SSHReasonAccepted, "the route is attached to the gateway")
		setSSHCondition(conds, gen, v1alpha1.SSHConditionResolvedRefs, metav1.ConditionTrue,
			sshReasonResolvedRefs, "the backends and their host keys resolve")
	case sshgateway.ReasonBackendNotFound, sshgateway.ReasonHostKeyNotFound:
		setSSHCondition(conds, gen, v1alpha1.SSHConditionAccepted, metav1.ConditionTrue,
			v1alpha1.SSHReasonAccepted, "the route is attached to the gateway")
		setSSHCondition(conds, gen, v1alpha1.SSHConditionResolvedRefs, metav1.ConditionFalse,
			problem.Reason, problem.Message)
	default:
		setSSHCondition(conds, gen, v1alpha1.SSHConditionAccepted, metav1.ConditionFalse,
			problem.Reason, problem.Message)
		setSSHCondition(conds, gen, v1alpha1.SSHConditionResolvedRefs, metav1.ConditionTrue,
			sshReasonResolvedRefs, "the backends and their host keys resolve")
	}
}

// mergeParents replaces the statuses this controller wrote with ours, keeping
// the ones written by other controllers.
func mergeParents(existing, ours []v1alpha1.RouteParentStatus) []v1alpha1.RouteParentStatus {
	out := make([]v1alpha1.RouteParentStatus, 0, len(existing)+len(ours))
	for _, p := range existing {
		if p.ControllerName != v1alpha1.SSHGatewayControllerName {
			out = append(out, p)
		}
	}
	return append(out, ours...)
}

// SetupWithManager watches the routes and everything they are planned from:
// gateways, classes, namespaces (for selectors) and the backend Services and
// host key Secrets that routes name.
func (r *SSHRouteReconciler) SetupWithManager(mgr ctrl.Manager) error {
	all := func(ctx context.Context, _ client.Object) []reconcile.Request {
		return routeRequests(ctx, mgr.GetClient())
	}
	backend := func(ctx context.Context, obj client.Object) []reconcile.Request {
		return backendRequests(ctx, mgr.GetClient(), obj)
	}
	return ctrl.NewControllerManagedBy(mgr).
		Named("sshroute").
		For(&v1alpha1.SSHRoute{}).
		Watches(&v1alpha1.SSHGateway{}, handler.EnqueueRequestsFromMapFunc(all)).
		Watches(&v1alpha1.SSHGatewayClass{}, handler.EnqueueRequestsFromMapFunc(all)).
		Watches(&corev1.Namespace{}, handler.EnqueueRequestsFromMapFunc(all)).
		Watches(&corev1.Service{}, handler.EnqueueRequestsFromMapFunc(backend)).
		Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(backend)).
		Complete(r)
}
