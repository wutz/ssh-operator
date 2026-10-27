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

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// Condition types of the SSH gateway API. They follow the Gateway API naming.
const (
	// SSHConditionAccepted is set on SSHGatewayClasses, SSHGateways and the
	// parents of SSHRoutes once the object is valid and admitted.
	SSHConditionAccepted = "Accepted"
	// SSHConditionProgrammed is set on SSHGateways whose data plane is configured.
	SSHConditionProgrammed = "Programmed"
	// SSHConditionReady is set on SSHGateways whose data plane serves connections.
	SSHConditionReady = "Ready"
	// SSHConditionResolvedRefs is set on the parents of SSHRoutes whose
	// backends exist and carry a host key.
	SSHConditionResolvedRefs = "ResolvedRefs"
)

// Reasons of the SSH gateway conditions.
const (
	SSHReasonAccepted              = "Accepted"
	SSHReasonInvalid               = "Invalid"
	SSHReasonGatewayClassNotFound  = "GatewayClassNotFound"
	SSHReasonNotPlatformNamespace  = "NotPlatformNamespace"
	SSHReasonNoMatchingParent      = "NoMatchingParent"
	SSHReasonNotAllowedByListeners = "NotAllowedByListeners"
	SSHReasonInvalidAuthorizedKeys = "InvalidAuthorizedKeys"
	SSHReasonUsernameConflict      = "UsernameConflict"
	SSHReasonBackendNotFound       = "BackendNotFound"
	SSHReasonHostKeyNotFound       = "HostKeyNotFound"
	SSHReasonProgrammed            = "Programmed"
	SSHReasonPending               = "Pending"
	SSHReasonReady                 = "Ready"
	SSHReasonNotReady              = "NotReady"
)

// SSHListenerProtocol is the protocol a listener accepts.
// +kubebuilder:validation:Enum=SSH
type SSHListenerProtocol string

// SSHProtocol is the only protocol: SSH, with public-key authentication only.
const SSHProtocol SSHListenerProtocol = "SSH"

// RouteNamespacesFrom selects the namespaces whose SSHRoutes may attach.
// +kubebuilder:validation:Enum=Same;All;Selector
type RouteNamespacesFrom string

const (
	// RouteNamespacesSame admits routes from the gateway's namespace only.
	RouteNamespacesSame RouteNamespacesFrom = "Same"
	// RouteNamespacesAll admits routes from every namespace.
	RouteNamespacesAll RouteNamespacesFrom = "All"
	// RouteNamespacesSelector admits routes from namespaces matching a label selector.
	RouteNamespacesSelector RouteNamespacesFrom = "Selector"
)

// RouteNamespaces selects the namespaces an SSHGateway accepts routes from.
type RouteNamespaces struct {
	// from is Same (the default), All or Selector.
	// +kubebuilder:default=Same
	// +optional
	From RouteNamespacesFrom `json:"from,omitempty"`
	// selector matches the namespace labels when from is Selector.
	// +optional
	Selector *metav1.LabelSelector `json:"selector,omitempty"`
}

// AllowedRoutes says which SSHRoutes may attach to a listener.
type AllowedRoutes struct {
	// namespaces selects the namespaces the routes come from.
	// +optional
	Namespaces *RouteNamespaces `json:"namespaces,omitempty"`
}

// SSHListener is a port the gateway accepts SSH connections on.
type SSHListener struct {
	// name identifies the listener; SSHRoute parentRefs select it by sectionName.
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	// +kubebuilder:validation:MaxLength=63
	Name string `json:"name"`
	// port the gateway listens on.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +kubebuilder:default=2222
	Port int32 `json:"port"`
	// protocol of the listener. Only SSH is offered, and only public-key
	// authentication: passwords and keyboard-interactive logins are never
	// accepted.
	// +kubebuilder:default=SSH
	// +optional
	Protocol SSHListenerProtocol `json:"protocol,omitempty"`
	// allowedRoutes selects the routes that may attach. Defaults to Same.
	// +optional
	AllowedRoutes *AllowedRoutes `json:"allowedRoutes,omitempty"`
}

// SSHGatewaySpec defines the desired state of SSHGateway.
type SSHGatewaySpec struct {
	// gatewayClassName names the SSHGatewayClass that selects the controller.
	// +kubebuilder:validation:MinLength=1
	GatewayClassName string `json:"gatewayClassName"`
	// listeners of the gateway. sshpiperd serves one port, so exactly one.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=1
	Listeners []SSHListener `json:"listeners"`
	// serviceType exposes the gateway. LoadBalancer is the default.
	// +kubebuilder:validation:Enum=LoadBalancer;NodePort;ClusterIP
	// +kubebuilder:default=LoadBalancer
	// +optional
	ServiceType corev1.ServiceType `json:"serviceType,omitempty"`
}

// SSHListenerStatus is the observed state of a listener.
type SSHListenerStatus struct {
	// name of the listener.
	Name string `json:"name"`
	// attachedRoutes counts the routes accepted on the listener.
	AttachedRoutes int32 `json:"attachedRoutes"`
}

// SSHGatewayStatus defines the observed state of SSHGateway.
type SSHGatewayStatus struct {
	// addresses the gateway is reachable at, as host:port.
	// +optional
	Addresses []string `json:"addresses,omitempty"`
	// listeners reports the state of each listener.
	// +optional
	Listeners []SSHListenerStatus `json:"listeners,omitempty"`
	// conditions represent the current state of the SSHGateway.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=sgw,categories=forgeai
// +kubebuilder:printcolumn:name="Class",type=string,JSONPath=`.spec.gatewayClassName`
// +kubebuilder:printcolumn:name="Address",type=string,JSONPath=`.status.addresses[0]`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=='Ready')].status`

// SSHGateway is a platform entry point for SSH into project pods, modelled on
// the Gateway API Gateway. The operator runs sshpiperd for it; sshpiperd routes
// each connection by username to the SSHRoute that matches, and authenticates
// the client with the route's authorized keys.
//
// Gateways live in the platform namespace. Routes attach from project
// namespaces when the listener's allowedRoutes admits them.
type SSHGateway struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of SSHGateway
	// +required
	Spec SSHGatewaySpec `json:"spec"`

	// status defines the observed state of SSHGateway
	// +optional
	Status SSHGatewayStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// SSHGatewayList contains a list of SSHGateway
type SSHGatewayList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []SSHGateway `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &SSHGateway{}, &SSHGatewayList{})
		return nil
	})
}
