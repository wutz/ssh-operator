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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// ParentReference names the SSHGateway a route attaches to.
type ParentReference struct {
	// name of the SSHGateway.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// namespace of the SSHGateway. Defaults to the route's namespace.
	// +optional
	Namespace *string `json:"namespace,omitempty"`
	// sectionName is the listener of the gateway. Defaults to every listener.
	// +optional
	SectionName *string `json:"sectionName,omitempty"`
}

// SSHRouteMatch selects a connection by the username it logs in as.
type SSHRouteMatch struct {
	// username the client logs in as. The gateway routes on this name, so it
	// must be unique across the routes of a gateway.
	// +kubebuilder:validation:Pattern=`^[a-z_][a-z0-9_-]{0,31}$`
	Username string `json:"username"`
}

// SSHBackendRef is the Service a matched connection is forwarded to.
type SSHBackendRef struct {
	// name of the Service in the route's namespace that exposes an sshd. The
	// Secret <name>-hostkey holds the SSH host key of that sshd; the gateway pins it.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	Name string `json:"name"`
	// port of the sshd behind the Service. Defaults to 22.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +optional
	Port int32 `json:"port,omitempty"`
	// username is the account the gateway logs in to the backend as. The
	// backend must accept the platform identity key for it.
	// +kubebuilder:validation:Pattern="^[a-z_][a-z0-9_-]{0,31}$"
	Username string `json:"username"`
}

// SSHRouteRule forwards the connections of some usernames to a backend.
type SSHRouteRule struct {
	// matches are the usernames the rule answers to.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	Matches []SSHRouteMatch `json:"matches"`
	// authorizedKeys are the OpenSSH public keys allowed to log in as the
	// matched usernames. Passwords are never offered, so at least one key is
	// required. Keys with options (from=, command=) and certificates are
	// rejected.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=64
	AuthorizedKeys []string `json:"authorizedKeys"`
	// backendRefs is the backend. Exactly one is supported.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=1
	BackendRefs []SSHBackendRef `json:"backendRefs"`
}

// SSHRouteSpec defines the desired state of SSHRoute.
type SSHRouteSpec struct {
	// parentRefs are the gateways the route attaches to.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=8
	ParentRefs []ParentReference `json:"parentRefs"`
	// rules route the connections to their backends.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	Rules []SSHRouteRule `json:"rules"`
}

// RouteParentStatus is the status of a route on one parent gateway.
type RouteParentStatus struct {
	// parentRef is the gateway the status is about.
	ParentRef ParentReference `json:"parentRef"`
	// controllerName of the controller that wrote the status.
	ControllerName string `json:"controllerName"`
	// conditions represent the state of the route on the parent.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// SSHRouteStatus defines the observed state of SSHRoute.
type SSHRouteStatus struct {
	// parents reports the state of the route on each parent gateway.
	// +optional
	Parents []RouteParentStatus `json:"parents,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=sroute,categories=sshgateway

// SSHRoute attaches SSH connections to a backend Service in its namespace,
// modelled on the Gateway API routes. It lets an SSH client with one of the
// listed keys log in to the sshd behind the Service.
type SSHRoute struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of SSHRoute
	// +required
	Spec SSHRouteSpec `json:"spec"`

	// status defines the observed state of SSHRoute
	// +optional
	Status SSHRouteStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// SSHRouteList contains a list of SSHRoute
type SSHRouteList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []SSHRoute `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &SSHRoute{}, &SSHRouteList{})
		return nil
	})
}
