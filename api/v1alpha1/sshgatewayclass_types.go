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

// SSHGatewayControllerName is the controllerName of the SSHGatewayClass that
// the forgeai operator reconciles.
const SSHGatewayControllerName = "forgeai.wutz.dev/ssh-gateway"

// SSHGatewayClassSpec defines the controller of SSHGateways.
type SSHGatewayClassSpec struct {
	// controllerName identifies the controller that reconciles the SSHGateways
	// of this class, e.g. forgeai.wutz.dev/ssh-gateway.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	ControllerName string `json:"controllerName"`
	// description says what the class is for.
	// +kubebuilder:validation:MaxLength=256
	// +optional
	Description string `json:"description,omitempty"`
}

// SSHGatewayClassStatus defines the observed state of SSHGatewayClass.
type SSHGatewayClassStatus struct {
	// conditions represent the current state of the SSHGatewayClass.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=sgc,categories=forgeai
// +kubebuilder:printcolumn:name="Controller",type=string,JSONPath=`.spec.controllerName`
// +kubebuilder:printcolumn:name="Accepted",type=string,JSONPath=`.status.conditions[?(@.type=='Accepted')].status`

// SSHGatewayClass describes a class of SSH gateways and the controller that
// implements it, as the Gateway API GatewayClass does.
type SSHGatewayClass struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of SSHGatewayClass
	// +required
	Spec SSHGatewayClassSpec `json:"spec"`

	// status defines the observed state of SSHGatewayClass
	// +optional
	Status SSHGatewayClassStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// SSHGatewayClassList contains a list of SSHGatewayClass
type SSHGatewayClassList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []SSHGatewayClass `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &SSHGatewayClass{}, &SSHGatewayClassList{})
		return nil
	})
}
