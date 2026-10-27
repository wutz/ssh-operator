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

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// fieldOwner is the field manager of the objects this operator applies.
const fieldOwner = client.FieldOwner("ssh-operator")

// apply server-side applies obj (typed or unstructured) as the operator's field owner.
func apply(ctx context.Context, c client.Client, obj client.Object) error {
	u := &unstructured.Unstructured{}
	if uo, ok := obj.(*unstructured.Unstructured); ok {
		u = uo
	} else {
		m, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
		if err != nil {
			return err
		}
		u.Object = m
		gvk, err := c.GroupVersionKindFor(obj)
		if err != nil {
			return err
		}
		u.SetGroupVersionKind(gvk)
	}
	unstructured.RemoveNestedField(u.Object, "metadata", "creationTimestamp")
	unstructured.RemoveNestedField(u.Object, "status")
	return c.Apply(ctx, client.ApplyConfigurationFromUnstructured(u), fieldOwner, client.ForceOwnership)
}
