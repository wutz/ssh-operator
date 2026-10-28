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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/wutz/sshgateway/internal/naming"
	"github.com/wutz/sshgateway/pkg/sshgateway"
)

// Keys of the platform identity Secret. The gateway logs in to backends with
// the private key; backends accept the public key only.
const (
	sshPrivateKeyKey = "ssh-privatekey"
	sshPublicKeyKey  = "ssh-publickey"
)

// ensureSSHIdentity returns the platform identity Secret in namespace, generating
// its key pair on first use. The platform reads the public key from it, so the
// Secret is created by whichever of the two gets there first.
func ensureSSHIdentity(ctx context.Context, c client.Client, namespace string) (*corev1.Secret, error) {
	key := types.NamespacedName{Namespace: namespace, Name: naming.SSHIdentitySecretName}
	existing := &corev1.Secret{}
	err := c.Get(ctx, key, existing)
	if err == nil {
		return existing, nil
	}
	if !apierrors.IsNotFound(err) {
		return nil, err
	}
	priv, pub, err := sshgateway.GenerateEd25519()
	if err != nil {
		return nil, err
	}
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      naming.SSHIdentitySecretName,
			Labels: map[string]string{
				naming.LabelManagedBy: naming.ManagedBy,
				naming.LabelComponent: naming.ComponentSSHGateway,
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{sshPrivateKeyKey: priv, sshPublicKeyKey: []byte(pub + "\n")},
	}
	if err := c.Create(ctx, s); err != nil {
		if apierrors.IsAlreadyExists(err) {
			// Another reconcile created it first: its keys are the ones in use.
			if err := c.Get(ctx, key, existing); err != nil {
				return nil, err
			}
			return existing, nil
		}
		return nil, err
	}
	return s, nil
}
