# ssh-operator

A Kubernetes operator that serves SSH gateways in front of sandboxes. An
`SSHGateway` runs [sshpiperd](https://github.com/tg123/sshpiperd) in the
cluster, and each `SSHRoute` rule becomes an sshpiperd `Pipe` that admits a
username with the listed public keys and forwards the session to the SSH
Service of a sandbox.

The API is modelled on the Gateway API: `SSHGatewayClass`, `SSHGateway` and
`SSHRoute`. The API group is `forgeai.wutz.dev/v1alpha1`, kept from the
[ForgeAI](https://github.com/wutz/forgeai) platform this operator was split
from, so existing manifests and platform code keep working.

## How it works

- **Gateway.** Each `SSHGateway` gets a Deployment, Service, ServiceAccount,
  Role and RoleBinding named `sshgateway-<name>`. The sshpiperd host key is
  generated once and kept in the Secret `sshgateway-<name>-hostkey`; clients
  pin it.
- **Routes.** Every rule of an `SSHRoute` becomes a sshpiper `Pipe` owned by
  its gateway. The Pipe accepts the keys in `authorizedKeys` for the listed
  usernames and forwards to the backend.
- **Backends.** A backend is the Service `<sandbox>-ssh` (port 22 by default)
  of a sandbox. Only Services owned by an agent-sandbox `Sandbox` are backends.
  The host key the sandbox presents is read from the Secret
  `<sandbox>-ssh-hostkey` (key `ssh_host_ed25519_key`), and the gateway pins it.
- **Login to sandboxes.** The gateway logs in to a sandbox as user `sandbox`
  with the platform identity key. The Secret `forgeai-ssh` in the platform
  namespace holds the key pair (`ssh-privatekey`, `ssh-publickey`). The
  operator creates it when it is missing; the sandbox must accept
  `ssh-publickey`.
- **Platform namespace.** Gateways are served in one namespace, set by
  `--platform-namespace` (default `forgeai-system`). Only one `SSHGateway` may
  serve it; a second one is rejected.

Forwarding is restricted: sshpiperd runs with `--disable-local-forwarding` and
`--disable-remote-forwarding`, as non-root, with all capabilities dropped. Only
key authentication is accepted; there are no passwords.

## Requirements

- Kubernetes with the sshpiper `Pipe` CRD (`pipes.sshpiper.com`, v1beta1)
  installed. The CRD is in [`internal/controller/testdata/crds/pipes.sshpiper.com.yaml`](internal/controller/testdata/crds/pipes.sshpiper.com.yaml).
  Without it the operator starts, logs `sshpiper Pipe CRD is not installed; the
  SSH gateway controllers are off`, and leaves gateways and routes without status.
- Backends are created by the platform (for ForgeAI, sandboxes of the
  agent-sandbox controller with an sshd sidecar on port 22).

## Install

The chart is published as an OCI artifact:

```bash
helm install ssh-operator oci://ghcr.io/wutz/charts/ssh-operator \
  --version 0.1.0 \
  --namespace ssh-operator-system --create-namespace \
  --set platform.namespace=forgeai-system
```

Values:

| Value | Default | Meaning |
|---|---|---|
| `manager.image.repository` | `ghcr.io/wutz/ssh-operator` | Operator image |
| `platform.namespace` | `forgeai-system` | Namespace the gateways are served in |
| `gateway.image` | `ghcr.io/tg123/sshpiperd:v1.6.1` | sshpiperd image of each gateway |
| `crd.keep` | `true` | Keep the CRDs on uninstall |

The operator's RBAC is cluster-wide (`ClusterRole`). It watches Services and
Secrets in all namespaces to find sandbox backends and writes host-key Secrets
in the gateway's namespace.

## Usage

```yaml
apiVersion: forgeai.wutz.dev/v1alpha1
kind: SSHGatewayClass
metadata:
  name: forgeai-ssh
spec:
  controllerName: forgeai.wutz.dev/ssh-gateway
---
apiVersion: forgeai.wutz.dev/v1alpha1
kind: SSHGateway
metadata:
  name: main
  namespace: forgeai-system
spec:
  gatewayClassName: forgeai-ssh
  listeners:
    - name: ssh
      port: 2222
      allowedRoutes:
        namespaces:
          from: All
  serviceType: ClusterIP
---
apiVersion: forgeai.wutz.dev/v1alpha1
kind: SSHRoute
metadata:
  name: agent-login
  namespace: forge-demo
spec:
  parentRefs:
    - name: main
  rules:
    - matches:
        - username: alice
      authorizedKeys:
        - ssh-ed25519 AAAA... alice@example.com
      backendRefs:
        - name: agent
```

Samples are in [`config/samples`](config/samples).

- A username is claimed by the first route that matches it, so keep login names
  unique across the cluster.
- `allowedRoutes` defaults to `Same`: only routes of the gateway's namespace
  attach.
- `status.parents` on an `SSHRoute` reports the `Accepted` and `ResolvedRefs`
  conditions. `status.conditions` on an `SSHGateway` reports `Accepted`,
  `Programmed` and `Ready`.

## Configuration

| Flag | Default | Meaning |
|---|---|---|
| `--platform-namespace` | `forgeai-system` | Namespace the gateways are served in and that holds the `forgeai-ssh` identity Secret |
| `--gateway-image` | `ghcr.io/tg123/sshpiperd:v1.6.1` | sshpiperd image of each gateway |
| `--leader-elect` | `false` | Leader election (lease `sshoperator.wutz.dev`) |
| `--metrics-bind-address` | `0` | Metrics endpoint; `:8443` for HTTPS |
| `--health-probe-bind-address` | `:8081` | Health and readiness probes |

## Development

```bash
make help                  # all targets
make manifests generate    # regenerate CRDs, RBAC and deepcopy after editing *_types.go or markers
make test                  # unit and controller tests (envtest: real API server and etcd)
make lint                  # golangci-lint
make run                   # run the operator against the current kubeconfig
make docker-build IMG=ghcr.io/wutz/ssh-operator:dev
make deploy IMG=ghcr.io/wutz/ssh-operator:dev   # Kustomize install
make helm-lint             # lint and render the chart
make helm-package CHART_VERSION=0.1.0           # package into dist/
```

`make test-e2e` runs the end-to-end tests against a dedicated
[kind](https://kind.sigs.k8s.io/) cluster; do not point it at a shared cluster.

## Releases

Pushing a `v<major>.<minor>.<patch>` tag runs
[`.github/workflows/release.yml`](.github/workflows/release.yml), which publishes:

- `ghcr.io/wutz/ssh-operator:<version>` (linux/amd64 and linux/arm64)
- `oci://ghcr.io/wutz/charts/ssh-operator:<version>`

## License

Apache License 2.0. See [LICENSE](LICENSE).
