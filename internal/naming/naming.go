// Package naming holds the names, label keys and annotations that the SSH
// operator shares with the forgeai platform. The platform creates the sandboxes
// and their SSH Services; this operator serves the gateway in front of them.
// Changing a value here changes the contract with the platform.
package naming

// Labels and annotations.
const (
	LabelManagedBy = "app.kubernetes.io/managed-by"
	LabelComponent = "app.kubernetes.io/component"
	// ManagedBy is the value of LabelManagedBy on the objects this operator
	// writes. It is kept from the forgeai platform so that a gateway written
	// before the split keeps its Deployment selector.
	ManagedBy = "forgeai"

	// LabelSandbox is set on the pods of a sandbox (value = Sandbox name).
	LabelSandbox = "forgeai.wutz.dev/sandbox"
	// LabelSSHGateway is set on the Pipes and the sshpiperd objects of an
	// SSHGateway (value = SSHGateway name).
	LabelSSHGateway = "forgeai.wutz.dev/ssh-gateway"
	// AnnotationSSHRoute is the namespace/name of the SSHRoute a Pipe serves.
	AnnotationSSHRoute = "forgeai.wutz.dev/ssh-route"
	// AnnotationSSHRule is the index of the SSHRoute rule a Pipe serves.
	AnnotationSSHRule = "forgeai.wutz.dev/ssh-rule"

	ComponentSandbox    = "sandbox"
	ComponentSSHGateway = "ssh-gateway"
)

// LiteralTrue is the string form of a boolean true in labels and annotations.
const LiteralTrue = "true"

// SSHIdentitySecretName is the Secret in the platform namespace that holds the
// key the gateway uses to log in to sandboxes. The platform creates it.
const SSHIdentitySecretName = "forgeai-ssh"

// SSHHostKeySecret is the Secret of an SSH Service that holds the host key of
// the sshd behind it. The gateway pins that key from it.
func SSHHostKeySecret(service string) string { return service + "-hostkey" }

// SSHServiceName is the Service that exposes the sshd of a sandbox.
func SSHServiceName(sandbox string) string { return sandbox + "-ssh" }

// SSHGatewayName is the name of the sshpiperd Deployment, Service and
// ConfigMap of an SSHGateway.
func SSHGatewayName(gateway string) string { return "sshgateway-" + gateway }
