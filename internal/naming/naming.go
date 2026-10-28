// Package naming holds the names, label keys and annotations of the sshgateway
// operator. The integrating platform creates the backend Services and their
// host key Secrets; this operator serves the gateway in front of them. Changing
// a value here changes the contract with the platform.
package naming

// Labels and annotations.
const (
	LabelManagedBy = "app.kubernetes.io/managed-by"
	LabelComponent = "app.kubernetes.io/component"
	// ManagedBy is the value of LabelManagedBy on the objects this operator
	// writes. The gateway Deployment selects its pods by it, so a change needs
	// the gateway Deployments to be recreated.
	ManagedBy = "sshgateway"

	// LabelSSHGateway is set on the Pipes and the sshpiper objects of an
	// SSHGateway (value = SSHGateway name).
	LabelSSHGateway = "sshgateway.wutz.dev/ssh-gateway"
	// AnnotationSSHRoute is the namespace/name of the SSHRoute a Pipe serves.
	AnnotationSSHRoute = "sshgateway.wutz.dev/ssh-route"
	// AnnotationSSHRule is the index of the SSHRoute rule a Pipe serves.
	AnnotationSSHRule = "sshgateway.wutz.dev/ssh-rule"

	ComponentSSHGateway = "ssh-gateway"
)

// LiteralTrue is the string form of a boolean true in labels and annotations.
const LiteralTrue = "true"

// SSHIdentitySecretName is the Secret in the gateway namespace that holds the
// key the gateway uses to log in to backends. The operator creates it on first use.
const SSHIdentitySecretName = "sshgateway-identity"

// SSHHostKeySecret is the Secret of an SSH Service that holds the host key of
// the sshd behind it. The gateway pins that key from it.
func SSHHostKeySecret(service string) string { return service + "-hostkey" }

// SSHGatewayName is the name of the sshpiper Deployment, Service and
// ConfigMap of an SSHGateway.
func SSHGatewayName(gateway string) string { return "sshgateway-" + gateway }
