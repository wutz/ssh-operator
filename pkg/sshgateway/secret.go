package sshgateway

// Keys of the Secret that holds the sshd keys of an SSH Service: the host key
// the gateway pins, and the platform key sshd accepts.
const (
	SSHHostKeyKey       = "ssh_host_ed25519_key"
	SSHAuthorizedKeyKey = "authorized_keys"
)

// DefaultGatewayImage is the sshpiper image that serves an SSHGateway when the
// operator is not given another one.
const DefaultGatewayImage = "ghcr.io/tg123/sshpiperd:v1.6.1"
