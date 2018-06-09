package sasl

import (
	"strings"
)

const (
	// PLAIN represents plain mechanism
	PLAIN = "plain"
	// EXTERNAL represents external mechanism
	EXTERNAL = "external"
	// DIGEST_MD5 represents digest-md5 mechanism
	DIGEST_MD5 = "digest-md5"
)

// Client is SASL client interface
type Client interface {
	EvaluateChallenge([]byte) ([]byte, error)
	Wrap([]byte) ([]byte, error)
	Unwrap([]byte) ([]byte, error)
	IsComplete() bool
	Mechanism() string
	HasInitialResponse() bool
}

// Options represent SASL client options. Different mechanims have different required fields
type Options struct {
	AuthorizationID  []byte
	AuthenticationID []byte
	Password         []byte
}

// NewClient creates new SASL client
func NewClient(mech string, options Options) (Client, error) {
	switch strings.ToLower(mech) {
	case PLAIN:
		return NewPlainClient(options.AuthenticationID, options.AuthorizationID, options.Password)
	case EXTERNAL:
		return NewExternalClient(options.AuthorizationID)
	case DIGEST_MD5:
		return NewDigestMD5Client()
	default:
		return NewExternalClient(options.AuthorizationID)
	}
}
