package sasl

import "errors"

var (
	errDigestMd5AlreadyCompleted = errors.New("DigestMd5 authentication already completed")
	errDigestMd5NotSupported     = errors.New("DigestMd5 has no supported QOP")
)

type digestMD5Client struct {
	completed bool
}

// NewDigestMD5Client creates a SASL DigestMd5 mechanism with optional authorization ID
func NewDigestMD5Client() (Client, error) {
	return &digestMD5Client{}, nil
}

// EvaluateChallenge returns the DigestMd5 mechanism's initial response,
// which is the authorization id encoded in UTF-8. This is the optional
// information that is sent along with the SASL command
func (d *digestMD5Client) EvaluateChallenge(challenge []byte) ([]byte, error) {
	return nil, nil
}

// Wrap wraps the outcoming buffer.
func (d *digestMD5Client) Wrap(data []byte) ([]byte, error) {
	return nil, errDigestMd5NotSupported
}

// Unwrap unwraps the incoming buffer.
func (d *digestMD5Client) Unwrap(data []byte) ([]byte, error) {
	return nil, errDigestMd5NotSupported
}

// IsComplete returns whether the mechanism is complete
func (d *digestMD5Client) IsComplete() bool {
	return d.completed
}

// Mechanism returns this mechanism's name
func (d *digestMD5Client) Mechanism() string {
	return DIGEST_MD5
}

// HasInitialResponse returns whether mechanism has an initial response.
func (d *digestMD5Client) HasInitialResponse() bool {
	return true
}
