package sasl

import "errors"

var (
	errExternalAlreadyCompleted = errors.New("EXTERNAL authentication already completed")
	errExternalNotSupported     = errors.New("EXTERNAL has no supported QOP")
)

type externalClient struct {
	username []byte

	completed bool
}

// NewExternalClient creates a SASL External mechanism with optional authorization ID
func NewExternalClient(authorizationID []byte) (Client, error) {
	if len(authorizationID) == 0 {
		authorizationID = []byte{}
	}

	return &externalClient{
		username: authorizationID,
	}, nil
}

// EvaluateChallenge returns the EXTERNAL mechanism's initial response,
// which is the authorization id encoded in UTF-8. This is the optional
// information that is sent along with the SASL command
func (p *externalClient) EvaluateChallenge(challenge []byte) ([]byte, error) {
	if p.completed {
		return nil, errExternalAlreadyCompleted
	}

	p.completed = true
	return p.username, nil
}

// Wrap wraps the outcoming buffer.
func (p *externalClient) Wrap(data []byte) ([]byte, error) {
	return nil, errExternalNotSupported
}

// Unwrap unwraps the incoming buffer.
func (p *externalClient) Unwrap(data []byte) ([]byte, error) {
	return nil, errExternalNotSupported
}

// IsComplete returns whether the mechanism is complete
func (p *externalClient) IsComplete() bool {
	return p.completed
}

// Mechanism returns this mechanism's name
func (p *externalClient) Mechanism() string {
	return EXTERNAL
}

// HasInitialResponse returns whether mechanism has an initial response.
func (p *externalClient) HasInitialResponse() bool {
	return true
}
