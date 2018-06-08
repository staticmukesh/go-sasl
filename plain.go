package sasl

import "errors"

var (
	errPlainMissingCredentials = errors.New("PLAIN authorization ID and password must be specified")
	errPlainAlreadyCompleted   = errors.New("PLAIN authentication already completed")
	errPlainNotSupported       = errors.New("PLAIN supports neither integrity nor privacy")
)

type plainClient struct {
	password         []byte
	authenticationID []byte
	authorizationID  []byte

	completed bool
	separator byte
}

// NewPlainClient creates a SASL mechanism with client credentials that
// it needs to participate in Plain authentication exchange with the server.
func NewPlainClient(authenticationID []byte, authorizationID []byte, password []byte) (Client, error) {
	if len(authenticationID) == 0 || len(password) == 0 {
		return nil, errPlainMissingCredentials
	}

	return &plainClient{
		authenticationID: authenticationID,
		authorizationID:  authorizationID,
		password:         password,
	}, nil
}

// Retrieves the initial response for the SASL command, which for PLAIN is
// the concatenation of authorization ID, authentication ID and password,
// with each component separated by the US-ASCII <NUL> byte.
func (p *plainClient) EvaluateChallenge(challenge []byte) ([]byte, error) {
	if p.completed {
		return nil, errPlainAlreadyCompleted
	}

	resp := []byte{}

	if p.authorizationID != nil {
		resp = append(resp, p.authorizationID...)
		resp = append(resp, p.separator)
	}

	resp = append(resp, p.authenticationID...)
	resp = append(resp, p.separator)
	resp = append(resp, p.password...)

	return resp, nil
}

// Wrap wraps the outcoming buffer.
func (p *plainClient) Wrap(data []byte) ([]byte, error) {
	return nil, errPlainNotSupported
}

// Unwrap unwraps the incoming buffer.
func (p *plainClient) Unwrap(data []byte) ([]byte, error) {
	return nil, errPlainNotSupported
}

func (p *plainClient) IsComplete() bool {
	return p.completed
}

func (p *plainClient) Mechanism() string {
	return "PLAIN"
}

func (p *plainClient) HasInitialResponse() bool {
	return true
}
