package sasl

// Client is SASL client interface
type Client interface {
	EvaluateChallenge([]byte) ([]byte, error)
	Wrap([]byte) ([]byte, error)
	Unwrap([]byte) ([]byte, error)
	IsComplete() bool
	Mechanism() string
	HasInitialResponse() bool
}
