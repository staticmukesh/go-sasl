package sasl

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"strconv"
	"strings"
)

var (
	errDigestMd5AlreadyCompleted = errors.New("DigestMd5 authentication already completed")
	errDigestMd5NotSupported     = errors.New("DigestMd5 has no supported QOP")
)

type digestMD5Client struct {
	step      int
	completed bool
}

// NewDigestMD5Client creates a SASL DigestMd5 mechanism with optional authorization ID
func NewDigestMD5Client() (Client, error) {
	return &digestMD5Client{
		step: 1,
	}, nil
}

// EvaluateChallenge returns the DigestMd5 mechanism's initial response,
// which is the authorization id encoded in UTF-8. This is the optional
// information that is sent along with the SASL command
func (d *digestMD5Client) EvaluateChallenge(challenge []byte) ([]byte, error) {
	switch d.step {
	case 1:
		d.step++
		return nil, nil
	case 2:
		d.step++
		return nil, nil
	case 3:
		d.step++
		return nil, nil
	default:
		return nil, errDigestMd5AlreadyCompleted
	}
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

func a1(username, realm, password, serverNonce, clientNonce, authorizationID string) [md5.Size]byte {
	x := strings.Join([]string{
		username,
		realm,
		password,
	}, ":")

	y := md5.Sum([]byte(x))

	a1Values := []string{
		string(y[:]),
		serverNonce,
		clientNonce,
	}

	if len(authorizationID) != 0 {
		a1Values = append(a1Values, authorizationID)
	}

	a1 := strings.Join(a1Values, ":")

	return md5.Sum([]byte(a1))
}

func a2(digestURI, qop string) [md5.Size]byte {
	a2 := strings.Join([]string{
		"AUTHENTICATE",
		digestURI,
	}, ":")

	if qop == "auth-conf" {
		a2 = a2 + ":00000000000000000000000000000000"
	}

	return md5.Sum([]byte(a2))
}

// kic, kis
func generateIntegrityKeyPair(data [md5.Size]byte) ([md5.Size]byte, [md5.Size]byte) {
	CLIENT_INT_MAGIC := []byte("Digest session key to client-to-server signing key magic constant")
	SERVER_INT_MAGIC := []byte("Digest session key to server-to-client signing key magic constant")

	kic := md5.Sum(append(data[:], CLIENT_INT_MAGIC...))
	kis := md5.Sum(append(data[:], SERVER_INT_MAGIC...))

	return kic, kis
}

// kcc, kcs
func generatePrivacyKeyPair(data [md5.Size]byte) ([md5.Size]byte, [md5.Size]byte) {
	CLIENT_CONF_MAGIC := []byte("Digest H(A1) to client-to-server sealing key magic constant")
	SERVER_CONF_MAGIC := []byte("Digest H(A1) to server-to-client sealing key magic constant")

	kcc := md5.Sum(append(data[:], CLIENT_CONF_MAGIC...))
	kcs := md5.Sum(append(data[:], SERVER_CONF_MAGIC...))

	return kcc, kcs
}

func getHMAC(key, seq, msg []byte) []byte {
	data := append(seq, msg...)

	mac := hmac.New(md5.New, key)
	mac.Write(data)

	hash := mac.Sum(nil)

	return hash[0:10]
}

func addDESParity(input []byte) []byte {
	result := make([]byte, 8)

	in := bytesToInt(input)
	mask := bytesToInt([]byte{0, 0, 0, 0, 0, 127})

	for i := 7; i >= 0; i-- {
		buf := new(bytes.Buffer)
		binary.Write(buf, binary.LittleEndian, in&mask)

		//last byte
		b := buf.Bytes()[0]
		//shift byte
		n := int8(b) << 1
		//shift integer to right by 7
		in = in >> 7
		result[i] = byte(n)
	}

	return setParity(result)
}

func setParity(key []byte) []byte {
	output := []byte{}
	for _, k := range key {
		b := k & 0xFE
		b = b | byte(bitCount(b)&1) ^ 1
		output = append(output, b)
	}

	return output
}

func bitCount(b byte) int {
	bs := strconv.FormatInt(int64(b), 2)
	return strings.Count(bs, "1")
}

func bytesToInt(b []byte) int64 {
	return int64(uint(b[6]) | uint(b[5])<<8 | uint(b[4])<<16 | uint(b[3])<<24 | uint(b[2])<<32 | uint(b[1])<<40 | uint(b[0])<<48)
}
