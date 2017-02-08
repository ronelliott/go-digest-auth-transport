package dat

import (
	"crypto/md5"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

const (
	AuthResponseHeaderModeBasic           = "Basic"
	AuthResponseHeaderModeDigest          = "Digest"
	AuthResponseHeaderAlgorithmMD5        = "MD5"
	AuthResponseHeaderAlgorithmMD5Session = "MD5-sess"
	AuthResponseHeaderQopAuth             = "auth"
	AuthResponseHeaderQopAuthInt          = "auth-int"
)

// The authentication header
type AuthResponseHeader struct {
	// The algorithm for this AuthResponseHeader
	Algorithm string

	// A flag for if this header is a basic auth header
	IsBasicAuth bool

	// The nonce value for this AuthResponseHeader
	Nonce string

	// The opaque value for this AuthResponseHeader
	Opaque string

	// The realm value for this AuthResponseHeader
	Realm string

	// The stale value for this AuthResponseHeader
	Stale bool

	// The qop value for this AuthResponseHeader
	Qop string
}

// Create a new AuthResponseHeader from the given string
func NewAuthResponseHeader(raw string) (*AuthResponseHeader, error) {
	if raw == "" {
		return nil, errors.New("Empty header given")
	}

	header := &AuthResponseHeader{}
	chunks := strings.SplitN(raw, " ", 2)
	mode := chunks[0]

	switch mode {
	case AuthResponseHeaderModeBasic:
		header.IsBasicAuth = true
	case AuthResponseHeaderModeDigest:
	default:
		return nil, errors.New("Unknown mode: " + mode)
	}

	values := header.parseHeader(chunks[1])
	header.Algorithm = values["algorithm"]
	header.Nonce = values["nonce"]
	header.Opaque = values["opaque"]
	header.Realm = values["realm"]
	header.Stale = values["stale"] != "false"
	header.Qop = values["qop"]

	return header, nil
}

// Return the md5 sum for the given string
func (header *AuthResponseHeader) md5Sum(in string) string {
	return header.md5SumBytes([]byte(in))
}

// Return the md5 sum for the given string
func (header *AuthResponseHeader) md5SumBytes(in []byte) string {
	return fmt.Sprintf("%x", md5.Sum(in))
}

// Parse the given digest header
func (header *AuthResponseHeader) parseHeader(raw string) map[string]string {
	out := map[string]string{}
	chunks := strings.Split(raw, ",")

	for _, chunk := range chunks {
		values := strings.Split(chunk, "=")
		key := values[0]
		var value string

		if len(values) > 1 {
			value = values[1]
		}

		valueLen := len(value)
		if strings.Index(value, "\"") == 0 &&
			strings.LastIndex(value, "\"") == valueLen-1 {
			value = value[1 : valueLen-1]
		}

		out[key] = value
	}

	return out
}

// Increments the current nonce in the global NonceCountMap
func (header *AuthResponseHeader) IncrementNonce() {
	NoncesIncrement(header.Nonce)
}

// Returns true if the algorithm is MD5
func (header *AuthResponseHeader) IsAlgorithmMD5() bool {
	return strings.ToLower(header.Algorithm) == strings.ToLower(AuthResponseHeaderAlgorithmMD5)
}

// Returns true if the algorithm is MD5-sess
func (header *AuthResponseHeader) IsAlgorithmMD5Session() bool {
	return strings.ToLower(header.Algorithm) == strings.ToLower(AuthResponseHeaderAlgorithmMD5Session)
}

// Returns true if the algorithm is unspecified
func (header *AuthResponseHeader) IsAlgorithmUnspecified() bool {
	return header.Algorithm == ""
}

// Returns true if the qop is auth
func (header *AuthResponseHeader) IsQoPAuth() bool {
	return strings.ToLower(header.Qop) == strings.ToLower(AuthResponseHeaderQopAuth)
}

// Returns true if the qop is auth-int
func (header *AuthResponseHeader) IsQoPAuthInt() bool {
	return strings.ToLower(header.Qop) == strings.ToLower(AuthResponseHeaderQopAuthInt)
}

// Returns true if the qop is unspecified
func (header *AuthResponseHeader) IsQoPUnspecified() bool {
	return header.Qop == ""
}

// Get the HA1 value for this header
func (header *AuthResponseHeader) GetA1Value(username, password, clientNonce string) string {
	out := header.md5Sum(fmt.Sprintf("%v:%v:%v", username, header.Realm, password))

	if header.IsAlgorithmMD5Session() {
		out = header.md5Sum(fmt.Sprintf("%v:%v:%v", out, header.Nonce, clientNonce))
	}

	return out
}

// Get the HA2 value for this header
func (header *AuthResponseHeader) GetA2Value(method, url string, body []byte) string {
	in := fmt.Sprintf("%v:%v", method, url)

	if header.IsQoPAuthInt() {
		in = fmt.Sprintf(":%v", header.md5SumBytes(body))
	}

	return header.md5Sum(in)
}

// Get the Response value for this header
func (header *AuthResponseHeader) GetResponseValue(
	a1,
	a2,
	clientNonce string,
	nonceCount int) string {

	in := ""

	if !header.IsQoPUnspecified() {
		in = fmt.Sprintf("%v:%v:%v:%v:%v:%v",
			a1,
			header.Nonce,
			fmt.Sprintf("%08d", nonceCount),
			clientNonce,
			header.Qop,
			a2)
	} else {
		in = fmt.Sprintf("%v:%v:%v", a1, header.Nonce, a2)
	}

	return header.md5Sum(in)
}

// Get the response header value
func (header *AuthResponseHeader) GetResponseHeaderValue(
	username,
	password,
	method,
	url string,
	body []byte) (string, error) {

	out := ""

	if header.IsBasicAuth {
		hash := base64.StdEncoding.EncodeToString(
			[]byte(fmt.Sprintf("%s:%s", username, password)))
		out = fmt.Sprintf("Basic ", hash)
	} else {

		clientNonce, err := RandHexStr(8)

		if err != nil {
			return "", err
		}

		a1 := header.GetA1Value(username, password, clientNonce)
		a2 := header.GetA2Value(method, url, body)
		nonceCount := NoncesCount(header.Nonce)
		response := header.GetResponseValue(a1, a2, clientNonce, nonceCount)

		out = fmt.Sprintf(
			"Digest username=\"%s\",response=\"%s\",algorithm=\"%s\",nc=%08d,cnonce=\"%s\",uri=\"%s\"",
			username,
			response,
			header.Algorithm,
			nonceCount,
			clientNonce,
			url)

		if header.Nonce != "" {
			out = fmt.Sprintf("%s,nonce=\"%s\"", out, header.Nonce)
		}

		if header.Opaque != "" {
			out = fmt.Sprintf("%s,opaque=\"%s\"", out, header.Opaque)
		}

		if header.Qop != "" {
			out = fmt.Sprintf("%s,qop=%s", out, header.Qop)
		}

		if header.Realm != "" {
			out = fmt.Sprintf("%s,realm=\"%s\"", out, header.Realm)
		}
	}

	return out, nil
}
