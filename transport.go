package dat

import (
	"crypto/tls"
	"net/http"
)

const (
	TransportAuthRequestHeaderKey  = "Authorization"
	TransportAuthResponseHeaderKey = "WWW-Authenticate"
)

// The transport used for making requests
type Transport struct {
	// The header for this Transport
	Header *AuthResponseHeader

	// The password for this Transport
	Password string

	// The piggyback transport
	Transport *http.Transport

	// The username for this Transport
	Username string
}

// Create a new transport
func NewTransport(username, password string, verifySsl bool) *Transport {
	return &Transport{
		Password: password,
		Username: username,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: !verifySsl,
			},
		},
	}
}

// Create a new transport with the given transport
func NewTransportWithTransport(username, password string, tx *http.Transport) *Transport {
	return &Transport{
		Password:  password,
		Username:  username,
		Transport: tx,
	}
}

// Return the client that uses this transport
func (tx *Transport) Client() *http.Client {
	return &http.Client{Transport: tx}
}

// RoundTrip executes a single HTTP transaction, returning a Response for the
// provided Request.
func (tx *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Check to see if this transport is already authenticated
	if tx.Header != nil {
		// Increment the nonce
		tx.Header.IncrementNonce()

		// It is so add the auth header
		auth, err := tx.Header.GetResponseHeaderValue(
			tx.Username,
			tx.Password,
			req.Method,
			req.URL.Path,
			nil)

		if err != nil {
			return nil, err
		}

		// Add the header value
		req.Header.Set(TransportAuthRequestHeaderKey, auth)
	}

	// Try the request
	res, err := tx.Transport.RoundTrip(req)

	if err != nil {
		return nil, err
	}

	// Check if the request was unauthorized
	if res.StatusCode == http.StatusUnauthorized {
		tx.Header = nil

		// Create the auth header
		header, err := NewAuthResponseHeader(res.Header.Get(TransportAuthResponseHeaderKey))

		if err != nil {
			return nil, err
		}

		// Increment the nonce
		header.IncrementNonce()

		// Authenticate the request
		auth, err := header.GetResponseHeaderValue(
			tx.Username,
			tx.Password,
			req.Method,
			req.URL.Path,
			nil)

		if err != nil {
			return nil, err
		}

		// Add the header value
		req.Header.Set(TransportAuthRequestHeaderKey, auth)

		// Try the request again
		res, err := tx.Transport.RoundTrip(req)

		if err != nil {
			return nil, err
		}

		if res.StatusCode != http.StatusUnauthorized {
			tx.Header = header
		}

		return res, nil
	}

	return res, nil
}
