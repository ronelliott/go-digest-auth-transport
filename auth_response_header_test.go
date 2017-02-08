package dat

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// Test values from: https://en.wikipedia.org/wiki/Digest_access_authentication

const (
	RawAuthReponseHeaderValues  = "nonce=\"nonce123\",algorithm=\"MD5\",realm=\"example.com\",qop=\"auth\",opaque=\"opaque123\",stale=\"true\""
	RawAuthReponseHeader        = "Digest " + RawAuthReponseHeaderValues
	RawAuthReponseHeaderExample = "Digest realm=\"testrealm@host.com\",qop=\"auth\",nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\""
)

func TestNewAuthResponseHeader(t *testing.T) {
	header, err := NewAuthResponseHeader(RawAuthReponseHeader)
	require.Nil(t, err)
	require.NotNil(t, header)
	require.Equal(t, "MD5", header.Algorithm)
	require.Equal(t, "nonce123", header.Nonce)
	require.Equal(t, "opaque123", header.Opaque)
	require.Equal(t, "auth", header.Qop)
	require.Equal(t, "example.com", header.Realm)
	require.True(t, header.Stale)
}

func TestNewAuthResponseHeader_EmptyHeader(t *testing.T) {
	header, err := NewAuthResponseHeader("")
	require.Nil(t, header)
	require.NotNil(t, err)
	require.Equal(t, "Empty header given", err.Error())
}

func TestNewAuthResponseHeader_InvalidMode(t *testing.T) {
	header, err := NewAuthResponseHeader("Foo " + RawAuthReponseHeaderValues)
	require.Nil(t, header)
	require.NotNil(t, err)
	require.Equal(t, "Unknown mode: Foo", err.Error())
}

func TestAuthResponseHeader_md5Sum(t *testing.T) {
	require.Equal(t,
		"acbd18db4cc2f85cedef654fccc4a4d8",
		(&AuthResponseHeader{}).md5Sum("foo"))
}

func TestAuthResponseHeader_md5SumBytes(t *testing.T) {
	require.Equal(t,
		"acbd18db4cc2f85cedef654fccc4a4d8",
		(&AuthResponseHeader{}).md5SumBytes([]byte("foo")))
}

func TestAuthResponseHeader_parseDigestHeader(t *testing.T) {
	require.Equal(t, map[string]string{
		"algorithm": "MD5",
		"nonce":     "nonce123",
		"opaque":    "opaque123",
		"qop":       "auth",
		"realm":     "example.com",
		"stale":     "true",
	}, (&AuthResponseHeader{}).parseDigestHeader(RawAuthReponseHeaderValues))
}

func TestAuthResponseHeader_IsAlgorithmMD5(t *testing.T) {
	require.False(t, (&AuthResponseHeader{
		Algorithm: "MD5-sess",
	}).IsAlgorithmMD5())

	require.True(t, (&AuthResponseHeader{
		Algorithm: "MD5",
	}).IsAlgorithmMD5())
}

func TestAuthResponseHeader_IsAlgorithmMD5Session(t *testing.T) {
	require.False(t, (&AuthResponseHeader{
		Algorithm: "MD5",
	}).IsAlgorithmMD5Session())

	require.True(t, (&AuthResponseHeader{
		Algorithm: "MD5-sess",
	}).IsAlgorithmMD5Session())
}

func TestAuthResponseHeader_IsAlgorithmUnspecified(t *testing.T) {
	require.False(t, (&AuthResponseHeader{
		Algorithm: "MD5",
	}).IsAlgorithmUnspecified())

	require.True(t, (&AuthResponseHeader{
		Algorithm: "",
	}).IsAlgorithmUnspecified())
}

func TestAuthResponseHeader_IsQoPAuth(t *testing.T) {
	require.False(t, (&AuthResponseHeader{
		Qop: "auth-int",
	}).IsQoPAuth())

	require.True(t, (&AuthResponseHeader{
		Qop: "auth",
	}).IsQoPAuth())
}

func TestAuthResponseHeader_IsQoPAuthInt(t *testing.T) {
	require.False(t, (&AuthResponseHeader{
		Qop: "auth",
	}).IsQoPAuthInt())

	require.True(t, (&AuthResponseHeader{
		Qop: "auth-int",
	}).IsQoPAuthInt())
}

func TestAuthResponseHeader_IsQoPUnspecified(t *testing.T) {
	require.False(t, (&AuthResponseHeader{
		Qop: "auth",
	}).IsQoPUnspecified())

	require.True(t, (&AuthResponseHeader{
		Qop: "",
	}).IsQoPUnspecified())
}

func TestAuthResponseHeader_GetA1Value(t *testing.T) {
	require.Equal(t, "939e7578ed9e3c518a452acee763bce9", (&AuthResponseHeader{
		Realm: "testrealm@host.com",
		Qop:   AuthResponseHeaderQopAuth,
	}).GetA1Value("Mufasa", "Circle Of Life", ""))
}

func TestAuthResponseHeader_GetA2Value(t *testing.T) {
	require.Equal(t, "39aff3a2bab6126f332b942af96d3366", (&AuthResponseHeader{
		Qop: AuthResponseHeaderQopAuth,
	}).GetA2Value(http.MethodGet, "/dir/index.html", nil))
}

func TestAuthResponseHeader_GetResponseValue(t *testing.T) {
	header := &AuthResponseHeader{
		Nonce: "dcd98b7102dd2f0e8b11d0f600bfb0c093",
		Qop:   AuthResponseHeaderQopAuth,
		Realm: "testrealm@host.com",
	}

	require.Equal(t,
		"6629fae49393a05397450978507c4ef1",
		header.GetResponseValue(
			"939e7578ed9e3c518a452acee763bce9",
			"39aff3a2bab6126f332b942af96d3366",
			"0a4f113b", 1))
}

func TestAuthResponseHeader_Example(t *testing.T) {
	header, err := NewAuthResponseHeader(RawAuthReponseHeaderExample)
	require.Nil(t, err)
	require.NotNil(t, header)

	a1 := header.GetA1Value("Mufasa", "Circle Of Life", "")
	require.Equal(t, "939e7578ed9e3c518a452acee763bce9", a1)

	a2 := header.GetA2Value(http.MethodGet, "/dir/index.html", nil)
	require.Equal(t, "39aff3a2bab6126f332b942af96d3366", a2)

	res := header.GetResponseValue(a1, a2, "0a4f113b", 1)
	require.Equal(t, "6629fae49393a05397450978507c4ef1", res)
}
