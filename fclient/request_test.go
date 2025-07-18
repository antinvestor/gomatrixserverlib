//nolint:testpackage
package fclient

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/antinvestor/gomatrixserverlib"
	"github.com/antinvestor/gomatrixserverlib/spec"
	"golang.org/x/crypto/ed25519"
)

// This GET request is taken from a request made by a synapse run by sytest.
// The headers have been reordered to match the order net/http writes them in.
const exampleGetRequest = "GET /_matrix/federation/v1/query/directory?room_alias=%23test%3Alocalhost%3A44033 HTTP/1.1\r\n" +
	"Host: localhost:44033\r\n" +
	"Authorization: X-Matrix" +
	" origin=\"localhost:8800\"" +
	",key=\"ed25519:a_Obwu\"" +
	",sig=\"7vt4vP/w8zYB3Zg77nuTPwie3TxEy2OHZQMsSa4nsXZzL4/qw+DguXbyMy3BF77XvSJmBt+Gw+fU6T4HId7fBg\"" +
	",destination=\"localhost:44033\"" +
	"\r\n" +
	"\r\n"

// This PUT request is taken from a request made by a synapse run by sytest.
// The headers have been reordered to match the order net/http writes them in.
const examplePutRequest = "PUT /_matrix/federation/v1/send/1493385816575/ HTTP/1.1\r\n" +
	"Host: localhost:44033\r\n" +
	"Content-Length: 321\r\n" +
	"Authorization: X-Matrix" +
	" origin=\"localhost:8800\"" +
	",key=\"ed25519:a_Obwu\"" +
	",sig=\"+hmW6UjEXx7vMt2+MXO/EImSfdEYdBsZEOmpiz3evYktAgGNpGuNMBYXIA969WGubmceREKA/r1phasUFHBpDg\"" +
	",destination=\"localhost:44033\"" +
	"\r\n" +
	"Content-Type: application/json\r\n" +
	"\r\n" +
	examplePutContent

const examplePutContent = `{"edus":[{"content":{"device_id":"YHRUBZNPFS",` +
	`"keys":{"device_id":"YHRUBZNPFS","device_keys":{},"user_id":` +
	`"@ANON-22:localhost:8800"},"prev_id":[],"stream_id":30,"user_id":` +
	`"@ANON-22:localhost:8800"},"edu_type":"m.device_list_update"}],"origin"` +
	`:"localhost:8800","origin_server_ts":1493385822396,"pdu_failures":[],` +
	`"pdus":[]}`

type noopJSONVerifier struct{}

func (v *noopJSONVerifier) VerifyJSONs(
	ctx context.Context,
	requests []gomatrixserverlib.VerifyJSONRequest,
) ([]gomatrixserverlib.VerifyJSONResult, error) {
	x := make([]gomatrixserverlib.VerifyJSONResult, len(requests))
	return x, nil
}

func TestSignGetRequest(t *testing.T) {
	request := NewFederationRequest(
		"GET", "localhost:8800", "localhost:44033",
		"/_matrix/federation/v1/query/directory?room_alias=%23test%3Alocalhost%3A44033",
	)
	if err := request.Sign("localhost:8800", "ed25519:a_Obwu", privateKey1); err != nil {
		t.Fatal(err)
	}

	hr, err := request.HTTPRequest()
	if err != nil {
		t.Fatal(err)
	}
	hr.Header.Set("User-Agent", "")

	buf := bytes.NewBuffer(nil)
	if err = hr.Write(buf); err != nil {
		t.Fatal(err)
	}

	got := buf.String()
	want := exampleGetRequest
	if want != got {
		t.Errorf("Wanted %q got %q", want, got)
	}
}

func TestVerifyGetRequest(t *testing.T) {
	hr, err := http.ReadRequest(bufio.NewReader(bytes.NewReader([]byte(exampleGetRequest))))
	if err != nil {
		t.Fatal(err)
	}
	request, jsonResp := VerifyHTTPRequest(
		hr, time.Unix(1493142432, 96400), "localhost:44033", nil, &noopJSONVerifier{},
	)
	if request == nil {
		t.Fatalf("Wanted non-nil request got nil. (request was %#v, response was %#v)", hr, jsonResp)
	}

	if request.Method() != "GET" {
		t.Errorf("Wanted request.Method() to be \"GET\" got %q", request.Method())
	}

	if request.Origin() != "localhost:8800" {
		t.Errorf("Wanted request.Origin() to be \"localhost:8800\" got %q", request.Origin())
	}

	if request.Content() != nil {
		t.Errorf("Wanted request.Content() to be nil got %q", string(request.Content()))
	}

	wantPath := "/_matrix/federation/v1/query/directory?room_alias=%23test%3Alocalhost%3A44033"
	if request.RequestURI() != wantPath {
		t.Errorf("Wanted request.RequestURI() to be %q got %q", wantPath, request.RequestURI())
	}
}

func TestSignPutRequest(t *testing.T) {
	request := NewFederationRequest(
		"PUT", "localhost:8800", "localhost:44033", "/_matrix/federation/v1/send/1493385816575/",
	)
	if err := request.SetContent(json.RawMessage([]byte(examplePutContent))); err != nil {
		t.Fatal(err)
	}
	if err := request.Sign("localhost:8800", "ed25519:a_Obwu", privateKey1); err != nil {
		t.Fatal(err)
	}

	hr, err := request.HTTPRequest()
	if err != nil {
		t.Fatal(err)
	}
	hr.Header.Set("User-Agent", "")

	buf := bytes.NewBuffer(nil)
	if err = hr.Write(buf); err != nil {
		t.Fatal(err)
	}

	got := buf.String()
	want := examplePutRequest
	if want != got {
		t.Errorf("Wanted %q got %q", want, got)
	}
}

func TestVerifyPutRequest(t *testing.T) {
	hr, err := http.ReadRequest(bufio.NewReader(bytes.NewReader([]byte(examplePutRequest))))
	if err != nil {
		t.Fatal(err)
	}
	request, jsonResp := VerifyHTTPRequest(
		hr, time.Unix(1493142432, 96400), "localhost:44033", nil, &noopJSONVerifier{},
	)
	if request == nil {
		t.Fatalf("Wanted non-nil request got nil. (request was %#v, response was %#v)", hr, jsonResp)
	}

	if request.Method() != "PUT" {
		t.Errorf("Wanted request.Method() to be \"PUT\" got %q", request.Method())
	}

	if request.Origin() != "localhost:8800" {
		t.Errorf("Wanted request.Origin() to be \"localhost:8800\" got %q", request.Origin())
	}

	if string(request.Content()) != examplePutContent {
		t.Errorf("Wanted request.Content() to be %q got %q", examplePutContent, string(request.Content()))
	}

	wantPath := "/_matrix/federation/v1/send/1493385816575/"
	if request.RequestURI() != wantPath {
		t.Errorf("Wanted request.RequestURI() to be %q got %q", wantPath, request.RequestURI())
	}
}

var privateKeySeed1 = `QJvXAPj0D9MUb1exkD8pIWmCvT1xajlsB8jRYz/G5HE`
var privateKey1 = mustLoadPrivateKey(privateKeySeed1)

func mustLoadPrivateKey(seed string) ed25519.PrivateKey {
	seedBytes, err := base64.RawStdEncoding.DecodeString(seed)
	if err != nil {
		panic(err)
	}
	random := bytes.NewBuffer(seedBytes)
	_, privateKey, err := ed25519.GenerateKey(random)
	if err != nil {
		panic(err)
	}
	return privateKey
}

func TestParseAuthorization(t *testing.T) {
	wantScheme := "X-Matrix"
	wantOrigin := spec.ServerName("foo")
	wantKey := gomatrixserverlib.KeyID("ed25519:1")
	wantSig := "sig"
	wantDestination := spec.ServerName("bar")

	tests := []struct {
		name   string
		header string
	}{
		{
			name:   "parse with whitespace",
			header: `X-Matrix origin=foo , key="ed25519:1",  sig="sig",		destination="bar"`,
		},
		{
			name:   "parse without spaces",
			header: `X-Matrix origin=foo,key="ed25519:1",sig="sig",destination="bar"`,
		},
		{
			name:   "parse with tabs spaces",
			header: `X-Matrix 	origin=foo	,		key="ed25519:1",	sig="sig"	,destination	="bar"`,
		},
		{
			name:   "parse with different ordering and tabs",
			header: `X-Matrix 	origin=foo	,	,destination	="bar",	sig="sig", key="ed25519:1"`,
		},
		{
			name:   "parse with different ordering and whitespace around values",
			header: `X-Matrix 	origin=foo	,	,destination	=  "bar"  ,	sig=	"sig" , key="ed25519:1"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotScheme, gotOrigin, gotDestination, gotKey, gotSig := ParseAuthorization(tt.header)

			if gotScheme != wantScheme {
				t.Errorf("ParseAuthorization() gotScheme = %v, want %v", gotScheme, wantScheme)
			}
			if gotOrigin != wantOrigin {
				t.Errorf("ParseAuthorization() gotOrigin = %v, want %v", gotOrigin, wantOrigin)
			}
			if gotDestination != wantDestination {
				t.Errorf("ParseAuthorization() gotDestination = %v, want %v", gotDestination, wantDestination)
			}
			if gotKey != wantKey {
				t.Errorf("ParseAuthorization() gotKey = %v, want %v", gotKey, wantKey)
			}
			if gotSig != wantSig {
				t.Errorf("ParseAuthorization() gotSig = %v, want %v", gotSig, wantSig)
			}
		})
	}
}
