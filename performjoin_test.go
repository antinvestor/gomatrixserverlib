//nolint:testpackage
package gomatrixserverlib

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/antinvestor/gomatrix"
	"github.com/antinvestor/gomatrixserverlib/spec"
	"github.com/stretchr/testify/require"
)

type TestMakeJoinResponse struct {
	roomVersion RoomVersion
	joinEvent   ProtoEvent
}

func (t *TestMakeJoinResponse) GetJoinEvent() ProtoEvent {
	return t.joinEvent
}

func (t *TestMakeJoinResponse) GetRoomVersion() RoomVersion {
	return t.roomVersion
}

type TestSendJoinResponse struct {
	createEvent PDU
	joinEvent   PDU
}

func (t *TestSendJoinResponse) GetAuthEvents() EventJSONs {
	return EventJSONs{t.createEvent.JSON(), t.joinEvent.JSON()}
}

func (t *TestSendJoinResponse) GetStateEvents() EventJSONs {
	return EventJSONs{t.createEvent.JSON()}
}

func (t *TestSendJoinResponse) GetOrigin() spec.ServerName {
	return "server"
}

func (t *TestSendJoinResponse) GetJoinEvent() json.RawMessage {
	return t.joinEvent.JSON()
}

func (t *TestSendJoinResponse) GetMembersOmitted() bool {
	return true
}

func (t *TestSendJoinResponse) GetServersInRoom() []string {
	return []string{"server"}
}

type TestFederatedJoinClient struct {
	shouldMakeFail   bool
	shouldSendFail   bool
	roomVersion      RoomVersion
	createEvent      PDU
	joinEvent        PDU
	joinEventBuilder ProtoEvent
}

func (t *TestFederatedJoinClient) MakeJoin(
	ctx context.Context,
	origin, s spec.ServerName,
	roomID, userID string,
) (res MakeJoinResponse, err error) {
	if t.shouldMakeFail {
		return nil, gomatrix.HTTPError{}
	}

	return &TestMakeJoinResponse{joinEvent: t.joinEventBuilder, roomVersion: t.roomVersion}, nil
}

func (t *TestFederatedJoinClient) SendJoin(
	ctx context.Context,
	origin, s spec.ServerName,
	event PDU,
) (res SendJoinResponse, err error) {
	if t.shouldSendFail {
		return nil, gomatrix.HTTPError{}
	}

	return &TestSendJoinResponse{createEvent: t.createEvent, joinEvent: t.joinEvent}, nil
}

type joinKeyDatabase struct{ key ed25519.PublicKey }

func (db joinKeyDatabase) FetcherName() string {
	return "joinKeyDatabase"
}

func (db *joinKeyDatabase) FetchKeys(
	ctx context.Context, requests map[PublicKeyLookupRequest]spec.Timestamp,
) (map[PublicKeyLookupRequest]PublicKeyLookupResult, error) {
	results := map[PublicKeyLookupRequest]PublicKeyLookupResult{}

	req1 := PublicKeyLookupRequest{"server", "ed25519:1234"}

	for req := range requests {
		if req == req1 {
			k, err := hex.DecodeString(hex.EncodeToString(db.key))
			vk := VerifyKey{Key: k}
			if err != nil {
				return nil, err
			}
			results[req] = PublicKeyLookupResult{
				VerifyKey:    vk,
				ValidUntilTS: spec.Timestamp(time.Now().Add(time.Hour).Unix() * 1000),
				ExpiredTS:    PublicKeyNotExpired,
			}
		}
	}
	return results, nil
}

func (db *joinKeyDatabase) StoreKeys(
	ctx context.Context, requests map[PublicKeyLookupRequest]PublicKeyLookupResult,
) error {
	return nil
}

func TestPerformJoin(t *testing.T) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	keyID := KeyID("ed25519:1234")
	userID, err := spec.NewUserID("@user:server", true)
	require.NoError(t, err)
	roomID, err := spec.NewRoomID("!room:server")
	require.NoError(t, err)

	stateKey := ""
	eb := MustGetRoomVersion(RoomVersionV10).NewEventBuilderFromProtoEvent(&ProtoEvent{
		SenderID:   userID.String(),
		RoomID:     roomID.String(),
		Type:       "m.room.create",
		StateKey:   &stateKey,
		PrevEvents: []interface{}{},
		AuthEvents: []interface{}{},
		Depth:      0,
		Content:    json.RawMessage(`{"creator":"@user:server","m.federate":true,"room_version":"10"}`),
		Unsigned:   json.RawMessage(""),
	})
	createEvent, err := eb.Build(time.Now(), userID.Domain(), keyID, sk)
	require.NoError(t, err)

	stateKey = userID.String()
	joinProto := ProtoEvent{
		SenderID:   userID.String(),
		RoomID:     roomID.String(),
		Type:       "m.room.member",
		StateKey:   &stateKey,
		PrevEvents: []interface{}{createEvent.EventID()},
		AuthEvents: []interface{}{createEvent.EventID()},
		Depth:      1,
		Content:    json.RawMessage(`{"membership":"join"}`),
		Unsigned:   json.RawMessage(""),
	}
	joinEB := MustGetRoomVersion(RoomVersionV10).NewEventBuilderFromProtoEvent(&joinProto)
	joinEvent, err := joinEB.Build(time.Now(), userID.Domain(), keyID, sk)
	require.NoError(t, err)

	eventProvider := func(ctx context.Context, roomVer RoomVersion, eventIDs []string) ([]PDU, error) {
		for _, eventID := range eventIDs {
			if eventID == createEvent.EventID() {
				return []PDU{createEvent}, nil
			}
		}
		return []PDU{}, nil
	}

	tests := map[string]struct {
		FedClient           FederatedJoinClient
		Input               PerformJoinInput
		ExpectedErr         bool
		ExpectedHTTPErr     bool
		ExpectedRoomVersion RoomVersion
	}{
		"invalid_user_id": {
			FedClient: &TestFederatedJoinClient{
				shouldMakeFail: false,
				shouldSendFail: false,
				roomVersion:    RoomVersionV10,
			},
			Input: PerformJoinInput{
				UserID:        nil,
				RoomID:        roomID,
				KeyRing:       &KeyRing{[]KeyFetcher{&TestRequestKeyDummy{}}, &joinKeyDatabase{key: pk}},
				UserIDQuerier: UserIDForSenderTest,
			},
			ExpectedErr:         true,
			ExpectedHTTPErr:     false,
			ExpectedRoomVersion: joinEvent.Version(),
		},
		"invalid_room_id": {
			FedClient: &TestFederatedJoinClient{
				shouldMakeFail: false,
				shouldSendFail: false,
				roomVersion:    RoomVersionV10,
			},
			Input: PerformJoinInput{
				UserID:        userID,
				RoomID:        nil,
				KeyRing:       &KeyRing{[]KeyFetcher{&TestRequestKeyDummy{}}, &joinKeyDatabase{key: pk}},
				UserIDQuerier: UserIDForSenderTest,
			},
			ExpectedErr:         true,
			ExpectedHTTPErr:     false,
			ExpectedRoomVersion: joinEvent.Version(),
		},
		"invalid_key_ring": {
			FedClient: &TestFederatedJoinClient{
				shouldMakeFail: false,
				shouldSendFail: false,
				roomVersion:    RoomVersionV10,
			},
			Input: PerformJoinInput{
				UserID:        userID,
				RoomID:        roomID,
				KeyRing:       nil,
				UserIDQuerier: UserIDForSenderTest,
			},
			ExpectedErr:         true,
			ExpectedHTTPErr:     false,
			ExpectedRoomVersion: joinEvent.Version(),
		},
		"make_join_http_err": {
			FedClient: &TestFederatedJoinClient{
				shouldMakeFail: true,
				shouldSendFail: false,
				roomVersion:    RoomVersionV10,
			},
			Input: PerformJoinInput{
				UserID:        userID,
				RoomID:        roomID,
				KeyRing:       &KeyRing{[]KeyFetcher{&TestRequestKeyDummy{}}, &joinKeyDatabase{key: pk}},
				UserIDQuerier: UserIDForSenderTest,
			},
			ExpectedErr:         true,
			ExpectedHTTPErr:     true,
			ExpectedRoomVersion: joinEvent.Version(),
		},
		"send_join_http_err": {
			FedClient: &TestFederatedJoinClient{
				shouldMakeFail: false,
				shouldSendFail: true,
				roomVersion:    RoomVersionV10,
			},
			Input: PerformJoinInput{
				UserID:        userID,
				RoomID:        roomID,
				PrivateKey:    sk,
				KeyID:         keyID,
				KeyRing:       &KeyRing{[]KeyFetcher{&TestRequestKeyDummy{}}, &joinKeyDatabase{key: pk}},
				UserIDQuerier: UserIDForSenderTest,
			},
			ExpectedErr:         true,
			ExpectedHTTPErr:     true,
			ExpectedRoomVersion: joinEvent.Version(),
		},
		"default_room_version": {
			FedClient: &TestFederatedJoinClient{
				shouldMakeFail:   false,
				shouldSendFail:   false,
				roomVersion:      "",
				createEvent:      createEvent,
				joinEvent:        joinEvent,
				joinEventBuilder: joinProto,
			},
			Input: PerformJoinInput{
				UserID:        userID,
				RoomID:        roomID,
				PrivateKey:    sk,
				KeyID:         keyID,
				KeyRing:       &KeyRing{[]KeyFetcher{&TestRequestKeyDummy{}}, &joinKeyDatabase{key: pk}},
				EventProvider: eventProvider,
				UserIDQuerier: UserIDForSenderTest,
			},
			ExpectedErr:         false,
			ExpectedHTTPErr:     false,
			ExpectedRoomVersion: RoomVersionV4,
		},
		"successful_join": {
			FedClient: &TestFederatedJoinClient{
				shouldMakeFail:   false,
				shouldSendFail:   false,
				roomVersion:      RoomVersionV10,
				createEvent:      createEvent,
				joinEvent:        joinEvent,
				joinEventBuilder: joinProto,
			},
			Input: PerformJoinInput{
				UserID:        userID,
				RoomID:        roomID,
				PrivateKey:    sk,
				KeyID:         keyID,
				KeyRing:       &KeyRing{[]KeyFetcher{&TestRequestKeyDummy{}}, &joinKeyDatabase{key: pk}},
				EventProvider: eventProvider,
				UserIDQuerier: UserIDForSenderTest,
			},
			ExpectedErr:         false,
			ExpectedHTTPErr:     false,
			ExpectedRoomVersion: joinEvent.Version(),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			res, err := PerformJoin(t.Context(), tc.FedClient, tc.Input)
			if tc.ExpectedErr {
				if err == nil {
					t.Fatalf("Expected an error but none received")
				}
				if tc.ExpectedHTTPErr {
					var httpErr gomatrix.HTTPError
					if ok := errors.As(err.Err, &httpErr); !ok {
						t.Fatalf("Expected HTTPError, got: %v", err)
					}
				}
			} else {
				if err != nil {
					t.Fatalf("Unexpected err: %v", err)
				}
				if res == nil {
					t.Fatalf("Nil response received")
				}

				if res.JoinEvent.EventID() != joinEvent.EventID() {
					t.Fatalf("Expected join eventID %v, got %v", joinEvent.EventID(), res.JoinEvent.EventID())
				}
				if res.JoinEvent.Version() != tc.ExpectedRoomVersion {
					t.Fatalf("Expected room version %v, got %v", tc.ExpectedRoomVersion, res.JoinEvent.Version())
				}
			}
		})
	}
}

func TestPerformJoinPseudoID(t *testing.T) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	keyID := KeyID("ed25519:1234")
	userID, err := spec.NewUserID("@user:server", true)
	require.NoError(t, err)
	roomID, err := spec.NewRoomID("!room:server")
	require.NoError(t, err)

	_, userPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pseudoID := spec.SenderIDFromPseudoIDKey(userPriv)

	rv := RoomVersionPseudoIDs
	cr := CreateContent{Creator: string(pseudoID), RoomVersion: &rv}
	crBytes, err := json.Marshal(cr)
	require.NoError(t, err)

	mapping := MXIDMapping{UserID: userID.String(), UserRoomKey: pseudoID}
	err = mapping.Sign("server", keyID, sk)
	require.NoError(t, err)
	content := MemberContent{Membership: spec.Join, MXIDMapping: &mapping}
	contentBytes, err := json.Marshal(content)
	require.NoError(t, err)

	stateKey := ""
	eb := MustGetRoomVersion(rv).NewEventBuilderFromProtoEvent(&ProtoEvent{
		SenderID:   string(mapping.UserRoomKey),
		RoomID:     roomID.String(),
		Type:       "m.room.create",
		StateKey:   &stateKey,
		PrevEvents: []interface{}{},
		AuthEvents: []interface{}{},
		Depth:      1,
		Content:    crBytes,
		Unsigned:   json.RawMessage(""),
	})
	createEvent, err := eb.Build(time.Now(), spec.ServerName(pseudoID), "ed25519:1", userPriv)
	require.NoError(t, err)

	stateKey = string(pseudoID)
	joinProto := ProtoEvent{
		SenderID:   string(mapping.UserRoomKey),
		RoomID:     roomID.String(),
		Type:       "m.room.member",
		StateKey:   &stateKey,
		PrevEvents: []interface{}{createEvent.EventID()},
		AuthEvents: []interface{}{createEvent.EventID()},
		Depth:      2,
		Content:    contentBytes,
		Unsigned:   json.RawMessage(""),
	}
	joinEB := MustGetRoomVersion(rv).NewEventBuilderFromProtoEvent(&joinProto)
	joinEvent, err := joinEB.Build(time.Now(), spec.ServerName(spec.SenderIDFromPseudoIDKey(sk)), "ed25519:1", sk)
	require.NoError(t, err)
	eventProvider := func(ctx context.Context, roomVer RoomVersion, eventIDs []string) ([]PDU, error) {
		var res []PDU
		for _, eventID := range eventIDs {
			if eventID == createEvent.EventID() {
				res = append(res, createEvent)
			}
			if eventID == joinEvent.EventID() {
				res = append(res, joinEvent)
			}
		}
		return res, nil
	}

	idCreator := func(ctx context.Context, userID spec.UserID, roomID spec.RoomID, roomVersion string) (spec.SenderID, ed25519.PrivateKey, error) {
		return spec.SenderIDFromPseudoIDKey(userPriv), userPriv, nil
	}

	tests := map[string]struct {
		FedClient           FederatedJoinClient
		Input               PerformJoinInput
		ExpectedErr         bool
		ExpectedHTTPErr     bool
		ExpectedRoomVersion RoomVersion
	}{
		"invalid_user_id": {
			FedClient: &TestFederatedJoinClient{
				shouldMakeFail: false,
				shouldSendFail: false,
				roomVersion:    RoomVersionPseudoIDs,
			},
			Input: PerformJoinInput{
				UserID:              nil,
				RoomID:              roomID,
				KeyRing:             &KeyRing{[]KeyFetcher{&TestRequestKeyDummy{}}, &joinKeyDatabase{key: pk}},
				UserIDQuerier:       UserIDForSenderTest,
				GetOrCreateSenderID: idCreator,
			},
			ExpectedErr:         true,
			ExpectedHTTPErr:     false,
			ExpectedRoomVersion: joinEvent.Version(),
		},
		"invalid_room_id": {
			FedClient: &TestFederatedJoinClient{
				shouldMakeFail: false,
				shouldSendFail: false,
				roomVersion:    RoomVersionPseudoIDs,
			},
			Input: PerformJoinInput{
				UserID:              userID,
				RoomID:              nil,
				KeyRing:             &KeyRing{[]KeyFetcher{&TestRequestKeyDummy{}}, &joinKeyDatabase{key: pk}},
				UserIDQuerier:       UserIDForSenderTest,
				GetOrCreateSenderID: idCreator,
			},
			ExpectedErr:         true,
			ExpectedHTTPErr:     false,
			ExpectedRoomVersion: joinEvent.Version(),
		},
		"invalid_key_ring": {
			FedClient: &TestFederatedJoinClient{
				shouldMakeFail: false,
				shouldSendFail: false,
				roomVersion:    RoomVersionPseudoIDs,
			},
			Input: PerformJoinInput{
				UserID:              userID,
				RoomID:              roomID,
				KeyRing:             nil,
				UserIDQuerier:       UserIDForSenderTest,
				GetOrCreateSenderID: idCreator,
			},
			ExpectedErr:         true,
			ExpectedHTTPErr:     false,
			ExpectedRoomVersion: joinEvent.Version(),
		},
		"make_join_http_err": {
			FedClient: &TestFederatedJoinClient{
				shouldMakeFail: true,
				shouldSendFail: false,
				roomVersion:    RoomVersionPseudoIDs,
			},
			Input: PerformJoinInput{
				UserID:              userID,
				RoomID:              roomID,
				KeyRing:             &KeyRing{[]KeyFetcher{&TestRequestKeyDummy{}}, &joinKeyDatabase{key: pk}},
				UserIDQuerier:       UserIDForSenderTest,
				GetOrCreateSenderID: idCreator,
			},
			ExpectedErr:         true,
			ExpectedHTTPErr:     true,
			ExpectedRoomVersion: joinEvent.Version(),
		},
		"send_join_http_err": {
			FedClient: &TestFederatedJoinClient{
				shouldMakeFail: false,
				shouldSendFail: true,
				roomVersion:    RoomVersionPseudoIDs,
			},
			Input: PerformJoinInput{
				UserID:              userID,
				RoomID:              roomID,
				PrivateKey:          sk,
				KeyID:               keyID,
				KeyRing:             &KeyRing{[]KeyFetcher{&TestRequestKeyDummy{}}, &joinKeyDatabase{key: pk}},
				UserIDQuerier:       UserIDForSenderTest,
				GetOrCreateSenderID: idCreator,
			},
			ExpectedErr:         true,
			ExpectedHTTPErr:     true,
			ExpectedRoomVersion: joinEvent.Version(),
		},
		"successful_join": {
			FedClient: &TestFederatedJoinClient{
				shouldMakeFail:   false,
				shouldSendFail:   false,
				roomVersion:      RoomVersionPseudoIDs,
				createEvent:      createEvent,
				joinEvent:        joinEvent,
				joinEventBuilder: joinProto,
			},
			Input: PerformJoinInput{
				UserID:        userID,
				RoomID:        roomID,
				PrivateKey:    sk,
				KeyID:         keyID,
				KeyRing:       &KeyRing{[]KeyFetcher{&TestRequestKeyDummy{}}, &joinKeyDatabase{key: pk}},
				EventProvider: eventProvider,
				UserIDQuerier: func(roomID spec.RoomID, senderID spec.SenderID) (*spec.UserID, error) {
					return userID, nil
				},
				StoreSenderIDFromPublicID: func(ctx context.Context, senderID spec.SenderID, userID string, id spec.RoomID) error {
					return nil
				},
				GetOrCreateSenderID: idCreator,
			},
			ExpectedErr:         false,
			ExpectedHTTPErr:     false,
			ExpectedRoomVersion: joinEvent.Version(),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			res, err := PerformJoin(t.Context(), tc.FedClient, tc.Input)
			if tc.ExpectedErr {
				if err == nil {
					t.Fatalf("Expected an error but none received")
				}
				if tc.ExpectedHTTPErr {
					var httpErr gomatrix.HTTPError
					if ok := errors.As(err.Err, &httpErr); !ok {
						t.Fatalf("Expected HTTPError, got: %v", err)
					}
				}
			} else {
				if err != nil {
					t.Fatalf("Unexpected err: %v", err)
				}
				if res == nil {
					t.Fatalf("Nil response received")
				}

				if res.JoinEvent.EventID() != joinEvent.EventID() {
					t.Fatalf("Expected join eventID %v, got %v", joinEvent.EventID(), res.JoinEvent.EventID())
				}
				if res.JoinEvent.Version() != tc.ExpectedRoomVersion {
					t.Fatalf("Expected room version %v, got %v", tc.ExpectedRoomVersion, res.JoinEvent.Version())
				}
			}
		})
	}
}
