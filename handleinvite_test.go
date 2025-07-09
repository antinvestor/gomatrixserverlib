//nolint:testpackage
package gomatrixserverlib

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/antinvestor/gomatrixserverlib/spec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ed25519"
)

type TestRoomQuerier struct {
	shouldFail bool
	knownRoom  bool
}

func (r *TestRoomQuerier) IsKnownRoom(ctx context.Context, roomID spec.RoomID) (bool, error) {
	if r.shouldFail {
		return false, errors.New("failed finding room")
	}
	return r.knownRoom, nil
}

type TestStateQuerier struct {
	shouldFailState    bool
	shouldFailAuth     bool
	state              []PDU
	createEvent        PDU
	inviterMemberEvent PDU
}

func (r *TestStateQuerier) GetAuthEvents(ctx context.Context, event PDU) (AuthEventProvider, error) {
	if r.shouldFailAuth {
		return nil, errors.New("failed getting auth provider")
	}

	eventProvider, _ := NewAuthEvents(nil)
	if r.createEvent != nil {
		if err := eventProvider.AddEvent(r.createEvent); err != nil {
			return nil, err
		}
		if r.inviterMemberEvent != nil {
			err := eventProvider.AddEvent(r.inviterMemberEvent)
			if err != nil {
				return nil, err
			}
		}
	}
	return eventProvider, nil
}

func (r *TestStateQuerier) GetState(
	ctx context.Context,
	roomID spec.RoomID,
	stateWanted []StateKeyTuple,
) ([]PDU, error) {
	if r.shouldFailState {
		return nil, errors.New("failed getting state")
	}
	return r.state, nil
}

func TestHandleInvite(t *testing.T) {
	userID, err := spec.NewUserID("@user:server", true)
	require.NoError(t, err)
	validRoom, err := spec.NewRoomID("!room:server")
	require.NoError(t, err)
	badRoom, err := spec.NewRoomID("!bad:room")
	require.NoError(t, err)

	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	keyID := KeyID("ed25519:1234")
	verifier := &KeyRing{[]KeyFetcher{&TestRequestKeyDummy{}}, &joinKeyDatabase{key: pk}}

	stateKey := userID.String()
	eb := createMemberEventBuilder(
		RoomVersionV10,
		userID.String(),
		validRoom.String(),
		&stateKey,
		json.RawMessage(`{"membership":"invite"}`),
	)
	inviteEvent, err := eb.Build(time.Now(), userID.Domain(), keyID, sk)
	require.NoError(t, err)

	stateKey = ""
	createEB := MustGetRoomVersion(RoomVersionV10).NewEventBuilderFromProtoEvent(&ProtoEvent{
		SenderID:   userID.String(),
		RoomID:     validRoom.String(),
		Type:       "m.room.create",
		StateKey:   &stateKey,
		PrevEvents: []interface{}{},
		AuthEvents: []interface{}{},
		Depth:      0,
		Content:    json.RawMessage(`{"creator":"@user:server","m.federate":true,"room_version":"10"}`),
		Unsigned:   json.RawMessage(""),
	})
	createEvent, err := createEB.Build(time.Now(), userID.Domain(), keyID, sk)
	require.NoError(t, err)

	type ErrorType int
	const (
		InternalErr ErrorType = iota
		MatrixErr
	)

	tests := map[string]struct {
		input       HandleInviteInput
		expectedErr bool
		errType     ErrorType
		errCode     spec.MatrixErrorCode
	}{
		"unsupported_room_version": {
			input: HandleInviteInput{
				RoomID:            *validRoom,
				RoomVersion:       "",
				InvitedUser:       *userID,
				InviteEvent:       inviteEvent,
				RoomQuerier:       &TestRoomQuerier{},
				MembershipQuerier: &TestMembershipQuerier{},
				StateQuerier:      &TestStateQuerier{},
				KeyID:             keyID,
				PrivateKey:        sk,
				Verifier:          verifier,
				UserIDQuerier:     UserIDForSenderTest,
			},
			expectedErr: true,
			errType:     MatrixErr,
			errCode:     spec.ErrorUnsupportedRoomVersion,
		},
		"mismatched_room_ids": {
			input: HandleInviteInput{
				RoomID:            *badRoom,
				RoomVersion:       RoomVersionV10,
				InvitedUser:       *userID,
				InviteEvent:       inviteEvent,
				RoomQuerier:       &TestRoomQuerier{},
				MembershipQuerier: &TestMembershipQuerier{},
				StateQuerier:      &TestStateQuerier{},
				KeyID:             keyID,
				PrivateKey:        sk,
				Verifier:          verifier,
				UserIDQuerier:     UserIDForSenderTest,
			},
			expectedErr: true,
			errType:     MatrixErr,
			errCode:     spec.ErrorBadJSON,
		},
		"room_querier_error": {
			input: HandleInviteInput{
				RoomID:            *validRoom,
				RoomVersion:       RoomVersionV10,
				InvitedUser:       *userID,
				InviteEvent:       inviteEvent,
				RoomQuerier:       &TestRoomQuerier{shouldFail: true},
				MembershipQuerier: &TestMembershipQuerier{},
				StateQuerier:      &TestStateQuerier{},
				KeyID:             keyID,
				PrivateKey:        sk,
				Verifier:          verifier,
				UserIDQuerier:     UserIDForSenderTest,
			},
			expectedErr: true,
			errType:     InternalErr,
		},
		"known_room_no_state": {
			input: HandleInviteInput{
				RoomID:            *validRoom,
				RoomVersion:       RoomVersionV10,
				InvitedUser:       *userID,
				InviteEvent:       inviteEvent,
				RoomQuerier:       &TestRoomQuerier{knownRoom: true},
				MembershipQuerier: &TestMembershipQuerier{},
				StateQuerier:      &TestStateQuerier{},
				KeyID:             keyID,
				PrivateKey:        sk,
				Verifier:          verifier,
				UserIDQuerier:     UserIDForSenderTest,
			},
			expectedErr: true,
			errType:     InternalErr,
		},
		"known_room_already_joined": {
			input: HandleInviteInput{
				RoomID:            *validRoom,
				RoomVersion:       RoomVersionV10,
				InvitedUser:       *userID,
				InviteEvent:       inviteEvent,
				RoomQuerier:       &TestRoomQuerier{knownRoom: true},
				MembershipQuerier: &TestMembershipQuerier{membership: spec.Join},
				StateQuerier:      &TestStateQuerier{state: []PDU{createEvent}},
				KeyID:             keyID,
				PrivateKey:        sk,
				Verifier:          verifier,
				UserIDQuerier:     UserIDForSenderTest,
			},
			expectedErr: true,
			errType:     MatrixErr,
			errCode:     spec.ErrorForbidden,
		},
		"known_room_state_query_error": {
			input: HandleInviteInput{
				RoomID:            *validRoom,
				RoomVersion:       RoomVersionV10,
				InvitedUser:       *userID,
				InviteEvent:       inviteEvent,
				RoomQuerier:       &TestRoomQuerier{knownRoom: true},
				MembershipQuerier: &TestMembershipQuerier{membership: ""},
				StateQuerier:      &TestStateQuerier{shouldFailState: true},
				KeyID:             keyID,
				PrivateKey:        sk,
				Verifier:          verifier,
				UserIDQuerier:     UserIDForSenderTest,
			},
			expectedErr: true,
			errType:     InternalErr,
		},
		"known_room_not_already_joined_membership_error": {
			input: HandleInviteInput{
				RoomID:            *validRoom,
				RoomVersion:       RoomVersionV10,
				InvitedUser:       *userID,
				InviteEvent:       inviteEvent,
				RoomQuerier:       &TestRoomQuerier{knownRoom: true},
				MembershipQuerier: &TestMembershipQuerier{memberEventErr: true},
				StateQuerier:      &TestStateQuerier{state: []PDU{createEvent}},
				KeyID:             keyID,
				PrivateKey:        sk,
				Verifier:          verifier,
				UserIDQuerier:     UserIDForSenderTest,
			},
			expectedErr: true,
			errType:     InternalErr,
		},
		"known_room_not_already_joined": {
			input: HandleInviteInput{
				RoomID:            *validRoom,
				RoomVersion:       RoomVersionV10,
				InvitedUser:       *userID,
				InviteEvent:       inviteEvent,
				RoomQuerier:       &TestRoomQuerier{knownRoom: true},
				MembershipQuerier: &TestMembershipQuerier{membership: ""},
				StateQuerier:      &TestStateQuerier{state: []PDU{createEvent}},
				KeyID:             keyID,
				PrivateKey:        sk,
				Verifier:          verifier,
				UserIDQuerier:     UserIDForSenderTest,
			},
			expectedErr: false,
		},
		"success_no_room_state": {
			input: HandleInviteInput{
				RoomID:            *validRoom,
				RoomVersion:       RoomVersionV10,
				InvitedUser:       *userID,
				InviteEvent:       inviteEvent,
				RoomQuerier:       &TestRoomQuerier{},
				MembershipQuerier: &TestMembershipQuerier{},
				StateQuerier:      &TestStateQuerier{},
				KeyID:             keyID,
				PrivateKey:        sk,
				Verifier:          verifier,
				UserIDQuerier:     UserIDForSenderTest,
			},
			expectedErr: false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, joinErr := HandleInvite(t.Context(), tc.input)
			if tc.expectedErr {
				switch e := joinErr.(type) {
				case nil:
					t.Fatalf("Error should not be nil")
				case spec.InternalServerError:
					assert.Equal(t, InternalErr, tc.errType)
				case spec.MatrixError:
					assert.Equal(t, MatrixErr, tc.errType)
					assert.Equal(t, tc.errCode, e.ErrCode)
				default:
					t.Fatalf("Unexpected Error Type")
				}
			} else {
				jsonBytes, err := json.Marshal(&joinErr)
				require.NoError(t, err)
				require.NoError(t, joinErr, string(jsonBytes))
			}
		})
	}
}

func TestHandleInviteNilVerifier(t *testing.T) {
	validRoom, err := spec.NewRoomID("!room:remote")
	require.NoError(t, err)

	_, sk, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	keyID := KeyID("ed25519:1234")

	assert.Panics(t, func() {
		_, _ = HandleInvite(t.Context(), HandleInviteInput{
			RoomID:            *validRoom,
			RoomVersion:       "",
			KeyID:             keyID,
			PrivateKey:        sk,
			Verifier:          nil,
			RoomQuerier:       &TestRoomQuerier{},
			MembershipQuerier: &TestMembershipQuerier{},
			StateQuerier:      &TestStateQuerier{},
			UserIDQuerier:     UserIDForSenderTest,
		})
	})
}

func TestHandleInviteNilRoomQuerier(t *testing.T) {
	validRoom, err := spec.NewRoomID("!room:remote")
	require.NoError(t, err)

	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	keyID := KeyID("ed25519:1234")
	verifier := &KeyRing{[]KeyFetcher{&TestRequestKeyDummy{}}, &joinKeyDatabase{key: pk}}

	assert.Panics(t, func() {
		_, _ = HandleInvite(t.Context(), HandleInviteInput{
			RoomID:            *validRoom,
			RoomVersion:       "",
			KeyID:             keyID,
			PrivateKey:        sk,
			Verifier:          verifier,
			RoomQuerier:       nil,
			MembershipQuerier: &TestMembershipQuerier{},
			StateQuerier:      &TestStateQuerier{},
			UserIDQuerier:     UserIDForSenderTest,
		})
	})
}

func TestHandleInviteNilMembershipQuerier(t *testing.T) {
	validRoom, err := spec.NewRoomID("!room:remote")
	require.NoError(t, err)

	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	keyID := KeyID("ed25519:1234")
	verifier := &KeyRing{[]KeyFetcher{&TestRequestKeyDummy{}}, &joinKeyDatabase{key: pk}}

	assert.Panics(t, func() {
		_, _ = HandleInvite(t.Context(), HandleInviteInput{
			RoomID:            *validRoom,
			RoomVersion:       "",
			KeyID:             keyID,
			PrivateKey:        sk,
			Verifier:          verifier,
			RoomQuerier:       &TestRoomQuerier{},
			MembershipQuerier: nil,
			StateQuerier:      &TestStateQuerier{},
			UserIDQuerier:     UserIDForSenderTest,
		})
	})
}

func TestHandleInviteNilStateQuerier(t *testing.T) {
	validRoom, err := spec.NewRoomID("!room:remote")
	require.NoError(t, err)

	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	keyID := KeyID("ed25519:1234")
	verifier := &KeyRing{[]KeyFetcher{&TestRequestKeyDummy{}}, &joinKeyDatabase{key: pk}}

	assert.Panics(t, func() {
		_, _ = HandleInvite(t.Context(), HandleInviteInput{
			RoomID:            *validRoom,
			RoomVersion:       "",
			KeyID:             keyID,
			PrivateKey:        sk,
			Verifier:          verifier,
			RoomQuerier:       &TestRoomQuerier{},
			MembershipQuerier: &TestMembershipQuerier{},
			StateQuerier:      nil,
			UserIDQuerier:     UserIDForSenderTest,
		})
	})
}

func TestHandleInviteNilUserIDQuerier(t *testing.T) {
	validRoom, err := spec.NewRoomID("!room:remote")
	require.NoError(t, err)

	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	keyID := KeyID("ed25519:1234")
	verifier := &KeyRing{[]KeyFetcher{&TestRequestKeyDummy{}}, &joinKeyDatabase{key: pk}}

	assert.Panics(t, func() {
		_, _ = HandleInvite(t.Context(), HandleInviteInput{
			RoomID:            *validRoom,
			RoomVersion:       "",
			KeyID:             keyID,
			PrivateKey:        sk,
			Verifier:          verifier,
			RoomQuerier:       &TestRoomQuerier{},
			MembershipQuerier: &TestMembershipQuerier{},
			StateQuerier:      &TestStateQuerier{},
			UserIDQuerier:     nil,
		})
	})
}

func TestHandleInviteNilContext(t *testing.T) {
	validRoom, err := spec.NewRoomID("!room:remote")
	require.NoError(t, err)

	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	keyID := KeyID("ed25519:1234")
	verifier := &KeyRing{[]KeyFetcher{&TestRequestKeyDummy{}}, &joinKeyDatabase{key: pk}}

	assert.Panics(t, func() {
		_, _ = HandleInvite(nil, HandleInviteInput{ //nolint
			RoomID:            *validRoom,
			RoomVersion:       "",
			KeyID:             keyID,
			PrivateKey:        sk,
			Verifier:          verifier,
			RoomQuerier:       &TestRoomQuerier{},
			MembershipQuerier: &TestMembershipQuerier{},
			StateQuerier:      &TestStateQuerier{},
			UserIDQuerier:     UserIDForSenderTest,
		})
	})
}

func TestHandleInviteV3(t *testing.T) {
	userID, err := spec.NewUserID("@user:server", true)
	require.NoError(t, err)
	validRoom, err := spec.NewRoomID("!room:server")
	require.NoError(t, err)
	badRoom, err := spec.NewRoomID("!bad:room")
	require.NoError(t, err)

	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	keyID := KeyID("ed25519:1234")
	verifier := &KeyRing{[]KeyFetcher{&TestRequestKeyDummy{}}, &joinKeyDatabase{key: pk}}

	stateKey := userID.String()
	inviteEvent := createMemberProtoEvent(
		userID.String(),
		validRoom.String(),
		&stateKey,
		json.RawMessage(`{"membership":"invite"}`),
	)
	require.NoError(t, err)

	stateKey = ""
	createEB := MustGetRoomVersion(RoomVersionV10).NewEventBuilderFromProtoEvent(&ProtoEvent{
		SenderID:   userID.String(),
		RoomID:     validRoom.String(),
		Type:       "m.room.create",
		StateKey:   &stateKey,
		PrevEvents: []interface{}{},
		AuthEvents: []interface{}{},
		Depth:      0,
		Content:    json.RawMessage(`{"creator":"@user:server","m.federate":true,"room_version":"10"}`),
		Unsigned:   json.RawMessage(""),
	})
	createEvent, err := createEB.Build(time.Now(), userID.Domain(), keyID, sk)
	require.NoError(t, err)

	type ErrorType int
	const (
		InternalErr ErrorType = iota
		MatrixErr
	)

	tests := map[string]struct {
		input       HandleInviteV3Input
		expectedErr bool
		errType     ErrorType
		errCode     spec.MatrixErrorCode
	}{
		"unsupported_room_version": {
			input: HandleInviteV3Input{
				HandleInviteInput: HandleInviteInput{
					RoomID:            *validRoom,
					RoomVersion:       "",
					InvitedUser:       *userID,
					RoomQuerier:       &TestRoomQuerier{},
					MembershipQuerier: &TestMembershipQuerier{},
					StateQuerier:      &TestStateQuerier{},
					KeyID:             keyID,
					PrivateKey:        sk,
					Verifier:          verifier,
					UserIDQuerier:     UserIDForSenderTest,
				},
				InviteProtoEvent:    inviteEvent,
				GetOrCreateSenderID: CreateSenderID,
			},
			expectedErr: true,
			errType:     MatrixErr,
			errCode:     spec.ErrorUnsupportedRoomVersion,
		},
		"mismatched_room_ids": {
			input: HandleInviteV3Input{
				HandleInviteInput: HandleInviteInput{
					RoomID:            *badRoom,
					RoomVersion:       RoomVersionV10,
					InvitedUser:       *userID,
					RoomQuerier:       &TestRoomQuerier{},
					MembershipQuerier: &TestMembershipQuerier{},
					StateQuerier:      &TestStateQuerier{},
					KeyID:             keyID,
					PrivateKey:        sk,
					Verifier:          verifier,
					UserIDQuerier:     UserIDForSenderTest,
				},
				InviteProtoEvent:    inviteEvent,
				GetOrCreateSenderID: CreateSenderID,
			},
			expectedErr: true,
			errType:     MatrixErr,
			errCode:     spec.ErrorBadJSON,
		},
		"room_querier_error": {
			input: HandleInviteV3Input{
				HandleInviteInput: HandleInviteInput{
					RoomID:            *validRoom,
					RoomVersion:       RoomVersionV10,
					InvitedUser:       *userID,
					RoomQuerier:       &TestRoomQuerier{shouldFail: true},
					MembershipQuerier: &TestMembershipQuerier{},
					StateQuerier:      &TestStateQuerier{},
					KeyID:             keyID,
					PrivateKey:        sk,
					Verifier:          verifier,
					UserIDQuerier:     UserIDForSenderTest,
				},
				InviteProtoEvent:    inviteEvent,
				GetOrCreateSenderID: CreateSenderID,
			},
			expectedErr: true,
			errType:     InternalErr,
		},
		"known_room_no_state": {
			input: HandleInviteV3Input{
				HandleInviteInput: HandleInviteInput{
					RoomID:            *validRoom,
					RoomVersion:       RoomVersionV10,
					InvitedUser:       *userID,
					RoomQuerier:       &TestRoomQuerier{knownRoom: true},
					MembershipQuerier: &TestMembershipQuerier{},
					StateQuerier:      &TestStateQuerier{},
					KeyID:             keyID,
					PrivateKey:        sk,
					Verifier:          verifier,
					UserIDQuerier:     UserIDForSenderTest,
				},
				InviteProtoEvent:    inviteEvent,
				GetOrCreateSenderID: CreateSenderID,
			},
			expectedErr: true,
			errType:     InternalErr,
		},
		"known_room_already_joined": {
			input: HandleInviteV3Input{
				HandleInviteInput: HandleInviteInput{
					RoomID:            *validRoom,
					RoomVersion:       RoomVersionV10,
					InvitedUser:       *userID,
					RoomQuerier:       &TestRoomQuerier{knownRoom: true},
					MembershipQuerier: &TestMembershipQuerier{membership: spec.Join},
					StateQuerier:      &TestStateQuerier{state: []PDU{createEvent}},
					KeyID:             keyID,
					PrivateKey:        sk,
					Verifier:          verifier,
					UserIDQuerier:     UserIDForSenderTest,
				},
				InviteProtoEvent:    inviteEvent,
				GetOrCreateSenderID: CreateSenderID,
			},
			expectedErr: true,
			errType:     MatrixErr,
			errCode:     spec.ErrorForbidden,
		},
		"known_room_state_query_error": {
			input: HandleInviteV3Input{
				HandleInviteInput: HandleInviteInput{
					RoomID:            *validRoom,
					RoomVersion:       RoomVersionV10,
					InvitedUser:       *userID,
					RoomQuerier:       &TestRoomQuerier{knownRoom: true},
					MembershipQuerier: &TestMembershipQuerier{membership: ""},
					StateQuerier:      &TestStateQuerier{shouldFailState: true},
					KeyID:             keyID,
					PrivateKey:        sk,
					Verifier:          verifier,
					UserIDQuerier:     UserIDForSenderTest,
				},
				InviteProtoEvent:    inviteEvent,
				GetOrCreateSenderID: CreateSenderID,
			},
			expectedErr: true,
			errType:     InternalErr,
		},
		"known_room_not_already_joined_membership_error": {
			input: HandleInviteV3Input{
				HandleInviteInput: HandleInviteInput{
					RoomID:            *validRoom,
					RoomVersion:       RoomVersionV10,
					InvitedUser:       *userID,
					RoomQuerier:       &TestRoomQuerier{knownRoom: true},
					MembershipQuerier: &TestMembershipQuerier{memberEventErr: true},
					StateQuerier:      &TestStateQuerier{state: []PDU{createEvent}},
					KeyID:             keyID,
					PrivateKey:        sk,
					Verifier:          verifier,
					UserIDQuerier:     UserIDForSenderTest,
				},
				InviteProtoEvent:    inviteEvent,
				GetOrCreateSenderID: CreateSenderID,
			},
			expectedErr: true,
			errType:     InternalErr,
		},
		"known_room_not_already_joined": {
			input: HandleInviteV3Input{
				HandleInviteInput: HandleInviteInput{
					RoomID:            *validRoom,
					RoomVersion:       RoomVersionV10,
					InvitedUser:       *userID,
					RoomQuerier:       &TestRoomQuerier{knownRoom: true},
					MembershipQuerier: &TestMembershipQuerier{membership: ""},
					StateQuerier:      &TestStateQuerier{state: []PDU{createEvent}},
					KeyID:             keyID,
					PrivateKey:        sk,
					Verifier:          verifier,
					UserIDQuerier:     UserIDForSenderTest,
				},
				InviteProtoEvent:    inviteEvent,
				GetOrCreateSenderID: CreateSenderID,
			},
			expectedErr: false,
		},
		"success_no_room_state": {
			input: HandleInviteV3Input{
				HandleInviteInput: HandleInviteInput{
					RoomID:            *validRoom,
					RoomVersion:       RoomVersionV10,
					InvitedUser:       *userID,
					RoomQuerier:       &TestRoomQuerier{},
					MembershipQuerier: &TestMembershipQuerier{},
					StateQuerier:      &TestStateQuerier{},
					KeyID:             keyID,
					PrivateKey:        sk,
					Verifier:          verifier,
					UserIDQuerier:     UserIDForSenderTest,
				},
				InviteProtoEvent:    inviteEvent,
				GetOrCreateSenderID: CreateSenderID,
			},
			expectedErr: false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, joinErr := HandleInviteV3(t.Context(), tc.input)
			if tc.expectedErr {
				switch e := joinErr.(type) {
				case nil:
					t.Fatalf("Error should not be nil")
				case spec.InternalServerError:
					assert.Equal(t, InternalErr, tc.errType)
				case spec.MatrixError:
					assert.Equal(t, MatrixErr, tc.errType)
					assert.Equal(t, tc.errCode, e.ErrCode)
				default:
					t.Fatalf("Unexpected Error Type")
				}
			} else {
				jsonBytes, err := json.Marshal(&joinErr)
				require.NoError(t, err)
				require.NoError(t, joinErr, string(jsonBytes))
			}
		})
	}
}

func TestHandleInviteV3NilVerifier(t *testing.T) {
	validRoom, err := spec.NewRoomID("!room:remote")
	require.NoError(t, err)

	_, sk, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	keyID := KeyID("ed25519:1234")

	assert.Panics(t, func() {
		_, _ = HandleInviteV3(t.Context(), HandleInviteV3Input{
			HandleInviteInput: HandleInviteInput{
				RoomID:            *validRoom,
				RoomVersion:       "",
				KeyID:             keyID,
				PrivateKey:        sk,
				Verifier:          nil,
				RoomQuerier:       &TestRoomQuerier{},
				MembershipQuerier: &TestMembershipQuerier{},
				StateQuerier:      &TestStateQuerier{},
				UserIDQuerier:     UserIDForSenderTest,
			},
			GetOrCreateSenderID: CreateSenderID,
		})
	})
}

func TestHandleInviteV3NilRoomQuerier(t *testing.T) {
	validRoom, err := spec.NewRoomID("!room:remote")
	require.NoError(t, err)

	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	keyID := KeyID("ed25519:1234")
	verifier := &KeyRing{[]KeyFetcher{&TestRequestKeyDummy{}}, &joinKeyDatabase{key: pk}}

	assert.Panics(t, func() {
		_, _ = HandleInviteV3(t.Context(), HandleInviteV3Input{
			HandleInviteInput: HandleInviteInput{
				RoomID:            *validRoom,
				RoomVersion:       "",
				KeyID:             keyID,
				PrivateKey:        sk,
				Verifier:          verifier,
				RoomQuerier:       nil,
				MembershipQuerier: &TestMembershipQuerier{},
				StateQuerier:      &TestStateQuerier{},
				UserIDQuerier:     UserIDForSenderTest,
			},
			GetOrCreateSenderID: CreateSenderID,
		})
	})
}

func TestHandleInviteV3NilMembershipQuerier(t *testing.T) {
	validRoom, err := spec.NewRoomID("!room:remote")
	require.NoError(t, err)

	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	keyID := KeyID("ed25519:1234")
	verifier := &KeyRing{[]KeyFetcher{&TestRequestKeyDummy{}}, &joinKeyDatabase{key: pk}}

	assert.Panics(t, func() {
		_, _ = HandleInviteV3(t.Context(), HandleInviteV3Input{
			HandleInviteInput: HandleInviteInput{
				RoomID:            *validRoom,
				RoomVersion:       "",
				KeyID:             keyID,
				PrivateKey:        sk,
				Verifier:          verifier,
				RoomQuerier:       &TestRoomQuerier{},
				MembershipQuerier: nil,
				StateQuerier:      &TestStateQuerier{},
				UserIDQuerier:     UserIDForSenderTest,
			},
			GetOrCreateSenderID: CreateSenderID,
		})
	})
}

func TestHandleInviteV3NilStateQuerier(t *testing.T) {
	validRoom, err := spec.NewRoomID("!room:remote")
	require.NoError(t, err)

	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	keyID := KeyID("ed25519:1234")
	verifier := &KeyRing{[]KeyFetcher{&TestRequestKeyDummy{}}, &joinKeyDatabase{key: pk}}

	assert.Panics(t, func() {
		_, _ = HandleInviteV3(t.Context(), HandleInviteV3Input{
			HandleInviteInput: HandleInviteInput{
				RoomID:            *validRoom,
				RoomVersion:       "",
				KeyID:             keyID,
				PrivateKey:        sk,
				Verifier:          verifier,
				RoomQuerier:       &TestRoomQuerier{},
				MembershipQuerier: &TestMembershipQuerier{},
				StateQuerier:      nil,
				UserIDQuerier:     UserIDForSenderTest,
			},
			GetOrCreateSenderID: CreateSenderID,
		})
	})
}

func TestHandleInviteV3NilUserIDQuerier(t *testing.T) {
	validRoom, err := spec.NewRoomID("!room:remote")
	require.NoError(t, err)

	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	keyID := KeyID("ed25519:1234")
	verifier := &KeyRing{[]KeyFetcher{&TestRequestKeyDummy{}}, &joinKeyDatabase{key: pk}}

	assert.Panics(t, func() {
		_, _ = HandleInviteV3(t.Context(), HandleInviteV3Input{
			HandleInviteInput: HandleInviteInput{
				RoomID:            *validRoom,
				RoomVersion:       "",
				KeyID:             keyID,
				PrivateKey:        sk,
				Verifier:          verifier,
				RoomQuerier:       &TestRoomQuerier{},
				MembershipQuerier: &TestMembershipQuerier{},
				StateQuerier:      &TestStateQuerier{},
				UserIDQuerier:     nil,
			},
			GetOrCreateSenderID: CreateSenderID,
		})
	})
}

func TestHandleInviteV3NilContext(t *testing.T) {
	validRoom, err := spec.NewRoomID("!room:remote")
	require.NoError(t, err)

	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	keyID := KeyID("ed25519:1234")
	verifier := &KeyRing{[]KeyFetcher{&TestRequestKeyDummy{}}, &joinKeyDatabase{key: pk}}

	assert.Panics(t, func() {
		_, _ = HandleInviteV3(nil, HandleInviteV3Input{ //nolint
			HandleInviteInput: HandleInviteInput{
				RoomID:            *validRoom,
				RoomVersion:       "",
				KeyID:             keyID,
				PrivateKey:        sk,
				Verifier:          verifier,
				RoomQuerier:       &TestRoomQuerier{},
				MembershipQuerier: &TestMembershipQuerier{},
				StateQuerier:      &TestStateQuerier{},
				UserIDQuerier:     UserIDForSenderTest,
			},
			GetOrCreateSenderID: CreateSenderID,
		})
	})
}
