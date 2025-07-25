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

func SenderIDForUserTest(roomID spec.RoomID, userID spec.UserID) (*spec.SenderID, error) {
	senderID := spec.SenderID(userID.String())
	return &senderID, nil
}

func CreateSenderID(
	ctx context.Context,
	userID spec.UserID,
	roomID spec.RoomID,
	roomVersion string,
) (spec.SenderID, ed25519.PrivateKey, error) {
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		return "", nil, err
	}
	return spec.SenderID(userID.String()), key, nil
}

func CreateSenderIDPseudoIDs(
	ctx context.Context,
	userID spec.UserID,
	roomID spec.RoomID,
	roomVersion string,
) (spec.SenderID, ed25519.PrivateKey, error) {
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		return "", nil, err
	}
	return spec.SenderIDFromPseudoIDKey(key), key, nil
}

func StoreSenderIDTest(ctx context.Context, senderID spec.SenderID, userID string, id spec.RoomID) error {
	return nil
}

type TestFederatedInviteClient struct {
	shouldFail bool
}

func (f *TestFederatedInviteClient) SendInvite(
	ctx context.Context,
	event PDU,
	strippedState []InviteStrippedState,
) (PDU, error) {
	if f.shouldFail {
		return nil, errors.New("failed sending invite")
	}
	return nil, nil
}

func (f *TestFederatedInviteClient) SendInviteV3(
	ctx context.Context,
	event ProtoEvent,
	userID spec.UserID,
	roomVersion RoomVersion,
	strippedState []InviteStrippedState,
) (PDU, error) {
	if f.shouldFail {
		return nil, errors.New("failed sending invite")
	}

	_, sk, _ := ed25519.GenerateKey(rand.Reader)
	keyID := KeyID("ed25519:1")

	verImpl, err := GetRoomVersion(roomVersion)
	if err != nil {
		return nil, err
	}

	stateKey := string(spec.SenderIDFromPseudoIDKey(sk))
	event.StateKey = &stateKey
	eb := verImpl.NewEventBuilderFromProtoEvent(&event)
	inviteEvent, err := eb.Build(time.Now(), spec.ServerName(stateKey), keyID, sk)

	return inviteEvent, err
}

type TestEventQuerier struct {
	createEvent PDU
}

func (q *TestEventQuerier) GetLatestEventsTest(
	ctx context.Context,
	roomID spec.RoomID,
	eventsNeeded []StateKeyTuple,
) (LatestEvents, error) {
	stateEvents := []PDU{}
	prevEvents := []string{}
	for _, event := range eventsNeeded {
		switch event.EventType {
		case spec.MRoomCreate:
			stateEvents = append(stateEvents, q.createEvent)
		}
		prevEvents = append(prevEvents, "random_event_id")
	}
	return LatestEvents{
		RoomExists:   true,
		StateEvents:  stateEvents,
		PrevEventIDs: prevEvents,
	}, nil
}

func createMemberProtoEvent(sender string, roomID string, stateKey *string, content json.RawMessage) ProtoEvent {
	return ProtoEvent{
		SenderID:   sender,
		RoomID:     roomID,
		Type:       "m.room.member",
		StateKey:   stateKey,
		PrevEvents: []interface{}{},
		AuthEvents: []interface{}{},
		Depth:      0,
		Content:    content,
		Unsigned:   json.RawMessage(""),
	}
}

func TestPerformInvite(t *testing.T) {
	inviteeID, err := spec.NewUserID("@invitee:server", true)
	require.NoError(t, err)
	inviteeIDRemote, err := spec.NewUserID("@invitee:remote", true)
	require.NoError(t, err)
	inviterID, err := spec.NewUserID("@inviter:server", true)
	require.NoError(t, err)
	validRoom, err := spec.NewRoomID("!room:remote")
	require.NoError(t, err)

	_, sk, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	keyID := KeyID("ed25519:1234")

	stateKey := inviteeID.String()
	inviteEvent := createMemberProtoEvent(
		inviterID.String(),
		validRoom.String(),
		&stateKey,
		json.RawMessage(`{"membership":"invite"}`),
	)

	stateKey = inviteeIDRemote.String()
	inviteEventRemote := createMemberProtoEvent(
		inviterID.String(),
		validRoom.String(),
		&stateKey,
		json.RawMessage(`{"membership":"invite"}`),
	)

	stateKey = inviterID.String()
	inviterMemberEventEB := createMemberEventBuilder(
		RoomVersionV10,
		inviterID.String(),
		validRoom.String(),
		&stateKey,
		json.RawMessage(`{"membership":"join"}`),
	)
	inviterMemberEvent, err := inviterMemberEventEB.Build(time.Now(), inviteeID.Domain(), keyID, sk)
	require.NoError(t, err)

	stateKey = ""
	createEventEB := MustGetRoomVersion(RoomVersionV10).NewEventBuilderFromProtoEvent(&ProtoEvent{
		SenderID:   inviterID.String(),
		RoomID:     validRoom.String(),
		Type:       "m.room.create",
		StateKey:   &stateKey,
		PrevEvents: []interface{}{},
		AuthEvents: []interface{}{},
		Depth:      0,
		Content:    json.RawMessage(`{"creator":"@inviter:server","m.federate":true,"room_version":"10"}`),
		Unsigned:   json.RawMessage(""),
	})
	createEvent, err := createEventEB.Build(time.Now(), inviterID.Domain(), keyID, sk)
	if err != nil {
		t.Fatalf("Failed building create event: %v", err)
	}

	eventQuerier := TestEventQuerier{createEvent: createEvent}

	type ErrorType int
	const (
		InternalErr ErrorType = iota
		MatrixErr
	)

	tests := map[string]struct {
		input       PerformInviteInput
		fedClient   FederatedInviteClient
		expectedErr bool
		errType     ErrorType
		errCode     spec.MatrixErrorCode
	}{
		"not_allowed_by_auth_events": {
			input: PerformInviteInput{
				RoomID:            *validRoom,
				RoomVersion:       RoomVersionV10,
				Invitee:           *inviteeID,
				IsTargetLocal:     true,
				EventTemplate:     inviteEvent,
				StrippedState:     []InviteStrippedState{},
				KeyID:             keyID,
				SigningKey:        sk,
				EventTime:         time.Now(),
				MembershipQuerier: &TestMembershipQuerier{},
				StateQuerier:      &TestStateQuerier{},
				UserIDQuerier:     UserIDForSenderTest,
				SenderIDQuerier:   SenderIDForUserTest,
				SenderIDCreator:   CreateSenderID,
				EventQuerier:      eventQuerier.GetLatestEventsTest,
			},
			fedClient:   &TestFederatedInviteClient{},
			expectedErr: true,
			errType:     MatrixErr,
			errCode:     spec.ErrorForbidden,
		},
		"auth_provider_error": {
			input: PerformInviteInput{
				RoomID:            *validRoom,
				RoomVersion:       RoomVersionV10,
				Invitee:           *inviteeID,
				IsTargetLocal:     true,
				EventTemplate:     inviteEvent,
				StrippedState:     []InviteStrippedState{},
				KeyID:             keyID,
				SigningKey:        sk,
				EventTime:         time.Now(),
				MembershipQuerier: &TestMembershipQuerier{},
				StateQuerier:      &TestStateQuerier{shouldFailAuth: true},
				UserIDQuerier:     UserIDForSenderTest,
				SenderIDQuerier:   SenderIDForUserTest,
				SenderIDCreator:   CreateSenderID,
				EventQuerier:      eventQuerier.GetLatestEventsTest,
			},
			fedClient:   &TestFederatedInviteClient{},
			expectedErr: true,
			errType:     MatrixErr,
			errCode:     spec.ErrorForbidden,
		},
		"state_provider_error": {
			input: PerformInviteInput{
				RoomID:            *validRoom,
				RoomVersion:       RoomVersionV10,
				Invitee:           *inviteeID,
				IsTargetLocal:     true,
				EventTemplate:     inviteEvent,
				StrippedState:     []InviteStrippedState{},
				KeyID:             keyID,
				SigningKey:        sk,
				EventTime:         time.Now(),
				MembershipQuerier: &TestMembershipQuerier{},
				StateQuerier:      &TestStateQuerier{shouldFailState: true},
				UserIDQuerier:     UserIDForSenderTest,
				SenderIDQuerier:   SenderIDForUserTest,
				SenderIDCreator:   CreateSenderID,
				EventQuerier:      eventQuerier.GetLatestEventsTest,
			},
			fedClient:   &TestFederatedInviteClient{},
			expectedErr: true,
			errType:     InternalErr,
		},
		"already_joined_failure": {
			input: PerformInviteInput{
				RoomID:            *validRoom,
				RoomVersion:       RoomVersionV10,
				Invitee:           *inviteeID,
				IsTargetLocal:     true,
				EventTemplate:     inviteEvent,
				StrippedState:     []InviteStrippedState{},
				KeyID:             keyID,
				SigningKey:        sk,
				EventTime:         time.Now(),
				MembershipQuerier: &TestMembershipQuerier{membership: spec.Join},
				StateQuerier:      &TestStateQuerier{},
				UserIDQuerier:     UserIDForSenderTest,
				SenderIDQuerier:   SenderIDForUserTest,
				SenderIDCreator:   CreateSenderID,
				EventQuerier:      eventQuerier.GetLatestEventsTest,
			},
			fedClient:   &TestFederatedInviteClient{},
			expectedErr: true,
			errType:     MatrixErr,
			errCode:     spec.ErrorForbidden,
		},
		"remote_invite_federation_error": {
			input: PerformInviteInput{
				RoomID:            *validRoom,
				RoomVersion:       RoomVersionV10,
				Invitee:           *inviteeIDRemote,
				IsTargetLocal:     false,
				EventTemplate:     inviteEventRemote,
				StrippedState:     []InviteStrippedState{},
				KeyID:             keyID,
				SigningKey:        sk,
				EventTime:         time.Now(),
				MembershipQuerier: &TestMembershipQuerier{},
				StateQuerier:      &TestStateQuerier{createEvent: createEvent, inviterMemberEvent: inviterMemberEvent},
				UserIDQuerier:     UserIDForSenderTest,
				SenderIDQuerier:   SenderIDForUserTest,
				SenderIDCreator:   CreateSenderID,
				EventQuerier:      eventQuerier.GetLatestEventsTest,
			},
			fedClient:   &TestFederatedInviteClient{shouldFail: true},
			expectedErr: true,
			errType:     MatrixErr,
			errCode:     spec.ErrorForbidden,
		},
		"success_local": {
			input: PerformInviteInput{
				RoomID:            *validRoom,
				RoomVersion:       RoomVersionV10,
				Invitee:           *inviteeID,
				IsTargetLocal:     true,
				EventTemplate:     inviteEvent,
				StrippedState:     []InviteStrippedState{},
				KeyID:             keyID,
				SigningKey:        sk,
				EventTime:         time.Now(),
				MembershipQuerier: &TestMembershipQuerier{},
				StateQuerier:      &TestStateQuerier{createEvent: createEvent, inviterMemberEvent: inviterMemberEvent},
				UserIDQuerier:     UserIDForSenderTest,
				SenderIDQuerier:   SenderIDForUserTest,
				SenderIDCreator:   CreateSenderID,
				EventQuerier:      eventQuerier.GetLatestEventsTest,
			},
			fedClient:   &TestFederatedInviteClient{},
			expectedErr: false,
		},
		"success_remote": {
			input: PerformInviteInput{
				RoomID:            *validRoom,
				RoomVersion:       RoomVersionV10,
				Invitee:           *inviteeIDRemote,
				IsTargetLocal:     false,
				EventTemplate:     inviteEventRemote,
				StrippedState:     []InviteStrippedState{},
				KeyID:             keyID,
				SigningKey:        sk,
				EventTime:         time.Now(),
				MembershipQuerier: &TestMembershipQuerier{},
				StateQuerier:      &TestStateQuerier{createEvent: createEvent, inviterMemberEvent: inviterMemberEvent},
				UserIDQuerier:     UserIDForSenderTest,
				SenderIDQuerier:   SenderIDForUserTest,
				SenderIDCreator:   CreateSenderID,
				EventQuerier:      eventQuerier.GetLatestEventsTest,
			},
			fedClient:   &TestFederatedInviteClient{},
			expectedErr: false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, joinErr := PerformInvite(t.Context(), tc.input, tc.fedClient)
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

func TestPerformInviteNilMembershipQuerier(t *testing.T) {
	userID, err := spec.NewUserID("@user:server", true)
	require.NoError(t, err)
	validRoom, err := spec.NewRoomID("!room:remote")
	require.NoError(t, err)

	_, sk, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	keyID := KeyID("ed25519:1234")

	stateKey := userID.String()
	inviteEvent := createMemberProtoEvent(
		userID.String(),
		validRoom.String(),
		&stateKey,
		json.RawMessage(`{"membership":"invite"}`),
	)
	eventQuerier := TestEventQuerier{}

	assert.Panics(t, func() {
		_, _ = PerformInvite(t.Context(), PerformInviteInput{
			RoomID:            *validRoom,
			RoomVersion:       RoomVersionV10,
			Invitee:           *userID,
			IsTargetLocal:     true,
			EventTemplate:     inviteEvent,
			StrippedState:     []InviteStrippedState{},
			KeyID:             keyID,
			SigningKey:        sk,
			EventTime:         time.Now(),
			MembershipQuerier: nil,
			StateQuerier:      &TestStateQuerier{},
			UserIDQuerier:     UserIDForSenderTest,
			SenderIDQuerier:   SenderIDForUserTest,
			SenderIDCreator:   CreateSenderID,
			EventQuerier:      eventQuerier.GetLatestEventsTest,
		}, &TestFederatedInviteClient{})
	})
}

func TestPerformInviteNilStateQuerier(t *testing.T) {
	userID, err := spec.NewUserID("@user:server", true)
	require.NoError(t, err)
	validRoom, err := spec.NewRoomID("!room:remote")
	require.NoError(t, err)

	_, sk, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	keyID := KeyID("ed25519:1234")

	stateKey := userID.String()
	inviteEvent := createMemberProtoEvent(
		userID.String(),
		validRoom.String(),
		&stateKey,
		json.RawMessage(`{"membership":"invite"}`),
	)
	eventQuerier := TestEventQuerier{}

	assert.Panics(t, func() {
		_, _ = PerformInvite(t.Context(), PerformInviteInput{
			RoomID:            *validRoom,
			RoomVersion:       RoomVersionV10,
			Invitee:           *userID,
			IsTargetLocal:     true,
			EventTemplate:     inviteEvent,
			StrippedState:     []InviteStrippedState{},
			KeyID:             keyID,
			SigningKey:        sk,
			EventTime:         time.Now(),
			MembershipQuerier: &TestMembershipQuerier{},
			StateQuerier:      nil,
			UserIDQuerier:     UserIDForSenderTest,
			SenderIDQuerier:   SenderIDForUserTest,
			SenderIDCreator:   CreateSenderID,
			EventQuerier:      eventQuerier.GetLatestEventsTest,
		}, &TestFederatedInviteClient{})
	})
}

func TestPerformInviteNilUserIDQuerier(t *testing.T) {
	userID, err := spec.NewUserID("@user:server", true)
	require.NoError(t, err)
	validRoom, err := spec.NewRoomID("!room:remote")
	require.NoError(t, err)

	_, sk, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	keyID := KeyID("ed25519:1234")

	stateKey := userID.String()
	inviteEvent := createMemberProtoEvent(
		userID.String(),
		validRoom.String(),
		&stateKey,
		json.RawMessage(`{"membership":"invite"}`),
	)
	eventQuerier := TestEventQuerier{}

	assert.Panics(t, func() {
		_, _ = PerformInvite(t.Context(), PerformInviteInput{
			RoomID:            *validRoom,
			RoomVersion:       RoomVersionV10,
			Invitee:           *userID,
			IsTargetLocal:     true,
			EventTemplate:     inviteEvent,
			StrippedState:     []InviteStrippedState{},
			KeyID:             keyID,
			SigningKey:        sk,
			EventTime:         time.Now(),
			MembershipQuerier: &TestMembershipQuerier{},
			StateQuerier:      &TestStateQuerier{},
			UserIDQuerier:     nil,
			SenderIDQuerier:   SenderIDForUserTest,
			SenderIDCreator:   CreateSenderID,
			EventQuerier:      eventQuerier.GetLatestEventsTest,
		}, &TestFederatedInviteClient{})
	})
}

func TestPerformInviteNilSenderIDQuerier(t *testing.T) {
	userID, err := spec.NewUserID("@user:server", true)
	require.NoError(t, err)
	validRoom, err := spec.NewRoomID("!room:remote")
	require.NoError(t, err)

	_, sk, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	keyID := KeyID("ed25519:1234")

	stateKey := userID.String()
	inviteEvent := createMemberProtoEvent(
		userID.String(),
		validRoom.String(),
		&stateKey,
		json.RawMessage(`{"membership":"invite"}`),
	)
	eventQuerier := TestEventQuerier{}

	assert.Panics(t, func() {
		_, _ = PerformInvite(t.Context(), PerformInviteInput{
			RoomID:            *validRoom,
			RoomVersion:       RoomVersionV10,
			Invitee:           *userID,
			IsTargetLocal:     true,
			EventTemplate:     inviteEvent,
			StrippedState:     []InviteStrippedState{},
			KeyID:             keyID,
			SigningKey:        sk,
			EventTime:         time.Now(),
			MembershipQuerier: &TestMembershipQuerier{},
			StateQuerier:      &TestStateQuerier{},
			UserIDQuerier:     UserIDForSenderTest,
			SenderIDQuerier:   nil,
			SenderIDCreator:   CreateSenderID,
			EventQuerier:      eventQuerier.GetLatestEventsTest,
		}, &TestFederatedInviteClient{})
	})
}

func TestPerformInviteNilSenderIDCreator(t *testing.T) {
	userID, err := spec.NewUserID("@user:server", true)
	require.NoError(t, err)
	validRoom, err := spec.NewRoomID("!room:remote")
	require.NoError(t, err)

	_, sk, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	keyID := KeyID("ed25519:1234")

	stateKey := userID.String()
	inviteEvent := createMemberProtoEvent(
		userID.String(),
		validRoom.String(),
		&stateKey,
		json.RawMessage(`{"membership":"invite"}`),
	)
	eventQuerier := TestEventQuerier{}

	assert.Panics(t, func() {
		_, _ = PerformInvite(t.Context(), PerformInviteInput{
			RoomID:            *validRoom,
			RoomVersion:       RoomVersionV10,
			Invitee:           *userID,
			IsTargetLocal:     true,
			EventTemplate:     inviteEvent,
			StrippedState:     []InviteStrippedState{},
			KeyID:             keyID,
			SigningKey:        sk,
			EventTime:         time.Now(),
			MembershipQuerier: &TestMembershipQuerier{},
			StateQuerier:      &TestStateQuerier{},
			UserIDQuerier:     UserIDForSenderTest,
			SenderIDQuerier:   SenderIDForUserTest,
			SenderIDCreator:   nil,
			EventQuerier:      eventQuerier.GetLatestEventsTest,
		}, &TestFederatedInviteClient{})
	})
}

func TestPerformInviteNilEventQuerier(t *testing.T) {
	userID, err := spec.NewUserID("@user:server", true)
	require.NoError(t, err)
	validRoom, err := spec.NewRoomID("!room:remote")
	require.NoError(t, err)

	_, sk, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	keyID := KeyID("ed25519:1234")

	stateKey := userID.String()
	inviteEvent := createMemberProtoEvent(
		userID.String(),
		validRoom.String(),
		&stateKey,
		json.RawMessage(`{"membership":"invite"}`),
	)

	assert.Panics(t, func() {
		_, _ = PerformInvite(t.Context(), PerformInviteInput{
			RoomID:            *validRoom,
			RoomVersion:       RoomVersionV10,
			Invitee:           *userID,
			IsTargetLocal:     true,
			EventTemplate:     inviteEvent,
			StrippedState:     []InviteStrippedState{},
			KeyID:             keyID,
			SigningKey:        sk,
			EventTime:         time.Now(),
			MembershipQuerier: &TestMembershipQuerier{},
			StateQuerier:      &TestStateQuerier{},
			UserIDQuerier:     UserIDForSenderTest,
			SenderIDQuerier:   SenderIDForUserTest,
			SenderIDCreator:   CreateSenderID,
			EventQuerier:      nil,
		}, &TestFederatedInviteClient{})
	})
}

func TestPerformInviteNilContext(t *testing.T) {
	userID, err := spec.NewUserID("@user:server", true)
	require.NoError(t, err)
	validRoom, err := spec.NewRoomID("!room:remote")
	require.NoError(t, err)

	_, sk, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	keyID := KeyID("ed25519:1234")

	stateKey := userID.String()
	inviteEvent := createMemberProtoEvent(
		userID.String(),
		validRoom.String(),
		&stateKey,
		json.RawMessage(`{"membership":"invite"}`),
	)
	eventQuerier := TestEventQuerier{}

	assert.Panics(t, func() {
		_, _ = PerformInvite(nil, PerformInviteInput{ //nolint
			RoomID:            *validRoom,
			RoomVersion:       RoomVersionV10,
			Invitee:           *userID,
			IsTargetLocal:     true,
			EventTemplate:     inviteEvent,
			StrippedState:     []InviteStrippedState{},
			KeyID:             keyID,
			SigningKey:        sk,
			EventTime:         time.Now(),
			MembershipQuerier: &TestMembershipQuerier{},
			StateQuerier:      &TestStateQuerier{},
			UserIDQuerier:     UserIDForSenderTest,
			SenderIDQuerier:   SenderIDForUserTest,
			SenderIDCreator:   CreateSenderID,
			EventQuerier:      eventQuerier.GetLatestEventsTest,
		}, &TestFederatedInviteClient{})
	})
}

func TestPerformInvitePseudoIDs(t *testing.T) {
	inviteeID, err := spec.NewUserID("@invitee:server", true)
	require.NoError(t, err)
	inviteeIDRemote, err := spec.NewUserID("@invitee:remote", true)
	require.NoError(t, err)

	inviterID, err := spec.NewUserID("@inviter:server", true)
	require.NoError(t, err)
	_, inviterKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	inviterPseudoID := string(spec.SenderIDFromPseudoIDKey(inviterKey))

	validRoom, err := spec.NewRoomID("!room:remote")
	require.NoError(t, err)

	keyID := KeyID("ed25519:1234")

	stateKey := inviteeID.String()
	inviteEvent := createMemberProtoEvent(
		inviterPseudoID,
		validRoom.String(),
		&stateKey,
		json.RawMessage(`{"membership":"invite"}`),
	)

	stateKey = inviteeIDRemote.String()
	inviteEventRemote := createMemberProtoEvent(
		inviterPseudoID,
		validRoom.String(),
		&stateKey,
		json.RawMessage(`{"membership":"invite"}`),
	)

	rv := RoomVersionPseudoIDs
	federate := true
	cr := CreateContent{Creator: inviterPseudoID, RoomVersion: &rv, Federate: &federate}
	crBytes, err := json.Marshal(cr)
	require.NoError(t, err)

	stateKey = ""
	createEventEB := MustGetRoomVersion(rv).NewEventBuilderFromProtoEvent(&ProtoEvent{
		SenderID:   inviterPseudoID,
		RoomID:     validRoom.String(),
		Type:       "m.room.create",
		StateKey:   &stateKey,
		PrevEvents: []interface{}{},
		AuthEvents: []interface{}{},
		Depth:      1,
		Content:    crBytes,
		Unsigned:   json.RawMessage(""),
	})
	createEvent, err := createEventEB.Build(time.Now(), spec.ServerName(inviterPseudoID), "ed25519:1", inviterKey)
	if err != nil {
		t.Fatalf("Failed building create event: %v", err)
	}

	mapping := MXIDMapping{UserID: inviterID.String(), UserRoomKey: spec.SenderID(inviterPseudoID)}
	err = mapping.Sign("server", keyID, inviterKey)
	require.NoError(t, err)
	content := MemberContent{Membership: spec.Join, MXIDMapping: &mapping}
	contentBytes, err := json.Marshal(content)
	require.NoError(t, err)

	stateKey = inviterPseudoID
	inviterJoinEB := MustGetRoomVersion(rv).NewEventBuilderFromProtoEvent(&ProtoEvent{
		SenderID:   inviterPseudoID,
		RoomID:     validRoom.String(),
		Type:       "m.room.member",
		StateKey:   &stateKey,
		PrevEvents: []interface{}{createEvent.EventID()},
		AuthEvents: []interface{}{createEvent.EventID()},
		Depth:      2,
		Content:    contentBytes,
		Unsigned:   json.RawMessage(""),
	})
	inviterJoinEvent, err := inviterJoinEB.Build(time.Now(), spec.ServerName(inviterPseudoID), "ed25519:1", inviterKey)
	if err != nil {
		t.Fatalf("Failed building create event: %v", err)
	}

	eventQuerier := TestEventQuerier{createEvent: createEvent}

	type ErrorType int
	const (
		InternalErr ErrorType = iota
		MatrixErr
	)

	userIDForSender := func(roomID spec.RoomID, senderID spec.SenderID) (*spec.UserID, error) {
		return spec.NewUserID(inviterID.String(), true)
	}

	tests := map[string]struct {
		input       PerformInviteInput
		fedClient   FederatedInviteClient
		expectedErr bool
		errType     ErrorType
		errCode     spec.MatrixErrorCode
	}{
		"not_allowed_by_auth_events": {
			input: PerformInviteInput{
				RoomID:                    *validRoom,
				RoomVersion:               RoomVersionPseudoIDs,
				Invitee:                   *inviteeID,
				IsTargetLocal:             true,
				EventTemplate:             inviteEvent,
				StrippedState:             []InviteStrippedState{},
				KeyID:                     keyID,
				SigningKey:                inviterKey,
				EventTime:                 time.Now(),
				MembershipQuerier:         &TestMembershipQuerier{},
				StateQuerier:              &TestStateQuerier{},
				UserIDQuerier:             UserIDForSenderTest,
				SenderIDQuerier:           SenderIDForUserTest,
				SenderIDCreator:           CreateSenderIDPseudoIDs,
				EventQuerier:              eventQuerier.GetLatestEventsTest,
				StoreSenderIDFromPublicID: StoreSenderIDTest,
			},
			fedClient:   &TestFederatedInviteClient{},
			expectedErr: true,
			errType:     MatrixErr,
			errCode:     spec.ErrorForbidden,
		},
		"auth_provider_error": {
			input: PerformInviteInput{
				RoomID:                    *validRoom,
				RoomVersion:               RoomVersionPseudoIDs,
				Invitee:                   *inviteeID,
				IsTargetLocal:             true,
				EventTemplate:             inviteEvent,
				StrippedState:             []InviteStrippedState{},
				KeyID:                     keyID,
				SigningKey:                inviterKey,
				EventTime:                 time.Now(),
				MembershipQuerier:         &TestMembershipQuerier{},
				StateQuerier:              &TestStateQuerier{shouldFailAuth: true},
				UserIDQuerier:             UserIDForSenderTest,
				SenderIDQuerier:           SenderIDForUserTest,
				SenderIDCreator:           CreateSenderIDPseudoIDs,
				EventQuerier:              eventQuerier.GetLatestEventsTest,
				StoreSenderIDFromPublicID: StoreSenderIDTest,
			},
			fedClient:   &TestFederatedInviteClient{},
			expectedErr: true,
			errType:     MatrixErr,
			errCode:     spec.ErrorForbidden,
		},
		"state_provider_error": {
			input: PerformInviteInput{
				RoomID:                    *validRoom,
				RoomVersion:               RoomVersionPseudoIDs,
				Invitee:                   *inviteeID,
				IsTargetLocal:             true,
				EventTemplate:             inviteEvent,
				StrippedState:             []InviteStrippedState{},
				KeyID:                     keyID,
				SigningKey:                inviterKey,
				EventTime:                 time.Now(),
				MembershipQuerier:         &TestMembershipQuerier{},
				StateQuerier:              &TestStateQuerier{shouldFailState: true},
				UserIDQuerier:             UserIDForSenderTest,
				SenderIDQuerier:           SenderIDForUserTest,
				SenderIDCreator:           CreateSenderIDPseudoIDs,
				EventQuerier:              eventQuerier.GetLatestEventsTest,
				StoreSenderIDFromPublicID: StoreSenderIDTest,
			},
			fedClient:   &TestFederatedInviteClient{},
			expectedErr: true,
			errType:     InternalErr,
		},
		"already_joined_failure": {
			input: PerformInviteInput{
				RoomID:                    *validRoom,
				RoomVersion:               RoomVersionPseudoIDs,
				Invitee:                   *inviteeID,
				IsTargetLocal:             true,
				EventTemplate:             inviteEvent,
				StrippedState:             []InviteStrippedState{},
				KeyID:                     keyID,
				SigningKey:                inviterKey,
				EventTime:                 time.Now(),
				MembershipQuerier:         &TestMembershipQuerier{membership: spec.Join},
				StateQuerier:              &TestStateQuerier{},
				UserIDQuerier:             UserIDForSenderTest,
				SenderIDQuerier:           SenderIDForUserTest,
				SenderIDCreator:           CreateSenderIDPseudoIDs,
				EventQuerier:              eventQuerier.GetLatestEventsTest,
				StoreSenderIDFromPublicID: StoreSenderIDTest,
			},
			fedClient:   &TestFederatedInviteClient{},
			expectedErr: true,
			errType:     MatrixErr,
			errCode:     spec.ErrorForbidden,
		},
		"remote_invite_federation_error": {
			input: PerformInviteInput{
				RoomID:            *validRoom,
				RoomVersion:       RoomVersionPseudoIDs,
				Invitee:           *inviteeIDRemote,
				IsTargetLocal:     false,
				EventTemplate:     inviteEventRemote,
				StrippedState:     []InviteStrippedState{},
				KeyID:             keyID,
				SigningKey:        inviterKey,
				EventTime:         time.Now(),
				MembershipQuerier: &TestMembershipQuerier{},
				StateQuerier: &TestStateQuerier{
					createEvent:        createEvent,
					inviterMemberEvent: inviterJoinEvent,
				},
				UserIDQuerier:             UserIDForSenderTest,
				SenderIDQuerier:           SenderIDForUserTest,
				SenderIDCreator:           CreateSenderIDPseudoIDs,
				EventQuerier:              eventQuerier.GetLatestEventsTest,
				StoreSenderIDFromPublicID: StoreSenderIDTest,
			},
			fedClient:   &TestFederatedInviteClient{shouldFail: true},
			expectedErr: true,
			errType:     MatrixErr,
			errCode:     spec.ErrorForbidden,
		},
		"success_local": {
			input: PerformInviteInput{
				RoomID:            *validRoom,
				RoomVersion:       RoomVersionPseudoIDs,
				Invitee:           *inviteeID,
				IsTargetLocal:     true,
				EventTemplate:     inviteEvent,
				StrippedState:     []InviteStrippedState{},
				KeyID:             keyID,
				SigningKey:        inviterKey,
				EventTime:         time.Now(),
				MembershipQuerier: &TestMembershipQuerier{},
				StateQuerier: &TestStateQuerier{
					createEvent:        createEvent,
					inviterMemberEvent: inviterJoinEvent,
				},
				UserIDQuerier:             userIDForSender,
				SenderIDQuerier:           SenderIDForUserTest,
				SenderIDCreator:           CreateSenderIDPseudoIDs,
				EventQuerier:              eventQuerier.GetLatestEventsTest,
				StoreSenderIDFromPublicID: StoreSenderIDTest,
			},
			fedClient:   &TestFederatedInviteClient{},
			expectedErr: false,
		},
		"success_remote": {
			input: PerformInviteInput{
				RoomID:            *validRoom,
				RoomVersion:       RoomVersionPseudoIDs,
				Invitee:           *inviteeIDRemote,
				IsTargetLocal:     false,
				EventTemplate:     inviteEventRemote,
				StrippedState:     []InviteStrippedState{},
				KeyID:             keyID,
				SigningKey:        inviterKey,
				EventTime:         time.Now(),
				MembershipQuerier: &TestMembershipQuerier{},
				StateQuerier: &TestStateQuerier{
					createEvent:        createEvent,
					inviterMemberEvent: inviterJoinEvent,
				},
				UserIDQuerier:             userIDForSender,
				SenderIDQuerier:           SenderIDForUserTest,
				SenderIDCreator:           CreateSenderIDPseudoIDs,
				EventQuerier:              eventQuerier.GetLatestEventsTest,
				StoreSenderIDFromPublicID: StoreSenderIDTest,
			},
			fedClient:   &TestFederatedInviteClient{},
			expectedErr: false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, joinErr := PerformInvite(t.Context(), tc.input, tc.fedClient)
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
