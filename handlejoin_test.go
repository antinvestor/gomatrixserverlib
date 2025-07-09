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

type TestMembershipQuerier struct {
	memberEventErr bool
	membership     string
}

func (s *TestMembershipQuerier) CurrentMembership(
	ctx context.Context,
	roomID spec.RoomID,
	senderID spec.SenderID,
) (string, error) {
	if s.memberEventErr {
		return "", errors.New("err")
	}
	return s.membership, nil
}

type TestRestrictedRoomJoinQuerier struct {
	roomInfoErr       bool
	stateEventErr     bool
	serverInRoomErr   bool
	membershipErr     bool
	getJoinedUsersErr bool
	invitePendingErr  bool
	roomExists        bool
	serverInRoom      map[string]bool

	pendingInvite bool
	joinerInRoom  bool
	joinedUsers   []PDU

	joinRulesEvent   PDU
	powerLevelsEvent PDU
	memberEvent      PDU
}

func (r *TestRestrictedRoomJoinQuerier) CurrentStateEvent(
	_ context.Context,
	_ spec.RoomID,
	eventType string,
	stateKey string,
) (PDU, error) {
	if r.stateEventErr {
		return nil, errors.New("err")
	}
	var event PDU

	switch eventType {
	case spec.MRoomJoinRules:
		event = r.joinRulesEvent
	case spec.MRoomPowerLevels:
		event = r.powerLevelsEvent
	case spec.MRoomMember:
		event = r.memberEvent
	}
	return event, nil
}

func (r *TestRestrictedRoomJoinQuerier) InvitePending(
	ctx context.Context,
	roomID spec.RoomID,
	senderID spec.SenderID,
) (bool, error) {
	if r.invitePendingErr {
		return false, errors.New("err")
	}
	return r.pendingInvite, nil
}

func (r *TestRestrictedRoomJoinQuerier) RestrictedRoomJoinInfo(
	ctx context.Context,
	roomID spec.RoomID,
	senderID spec.SenderID,
	localServerName spec.ServerName,
) (*RestrictedRoomJoinInfo, error) {
	if r.roomInfoErr {
		return nil, errors.New("err")
	}

	if r.serverInRoomErr {
		return nil, errors.New("err")
	}
	serverInRoom := false
	if inRoom, ok := r.serverInRoom[roomID.String()]; ok {
		serverInRoom = inRoom
	}
	serverInRoom = r.roomExists && serverInRoom

	if r.membershipErr {
		return nil, errors.New("err")
	}

	if r.getJoinedUsersErr {
		return nil, errors.New("err")
	}

	return &RestrictedRoomJoinInfo{
		LocalServerInRoom: serverInRoom,
		UserJoinedToRoom:  r.joinerInRoom,
		JoinedUsers:       r.joinedUsers,
	}, nil
}

func TestHandleMakeJoin(t *testing.T) {
	remoteServer := spec.ServerName("remote")
	localServer := spec.ServerName("local")
	validUser, err := spec.NewUserID("@user:remote", true)
	require.NoError(t, err)
	validRoom, err := spec.NewRoomID("!room:remote")
	require.NoError(t, err)
	joinedUser, err := spec.NewUserID("@joined:local", true)
	require.NoError(t, err)
	allowedRoom, err := spec.NewRoomID("!allowed:local")
	require.NoError(t, err)

	_, sk, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	keyID := KeyID("ed25519:1234")

	stateKey := ""
	eb := MustGetRoomVersion(RoomVersionV10).NewEventBuilderFromProtoEvent(&ProtoEvent{
		SenderID:   validUser.String(),
		RoomID:     validRoom.String(),
		Type:       spec.MRoomCreate,
		StateKey:   &stateKey,
		PrevEvents: []interface{}{},
		AuthEvents: []interface{}{},
		Depth:      0,
		Content:    json.RawMessage(`{"creator":"@user:local","m.federate":true,"room_version":"10"}`),
		Unsigned:   json.RawMessage(""),
	})
	createEvent, err := eb.Build(time.Now(), validUser.Domain(), keyID, sk)
	require.NoError(t, err)

	stateKey = ""
	joinRulesEB := MustGetRoomVersion(RoomVersionV10).NewEventBuilderFromProtoEvent(&ProtoEvent{
		SenderID:   validUser.String(),
		RoomID:     validRoom.String(),
		Type:       spec.MRoomJoinRules,
		StateKey:   &stateKey,
		PrevEvents: []interface{}{createEvent.EventID()},
		AuthEvents: []interface{}{createEvent.EventID()},
		Depth:      1,
		Content:    json.RawMessage(`{"join_rule":"public"}`),
		Unsigned:   json.RawMessage(""),
	})
	joinRulesEvent, err := joinRulesEB.Build(time.Now(), validUser.Domain(), keyID, sk)
	require.NoError(t, err)

	stateKey = ""
	joinRulesPrivateEB := MustGetRoomVersion(RoomVersionV10).NewEventBuilderFromProtoEvent(&ProtoEvent{
		SenderID:   validUser.String(),
		RoomID:     validRoom.String(),
		Type:       spec.MRoomJoinRules,
		StateKey:   &stateKey,
		PrevEvents: []interface{}{createEvent.EventID()},
		AuthEvents: []interface{}{createEvent.EventID()},
		Depth:      1,
		Content:    json.RawMessage(`{"join_rule":"private"}`),
		Unsigned:   json.RawMessage(""),
	})
	joinRulesPrivateEvent, err := joinRulesPrivateEB.Build(time.Now(), validUser.Domain(), keyID, sk)
	require.NoError(t, err)

	stateKey = ""
	joinRulesRestrictedEB := MustGetRoomVersion(RoomVersionV10).NewEventBuilderFromProtoEvent(&ProtoEvent{
		SenderID:   validUser.String(),
		RoomID:     validRoom.String(),
		Type:       spec.MRoomJoinRules,
		StateKey:   &stateKey,
		PrevEvents: []interface{}{createEvent.EventID()},
		AuthEvents: []interface{}{createEvent.EventID()},
		Depth:      1,
		Content: json.RawMessage(
			`{"join_rule":"restricted","allow":[{"room_id":"!allowed:local","type":"m.room_membership"}]}`,
		),
		Unsigned: json.RawMessage(""),
	})
	joinRulesRestrictedEvent, err := joinRulesRestrictedEB.Build(time.Now(), validUser.Domain(), keyID, sk)
	require.NoError(t, err)

	stateKey = ""
	powerLevelsEB := MustGetRoomVersion(RoomVersionV10).NewEventBuilderFromProtoEvent(&ProtoEvent{
		SenderID:   validUser.String(),
		RoomID:     validRoom.String(),
		Type:       spec.MRoomJoinRules,
		StateKey:   &stateKey,
		PrevEvents: []interface{}{createEvent.EventID()},
		AuthEvents: []interface{}{createEvent.EventID()},
		Depth:      2,
		Content:    json.RawMessage(`{"users":{"@joined:local":100}}`),
		Unsigned:   json.RawMessage(""),
	})
	powerLevelsEvent, err := powerLevelsEB.Build(time.Now(), validUser.Domain(), keyID, sk)
	require.NoError(t, err)

	stateKey = validUser.String()
	joinEB := MustGetRoomVersion(RoomVersionV10).NewEventBuilderFromProtoEvent(&ProtoEvent{
		SenderID:   validUser.String(),
		RoomID:     validRoom.String(),
		Type:       spec.MRoomMember,
		StateKey:   &stateKey,
		PrevEvents: []interface{}{powerLevelsEvent.EventID()},
		AuthEvents: []interface{}{createEvent.EventID(), joinRulesEvent.EventID(), powerLevelsEvent.EventID()},
		Depth:      3,
		Content:    json.RawMessage(`{"membership":"join"}`),
		Unsigned:   json.RawMessage(""),
	})
	joinEvent, err := joinEB.Build(time.Now(), validUser.Domain(), keyID, sk)
	require.NoError(t, err)

	stateKey = joinedUser.String()
	joinedUserEB := MustGetRoomVersion(RoomVersionV10).NewEventBuilderFromProtoEvent(&ProtoEvent{
		SenderID:   joinedUser.String(),
		RoomID:     allowedRoom.String(),
		Type:       spec.MRoomMember,
		StateKey:   &stateKey,
		PrevEvents: []interface{}{powerLevelsEvent.EventID()},
		AuthEvents: []interface{}{createEvent.EventID(), joinRulesEvent.EventID(), powerLevelsEvent.EventID()},
		Depth:      3,
		Content:    json.RawMessage(`{"membership":"join"}`),
		Unsigned:   json.RawMessage(""),
	})
	joinedUserEvent, err := joinedUserEB.Build(time.Now(), joinedUser.Domain(), keyID, sk)
	require.NoError(t, err)

	type ErrorType int
	const (
		InternalErr ErrorType = iota
		MatrixErr
		IncompatibleRoomVersionErr
	)

	tests := map[string]struct {
		input       HandleMakeJoinInput
		expectedErr bool
		errType     ErrorType
		errCode     spec.MatrixErrorCode
	}{
		"unsupported_room_version": {
			input: HandleMakeJoinInput{
				Context:            t.Context(),
				UserID:             *validUser,
				RoomID:             *validRoom,
				RoomVersion:        RoomVersionV10,
				RemoteVersions:     []RoomVersion{},
				RequestOrigin:      remoteServer,
				LocalServerName:    localServer,
				RoomQuerier:        &TestRestrictedRoomJoinQuerier{},
				UserIDQuerier:      UserIDForSenderTest,
				BuildEventTemplate: func(*ProtoEvent) (PDU, []PDU, error) { return nil, nil, nil },
			},
			expectedErr: true,
			errType:     IncompatibleRoomVersionErr,
		},
		"mismatched_user_and_origin": {
			input: HandleMakeJoinInput{
				Context:            t.Context(),
				UserID:             *validUser,
				RoomID:             *validRoom,
				RoomVersion:        RoomVersionV10,
				RemoteVersions:     []RoomVersion{RoomVersionV10},
				RequestOrigin:      "random.server",
				LocalServerName:    localServer,
				RoomQuerier:        &TestRestrictedRoomJoinQuerier{},
				UserIDQuerier:      UserIDForSenderTest,
				BuildEventTemplate: func(*ProtoEvent) (PDU, []PDU, error) { return nil, nil, nil },
			},
			expectedErr: true,
			errCode:     spec.ErrorForbidden,
			errType:     MatrixErr,
		},
		"server_room_doesnt_exist": {
			input: HandleMakeJoinInput{
				Context:         t.Context(),
				UserID:          *validUser,
				RoomID:          *validRoom,
				RoomVersion:     RoomVersionV10,
				RemoteVersions:  []RoomVersion{RoomVersionV10},
				RequestOrigin:   remoteServer,
				LocalServerName: localServer,
				RoomQuerier: &TestRestrictedRoomJoinQuerier{
					serverInRoom: map[string]bool{validRoom.String(): true},
				},
				UserIDQuerier:      UserIDForSenderTest,
				BuildEventTemplate: func(*ProtoEvent) (PDU, []PDU, error) { return nil, nil, nil },
			},
			expectedErr: true,
			errCode:     spec.ErrorNotFound,
			errType:     MatrixErr,
		},
		"server_not_in_room": {
			input: HandleMakeJoinInput{
				Context:            t.Context(),
				UserID:             *validUser,
				RoomID:             *validRoom,
				RoomVersion:        RoomVersionV10,
				RemoteVersions:     []RoomVersion{RoomVersionV10},
				RequestOrigin:      remoteServer,
				LocalServerName:    localServer,
				RoomQuerier:        &TestRestrictedRoomJoinQuerier{roomExists: true},
				UserIDQuerier:      UserIDForSenderTest,
				BuildEventTemplate: func(*ProtoEvent) (PDU, []PDU, error) { return nil, []PDU{}, nil },
			},
			expectedErr: true,
			errCode:     spec.ErrorNotFound,
			errType:     MatrixErr,
		},
		"cant_join_private_room": {
			input: HandleMakeJoinInput{
				Context:           t.Context(),
				UserID:            *validUser,
				RoomID:            *validRoom,
				RoomVersion:       RoomVersionV10,
				RemoteVersions:    []RoomVersion{RoomVersionV10},
				RequestOrigin:     remoteServer,
				LocalServerName:   localServer,
				LocalServerInRoom: true,
				RoomQuerier: &TestRestrictedRoomJoinQuerier{
					roomExists:   true,
					serverInRoom: map[string]bool{validRoom.String(): true},
				},
				UserIDQuerier: UserIDForSenderTest,
				BuildEventTemplate: func(*ProtoEvent) (PDU, []PDU, error) {
					return joinEvent, []PDU{createEvent, joinRulesPrivateEvent}, nil
				},
			},
			expectedErr: true,
			errCode:     spec.ErrorForbidden,
			errType:     MatrixErr,
		},
		"invalid_template_state": {
			input: HandleMakeJoinInput{
				Context:           t.Context(),
				UserID:            *validUser,
				RoomID:            *validRoom,
				RoomVersion:       RoomVersionV10,
				RemoteVersions:    []RoomVersion{RoomVersionV10},
				RequestOrigin:     remoteServer,
				LocalServerName:   localServer,
				LocalServerInRoom: true,
				RoomQuerier: &TestRestrictedRoomJoinQuerier{
					roomExists:   true,
					serverInRoom: map[string]bool{validRoom.String(): true},
				},
				UserIDQuerier: UserIDForSenderTest,
				BuildEventTemplate: func(*ProtoEvent) (PDU, []PDU, error) {
					return joinEvent, nil, nil
				},
			},
			expectedErr: true,
			errType:     InternalErr,
		},
		"invalid_template_event": {
			input: HandleMakeJoinInput{
				Context:           t.Context(),
				UserID:            *validUser,
				RoomID:            *validRoom,
				RoomVersion:       RoomVersionV10,
				RemoteVersions:    []RoomVersion{RoomVersionV10},
				RequestOrigin:     remoteServer,
				LocalServerName:   localServer,
				LocalServerInRoom: true,
				RoomQuerier: &TestRestrictedRoomJoinQuerier{
					roomExists:   true,
					serverInRoom: map[string]bool{validRoom.String(): true},
				},
				UserIDQuerier: UserIDForSenderTest,
				BuildEventTemplate: func(*ProtoEvent) (PDU, []PDU, error) {
					return nil, []PDU{createEvent, joinRulesEvent}, nil
				},
			},
			expectedErr: true,
			errType:     InternalErr,
		},
		"template_event_not_join": {
			input: HandleMakeJoinInput{
				Context:           t.Context(),
				UserID:            *validUser,
				RoomID:            *validRoom,
				RoomVersion:       RoomVersionV10,
				RemoteVersions:    []RoomVersion{RoomVersionV10},
				RequestOrigin:     remoteServer,
				LocalServerName:   localServer,
				LocalServerInRoom: true,
				RoomQuerier: &TestRestrictedRoomJoinQuerier{
					roomExists:   true,
					serverInRoom: map[string]bool{validRoom.String(): true},
				},
				UserIDQuerier: UserIDForSenderTest,
				BuildEventTemplate: func(*ProtoEvent) (PDU, []PDU, error) {
					return createEvent, []PDU{createEvent, joinRulesEvent}, nil
				},
			},
			expectedErr: true,
			errType:     InternalErr,
		},
		"success_no_join_rules": {
			input: HandleMakeJoinInput{
				Context:           t.Context(),
				UserID:            *validUser,
				RoomID:            *validRoom,
				RoomVersion:       RoomVersionV10,
				RemoteVersions:    []RoomVersion{RoomVersionV10},
				RequestOrigin:     remoteServer,
				LocalServerName:   localServer,
				LocalServerInRoom: true,
				RoomQuerier: &TestRestrictedRoomJoinQuerier{
					roomExists:   true,
					serverInRoom: map[string]bool{validRoom.String(): true},
				},
				UserIDQuerier: UserIDForSenderTest,
				BuildEventTemplate: func(*ProtoEvent) (PDU, []PDU, error) {
					return joinEvent, []PDU{createEvent, joinRulesEvent}, nil
				},
			},
			expectedErr: false,
		},
		"success_with_public_join_rules": {
			input: HandleMakeJoinInput{
				Context:           t.Context(),
				UserID:            *validUser,
				RoomID:            *validRoom,
				RoomVersion:       RoomVersionV10,
				RemoteVersions:    []RoomVersion{RoomVersionV10},
				RequestOrigin:     remoteServer,
				LocalServerName:   localServer,
				LocalServerInRoom: true,
				RoomQuerier: &TestRestrictedRoomJoinQuerier{
					roomExists:     true,
					serverInRoom:   map[string]bool{validRoom.String(): true},
					joinRulesEvent: joinRulesEvent,
				},
				UserIDQuerier: UserIDForSenderTest,
				BuildEventTemplate: func(*ProtoEvent) (PDU, []PDU, error) {
					return joinEvent, []PDU{createEvent, joinRulesEvent}, nil
				},
			},
			expectedErr: false,
		},
		"success_restricted_join_pending_invite": {
			input: HandleMakeJoinInput{
				Context:           t.Context(),
				UserID:            *validUser,
				RoomID:            *validRoom,
				RoomVersion:       RoomVersionV10,
				RemoteVersions:    []RoomVersion{RoomVersionV10},
				RequestOrigin:     remoteServer,
				LocalServerName:   localServer,
				LocalServerInRoom: true,
				RoomQuerier: &TestRestrictedRoomJoinQuerier{
					roomExists:     true,
					serverInRoom:   map[string]bool{validRoom.String(): true},
					pendingInvite:  true,
					joinRulesEvent: joinRulesRestrictedEvent,
				},
				UserIDQuerier: UserIDForSenderTest,
				BuildEventTemplate: func(*ProtoEvent) (PDU, []PDU, error) {
					return joinEvent, []PDU{createEvent, joinRulesEvent}, nil
				},
			},
			expectedErr: false,
		},
		"success_restricted_join_member_with_invite_power": {
			input: HandleMakeJoinInput{
				Context:           t.Context(),
				UserID:            *validUser,
				RoomID:            *validRoom,
				RoomVersion:       RoomVersionV10,
				RemoteVersions:    []RoomVersion{RoomVersionV10},
				RequestOrigin:     remoteServer,
				LocalServerName:   localServer,
				LocalServerInRoom: true,
				RoomQuerier: &TestRestrictedRoomJoinQuerier{
					roomExists: true,
					serverInRoom: map[string]bool{validRoom.String(): true,
						allowedRoom.String(): true},
					joinerInRoom:     true,
					joinedUsers:      []PDU{joinedUserEvent},
					joinRulesEvent:   joinRulesRestrictedEvent,
					powerLevelsEvent: powerLevelsEvent,
				},
				UserIDQuerier: UserIDForSenderTest,
				BuildEventTemplate: func(*ProtoEvent) (PDU, []PDU, error) {
					return joinEvent, []PDU{createEvent, joinRulesEvent}, nil
				},
			},
			expectedErr: false,
		},
		"failure_restricted_join_not_resident": {
			input: HandleMakeJoinInput{
				Context:           t.Context(),
				UserID:            *validUser,
				RoomID:            *validRoom,
				RoomVersion:       RoomVersionV10,
				RemoteVersions:    []RoomVersion{RoomVersionV10},
				RequestOrigin:     remoteServer,
				LocalServerName:   localServer,
				LocalServerInRoom: true,
				RoomQuerier: &TestRestrictedRoomJoinQuerier{
					roomExists:       true,
					serverInRoom:     map[string]bool{validRoom.String(): true},
					joinerInRoom:     true,
					joinedUsers:      []PDU{joinedUserEvent},
					joinRulesEvent:   joinRulesRestrictedEvent,
					powerLevelsEvent: powerLevelsEvent,
				},
				UserIDQuerier: UserIDForSenderTest,
				BuildEventTemplate: func(*ProtoEvent) (PDU, []PDU, error) {
					return joinEvent, []PDU{createEvent, joinRulesEvent}, nil
				},
			},
			expectedErr: true,
			errCode:     spec.ErrorUnableToAuthoriseJoin,
			errType:     MatrixErr,
		},
		"failure_restricted_join_no_member_with_invite_power": {
			input: HandleMakeJoinInput{
				Context:           t.Context(),
				UserID:            *validUser,
				RoomID:            *validRoom,
				RoomVersion:       RoomVersionV10,
				RemoteVersions:    []RoomVersion{RoomVersionV10},
				RequestOrigin:     remoteServer,
				LocalServerName:   localServer,
				LocalServerInRoom: true,
				RoomQuerier: &TestRestrictedRoomJoinQuerier{
					roomExists: true,
					serverInRoom: map[string]bool{validRoom.String(): true,
						allowedRoom.String(): true},
					joinedUsers:      []PDU{joinedUserEvent},
					joinRulesEvent:   joinRulesRestrictedEvent,
					powerLevelsEvent: powerLevelsEvent,
				},
				UserIDQuerier: UserIDForSenderTest,
				BuildEventTemplate: func(*ProtoEvent) (PDU, []PDU, error) {
					return joinEvent, []PDU{createEvent, joinRulesEvent}, nil
				},
			},
			expectedErr: true,
			errCode:     spec.ErrorForbidden,
			errType:     MatrixErr,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, joinErr := HandleMakeJoin(tc.input)
			if tc.expectedErr {
				switch e := joinErr.(type) {
				case nil:
					t.Fatalf("Error should not be nil")
				case spec.InternalServerError:
					assert.Equal(t, InternalErr, tc.errType)
				case spec.MatrixError:
					assert.Equal(t, MatrixErr, tc.errType)
					assert.Equal(t, tc.errCode, e.ErrCode)
				case spec.IncompatibleRoomVersionError:
					assert.Equal(t, IncompatibleRoomVersionErr, tc.errType)
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

func TestHandleMakeJoinNilRoomQuerier(t *testing.T) {
	remoteServer := spec.ServerName("remote")
	localServer := spec.ServerName("local")
	validUser, err := spec.NewUserID("@user:remote", true)
	require.NoError(t, err)
	validRoom, err := spec.NewRoomID("!room:remote")
	require.NoError(t, err)

	assert.Panics(t, func() {
		_, _ = HandleMakeJoin(HandleMakeJoinInput{
			Context:            t.Context(),
			UserID:             *validUser,
			RoomID:             *validRoom,
			RoomVersion:        RoomVersionV10,
			RemoteVersions:     []RoomVersion{RoomVersionV10},
			RequestOrigin:      remoteServer,
			LocalServerName:    localServer,
			RoomQuerier:        nil,
			UserIDQuerier:      UserIDForSenderTest,
			BuildEventTemplate: func(*ProtoEvent) (PDU, []PDU, error) { return nil, nil, nil },
		})
	})
}

func TestHandleMakeJoinNilUserIDQuerier(t *testing.T) {
	remoteServer := spec.ServerName("remote")
	localServer := spec.ServerName("local")
	validUser, err := spec.NewUserID("@user:remote", true)
	require.NoError(t, err)
	validRoom, err := spec.NewRoomID("!room:remote")
	require.NoError(t, err)

	assert.Panics(t, func() {
		_, _ = HandleMakeJoin(HandleMakeJoinInput{
			Context:            t.Context(),
			UserID:             *validUser,
			RoomID:             *validRoom,
			RoomVersion:        RoomVersionV10,
			RemoteVersions:     []RoomVersion{RoomVersionV10},
			RequestOrigin:      remoteServer,
			LocalServerName:    localServer,
			RoomQuerier:        &TestRestrictedRoomJoinQuerier{},
			UserIDQuerier:      nil,
			BuildEventTemplate: func(*ProtoEvent) (PDU, []PDU, error) { return nil, nil, nil },
		})
	})
}

func TestHandleMakeJoinNilContext(t *testing.T) {
	remoteServer := spec.ServerName("remote")
	localServer := spec.ServerName("local")
	validUser, err := spec.NewUserID("@user:remote", true)
	require.NoError(t, err)
	validRoom, err := spec.NewRoomID("!room:remote")
	require.NoError(t, err)

	assert.Panics(t, func() {
		_, _ = HandleMakeJoin(HandleMakeJoinInput{
			Context:            nil,
			UserID:             *validUser,
			RoomID:             *validRoom,
			RoomVersion:        RoomVersionV10,
			RemoteVersions:     []RoomVersion{RoomVersionV10},
			RequestOrigin:      remoteServer,
			LocalServerName:    localServer,
			RoomQuerier:        &TestRestrictedRoomJoinQuerier{},
			UserIDQuerier:      UserIDForSenderTest,
			BuildEventTemplate: func(*ProtoEvent) (PDU, []PDU, error) { return nil, nil, nil },
		})
	})
}

func createMemberEventBuilder(
	roomVersion RoomVersion,
	sender string,
	roomID string,
	stateKey *string,
	content json.RawMessage,
) *EventBuilder {
	return MustGetRoomVersion(roomVersion).NewEventBuilderFromProtoEvent(&ProtoEvent{
		SenderID:   sender,
		RoomID:     roomID,
		Type:       "m.room.member",
		StateKey:   stateKey,
		PrevEvents: []interface{}{},
		AuthEvents: []interface{}{},
		Depth:      0,
		Content:    content,
		Unsigned:   json.RawMessage(""),
	})
}

func TestHandleSendJoin(t *testing.T) {
	userID, err := spec.NewUserID("@user:server", true)
	require.NoError(t, err)
	remoteServer := spec.ServerName("server")
	localServer := spec.ServerName("local")
	validRoom, err := spec.NewRoomID("!room:server")
	require.NoError(t, err)
	badRoom, err := spec.NewRoomID("!bad:room")
	require.NoError(t, err)

	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	badPK, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	keyID := KeyID("ed25519:1234")
	verifier := &KeyRing{[]KeyFetcher{&TestRequestKeyDummy{}}, &joinKeyDatabase{key: pk}}
	badVerifier := &KeyRing{[]KeyFetcher{&TestRequestKeyDummy{}}, &joinKeyDatabase{key: badPK}}

	stateKey := userID.String()
	eb := createMemberEventBuilder(
		RoomVersionV10,
		userID.String(),
		validRoom.String(),
		&stateKey,
		json.RawMessage(`{"membership":"join"}`),
	)
	joinEvent, err := eb.Build(time.Now(), userID.Domain(), keyID, sk)
	require.NoError(t, err)

	// create a pseudoID join event
	_, userPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pseudoID := spec.SenderIDFromPseudoIDKey(userPriv)
	stateKey = string(pseudoID)
	mapping := MXIDMapping{UserID: userID.String(), UserRoomKey: pseudoID}
	err = mapping.Sign(remoteServer, keyID, sk)
	require.NoError(t, err)
	content := MemberContent{Membership: spec.Join, MXIDMapping: &mapping}
	contentBytes, err := json.Marshal(content)
	require.NoError(t, err)
	eb = createMemberEventBuilder(RoomVersionPseudoIDs, stateKey, validRoom.String(), &stateKey, contentBytes)
	joinEventPseudoID, err := eb.Build(time.Now(), spec.ServerName(pseudoID), "ed25519:1", userPriv)
	require.NoError(t, err)

	ebNotJoin := createMemberEventBuilder(
		RoomVersionV10,
		userID.String(),
		validRoom.String(),
		&stateKey,
		json.RawMessage(`{"membership":"ban"}`),
	)
	notJoinEvent, err := ebNotJoin.Build(time.Now(), userID.Domain(), keyID, sk)
	require.NoError(t, err)

	eb2 := createMemberEventBuilder(
		RoomVersionV10,
		"@asdf:asdf",
		validRoom.String(),
		&stateKey,
		json.RawMessage(`{"membership":"join"}`),
	)
	joinEventInvalidSender, err := eb2.Build(time.Now(), userID.Domain(), keyID, sk)
	require.NoError(t, err)

	stateKey = ""
	eb3 := createMemberEventBuilder(
		RoomVersionV10,
		userID.String(),
		validRoom.String(),
		&stateKey,
		json.RawMessage(`{"membership":"join"}`),
	)
	joinEventNoState, err := eb3.Build(time.Now(), userID.Domain(), keyID, sk)
	require.NoError(t, err)

	stateKey = userID.String()
	badAuthViaEB := createMemberEventBuilder(
		RoomVersionV10,
		userID.String(),
		validRoom.String(),
		&stateKey,
		json.RawMessage(`{"membership":"join","join_authorised_via_users_server":"baduser"}`),
	)
	badAuthViaEvent, err := badAuthViaEB.Build(time.Now(), userID.Domain(), keyID, sk)
	require.NoError(t, err)

	authViaNotLocalEB := createMemberEventBuilder(
		RoomVersionV10,
		userID.String(),
		validRoom.String(),
		&stateKey,
		json.RawMessage(`{"membership":"join","join_authorised_via_users_server":"@user:notlocalserver"}`),
	)
	authViaNotLocalEvent, err := authViaNotLocalEB.Build(time.Now(), userID.Domain(), keyID, sk)
	require.NoError(t, err)

	authViaEB := createMemberEventBuilder(
		RoomVersionV10,
		userID.String(),
		validRoom.String(),
		&stateKey,
		json.RawMessage(`{"membership":"join","join_authorised_via_users_server":"@user:local"}`),
	)
	authViaEvent, err := authViaEB.Build(time.Now(), userID.Domain(), keyID, sk)
	require.NoError(t, err)

	type ErrorType int
	const (
		InternalErr ErrorType = iota
		MatrixErr
	)

	tests := map[string]struct {
		input       HandleSendJoinInput
		expectedErr bool
		errType     ErrorType
		errCode     spec.MatrixErrorCode
	}{
		"unsupported_room_version": {
			input: HandleSendJoinInput{
				Context:           t.Context(),
				RoomID:            *validRoom,
				EventID:           joinEvent.EventID(),
				JoinEvent:         joinEvent.JSON(),
				RoomVersion:       "",
				RequestOrigin:     remoteServer,
				LocalServerName:   localServer,
				MembershipQuerier: &TestMembershipQuerier{},
				UserIDQuerier:     UserIDForSenderTest,
				KeyID:             keyID,
				PrivateKey:        sk,
				Verifier:          verifier,
			},
			expectedErr: true,
			errType:     MatrixErr,
			errCode:     spec.ErrorUnsupportedRoomVersion,
		},
		"invalid_event_json": {
			input: HandleSendJoinInput{
				Context:           t.Context(),
				RoomID:            *validRoom,
				EventID:           joinEvent.EventID(),
				JoinEvent:         []byte{'b'},
				RoomVersion:       RoomVersionV10,
				RequestOrigin:     remoteServer,
				LocalServerName:   localServer,
				MembershipQuerier: &TestMembershipQuerier{},
				UserIDQuerier:     UserIDForSenderTest,
				KeyID:             keyID,
				PrivateKey:        sk,
				Verifier:          verifier,
			},
			expectedErr: true,
			errType:     MatrixErr,
			errCode:     spec.ErrorBadJSON,
		},
		"invalid_event_state_key": {
			input: HandleSendJoinInput{
				Context:           t.Context(),
				RoomID:            *validRoom,
				EventID:           joinEventNoState.EventID(),
				JoinEvent:         joinEventNoState.JSON(),
				RoomVersion:       RoomVersionV10,
				RequestOrigin:     remoteServer,
				LocalServerName:   localServer,
				MembershipQuerier: &TestMembershipQuerier{},
				UserIDQuerier:     UserIDForSenderTest,
				KeyID:             keyID,
				PrivateKey:        sk,
				Verifier:          verifier,
			},
			expectedErr: true,
			errType:     MatrixErr,
			errCode:     spec.ErrorBadJSON,
		},
		"invalid_event_sender": {
			input: HandleSendJoinInput{
				Context:           t.Context(),
				RoomID:            *validRoom,
				EventID:           joinEventInvalidSender.EventID(),
				JoinEvent:         joinEventInvalidSender.JSON(),
				RoomVersion:       RoomVersionV10,
				RequestOrigin:     remoteServer,
				LocalServerName:   localServer,
				MembershipQuerier: &TestMembershipQuerier{},
				UserIDQuerier:     UserIDForSenderTest,
				KeyID:             keyID,
				PrivateKey:        sk,
				Verifier:          verifier,
			},
			expectedErr: true,
			errType:     MatrixErr,
			errCode:     spec.ErrorBadJSON,
		},
		"sender_does_not_match_request_origin": {
			input: HandleSendJoinInput{
				Context:           t.Context(),
				RoomID:            *validRoom,
				EventID:           joinEvent.EventID(),
				JoinEvent:         joinEvent.JSON(),
				RoomVersion:       RoomVersionV10,
				RequestOrigin:     "bad_origin",
				LocalServerName:   localServer,
				MembershipQuerier: &TestMembershipQuerier{},
				UserIDQuerier:     UserIDForSenderTest,
				KeyID:             keyID,
				PrivateKey:        sk,
				Verifier:          verifier,
			},
			expectedErr: true,
			errType:     MatrixErr,
			errCode:     spec.ErrorForbidden,
		},
		"roomid_does_not_match_json": {
			input: HandleSendJoinInput{
				Context:           t.Context(),
				RoomID:            *badRoom,
				EventID:           joinEvent.EventID(),
				JoinEvent:         joinEvent.JSON(),
				RoomVersion:       RoomVersionV10,
				RequestOrigin:     remoteServer,
				LocalServerName:   localServer,
				MembershipQuerier: &TestMembershipQuerier{},
				UserIDQuerier:     UserIDForSenderTest,
				KeyID:             keyID,
				PrivateKey:        sk,
				Verifier:          verifier,
			},
			expectedErr: true,
			errType:     MatrixErr,
			errCode:     spec.ErrorBadJSON,
		},
		"eventid_does_not_match_json": {
			input: HandleSendJoinInput{
				Context:           t.Context(),
				RoomID:            *validRoom,
				EventID:           "badevent",
				JoinEvent:         joinEvent.JSON(),
				RoomVersion:       RoomVersionV10,
				RequestOrigin:     remoteServer,
				LocalServerName:   localServer,
				MembershipQuerier: &TestMembershipQuerier{},
				UserIDQuerier:     UserIDForSenderTest,
				KeyID:             keyID,
				PrivateKey:        sk,
				Verifier:          verifier,
			},
			expectedErr: true,
			errType:     MatrixErr,
			errCode:     spec.ErrorBadJSON,
		},
		"member_event_not_join": {
			input: HandleSendJoinInput{
				Context:           t.Context(),
				RoomID:            *validRoom,
				EventID:           notJoinEvent.EventID(),
				JoinEvent:         notJoinEvent.JSON(),
				RoomVersion:       RoomVersionV10,
				RequestOrigin:     remoteServer,
				LocalServerName:   localServer,
				MembershipQuerier: &TestMembershipQuerier{},
				UserIDQuerier:     UserIDForSenderTest,
				KeyID:             keyID,
				PrivateKey:        sk,
				Verifier:          verifier,
			},
			expectedErr: true,
			errType:     MatrixErr,
			errCode:     spec.ErrorBadJSON,
		},
		"event_not_signed_correctly": {
			input: HandleSendJoinInput{
				Context:           t.Context(),
				RoomID:            *validRoom,
				EventID:           joinEvent.EventID(),
				JoinEvent:         joinEvent.JSON(),
				RoomVersion:       RoomVersionV10,
				RequestOrigin:     remoteServer,
				LocalServerName:   localServer,
				MembershipQuerier: &TestMembershipQuerier{},
				UserIDQuerier:     UserIDForSenderTest,
				KeyID:             keyID,
				PrivateKey:        sk,
				Verifier:          badVerifier,
			},
			expectedErr: true,
			errType:     MatrixErr,
			errCode:     spec.ErrorForbidden,
		},
		"state_event_lookup_failure": {
			input: HandleSendJoinInput{
				Context:           t.Context(),
				RoomID:            *validRoom,
				EventID:           joinEvent.EventID(),
				JoinEvent:         joinEvent.JSON(),
				RoomVersion:       RoomVersionV10,
				RequestOrigin:     remoteServer,
				LocalServerName:   localServer,
				MembershipQuerier: &TestMembershipQuerier{memberEventErr: true},
				UserIDQuerier:     UserIDForSenderTest,
				KeyID:             keyID,
				PrivateKey:        sk,
				Verifier:          verifier,
			},
			expectedErr: true,
			errType:     InternalErr,
		},
		"existing_member_banned": {
			input: HandleSendJoinInput{
				Context:           t.Context(),
				RoomID:            *validRoom,
				EventID:           joinEvent.EventID(),
				JoinEvent:         joinEvent.JSON(),
				RoomVersion:       RoomVersionV10,
				RequestOrigin:     remoteServer,
				LocalServerName:   localServer,
				MembershipQuerier: &TestMembershipQuerier{membership: spec.Ban},
				UserIDQuerier:     UserIDForSenderTest,
				KeyID:             keyID,
				PrivateKey:        sk,
				Verifier:          verifier,
			},
			expectedErr: true,
			errType:     MatrixErr,
			errCode:     spec.ErrorForbidden,
		},
		"auth_via_bad_username": {
			input: HandleSendJoinInput{
				Context:           t.Context(),
				RoomID:            *validRoom,
				EventID:           badAuthViaEvent.EventID(),
				JoinEvent:         badAuthViaEvent.JSON(),
				RoomVersion:       RoomVersionV10,
				RequestOrigin:     remoteServer,
				LocalServerName:   localServer,
				MembershipQuerier: &TestMembershipQuerier{},
				UserIDQuerier:     UserIDForSenderTest,
				KeyID:             keyID,
				PrivateKey:        sk,
				Verifier:          verifier,
			},
			expectedErr: true,
			errType:     MatrixErr,
			errCode:     spec.ErrorBadJSON,
		},
		"auth_via_not_local_username": {
			input: HandleSendJoinInput{
				Context:           t.Context(),
				RoomID:            *validRoom,
				EventID:           authViaNotLocalEvent.EventID(),
				JoinEvent:         authViaNotLocalEvent.JSON(),
				RoomVersion:       RoomVersionV10,
				RequestOrigin:     remoteServer,
				LocalServerName:   localServer,
				MembershipQuerier: &TestMembershipQuerier{},
				UserIDQuerier:     UserIDForSenderTest,
				KeyID:             keyID,
				PrivateKey:        sk,
				Verifier:          verifier,
			},
			expectedErr: true,
			errType:     MatrixErr,
			errCode:     spec.ErrorBadJSON,
		},
		"existing_member_allowed": {
			input: HandleSendJoinInput{
				Context:           t.Context(),
				RoomID:            *validRoom,
				EventID:           joinEvent.EventID(),
				JoinEvent:         joinEvent.JSON(),
				RoomVersion:       RoomVersionV10,
				RequestOrigin:     remoteServer,
				LocalServerName:   localServer,
				MembershipQuerier: &TestMembershipQuerier{membership: spec.Join},
				UserIDQuerier:     UserIDForSenderTest,
				KeyID:             keyID,
				PrivateKey:        sk,
				Verifier:          verifier,
			},
			expectedErr: false,
		},
		"success_auth_via": {
			input: HandleSendJoinInput{
				Context:           t.Context(),
				RoomID:            *validRoom,
				EventID:           authViaEvent.EventID(),
				JoinEvent:         authViaEvent.JSON(),
				RoomVersion:       RoomVersionV10,
				RequestOrigin:     remoteServer,
				LocalServerName:   localServer,
				MembershipQuerier: &TestMembershipQuerier{},
				UserIDQuerier:     UserIDForSenderTest,
				KeyID:             keyID,
				PrivateKey:        sk,
				Verifier:          verifier,
			},
			expectedErr: false,
		},
		"basic_success": {
			input: HandleSendJoinInput{
				Context:           t.Context(),
				RoomID:            *validRoom,
				EventID:           joinEvent.EventID(),
				JoinEvent:         joinEvent.JSON(),
				RoomVersion:       RoomVersionV10,
				RequestOrigin:     remoteServer,
				LocalServerName:   localServer,
				MembershipQuerier: &TestMembershipQuerier{},
				UserIDQuerier:     UserIDForSenderTest,
				KeyID:             keyID,
				PrivateKey:        sk,
				Verifier:          verifier,
			},
			expectedErr: false,
		},
		"pseudo_id_success": {
			input: HandleSendJoinInput{
				Context:           t.Context(),
				RoomID:            *validRoom,
				EventID:           joinEventPseudoID.EventID(),
				JoinEvent:         joinEventPseudoID.JSON(),
				RoomVersion:       RoomVersionPseudoIDs,
				RequestOrigin:     remoteServer,
				LocalServerName:   localServer,
				MembershipQuerier: &TestMembershipQuerier{membership: "join"},
				UserIDQuerier: func(roomID spec.RoomID, senderID spec.SenderID) (*spec.UserID, error) {
					return userID, nil
				},
				KeyID:      keyID,
				PrivateKey: sk,
				Verifier:   verifier,
			},
			expectedErr: false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if tc.input.StoreSenderIDFromPublicID == nil {
				tc.input.StoreSenderIDFromPublicID = func(ctx context.Context, senderID spec.SenderID, userID string, id spec.RoomID) error {
					return nil
				}
			}
			_, joinErr := HandleSendJoin(tc.input)
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

func TestHandleSendJoinNilVerifier(t *testing.T) {
	remoteServer := spec.ServerName("remote")
	localServer := spec.ServerName("local")
	validRoom, err := spec.NewRoomID("!room:remote")
	require.NoError(t, err)

	_, sk, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	keyID := KeyID("ed25519:1234")

	assert.Panics(t, func() {
		_, _ = HandleSendJoin(HandleSendJoinInput{
			Context:           t.Context(),
			RoomID:            *validRoom,
			EventID:           "#event",
			RoomVersion:       RoomVersionV10,
			RequestOrigin:     remoteServer,
			LocalServerName:   localServer,
			MembershipQuerier: &TestMembershipQuerier{},
			UserIDQuerier:     UserIDForSenderTest,
			KeyID:             keyID,
			PrivateKey:        sk,
			Verifier:          nil,
		})
	})
}

func TestHandleSendJoinNilMembershipQuerier(t *testing.T) {
	remoteServer := spec.ServerName("remote")
	localServer := spec.ServerName("local")
	validRoom, err := spec.NewRoomID("!room:remote")
	require.NoError(t, err)

	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	keyID := KeyID("ed25519:1234")
	verifier := &KeyRing{[]KeyFetcher{&TestRequestKeyDummy{}}, &joinKeyDatabase{key: pk}}

	assert.Panics(t, func() {
		_, _ = HandleSendJoin(HandleSendJoinInput{
			Context:           t.Context(),
			RoomID:            *validRoom,
			EventID:           "#event",
			RoomVersion:       RoomVersionV10,
			RequestOrigin:     remoteServer,
			LocalServerName:   localServer,
			MembershipQuerier: nil,
			UserIDQuerier:     UserIDForSenderTest,
			KeyID:             keyID,
			PrivateKey:        sk,
			Verifier:          verifier,
		})
	})
}

func TestHandleSendJoinNilUserIDQuerier(t *testing.T) {
	remoteServer := spec.ServerName("remote")
	localServer := spec.ServerName("local")
	validRoom, err := spec.NewRoomID("!room:remote")
	require.NoError(t, err)

	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	keyID := KeyID("ed25519:1234")
	verifier := &KeyRing{[]KeyFetcher{&TestRequestKeyDummy{}}, &joinKeyDatabase{key: pk}}

	assert.Panics(t, func() {
		_, _ = HandleSendJoin(HandleSendJoinInput{
			Context:           t.Context(),
			RoomID:            *validRoom,
			EventID:           "#event",
			RoomVersion:       RoomVersionV10,
			RequestOrigin:     remoteServer,
			LocalServerName:   localServer,
			MembershipQuerier: &TestMembershipQuerier{},
			UserIDQuerier:     nil,
			KeyID:             keyID,
			PrivateKey:        sk,
			Verifier:          verifier,
		})
	})
}

func TestHandleSendJoinNilContext(t *testing.T) {
	remoteServer := spec.ServerName("remote")
	localServer := spec.ServerName("local")
	validRoom, err := spec.NewRoomID("!room:remote")
	require.NoError(t, err)

	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	keyID := KeyID("ed25519:1234")
	verifier := &KeyRing{[]KeyFetcher{&TestRequestKeyDummy{}}, &joinKeyDatabase{key: pk}}

	assert.Panics(t, func() {
		_, _ = HandleSendJoin(HandleSendJoinInput{
			Context:           nil,
			RoomID:            *validRoom,
			EventID:           "#event",
			RoomVersion:       RoomVersionV10,
			RequestOrigin:     remoteServer,
			LocalServerName:   localServer,
			MembershipQuerier: &TestMembershipQuerier{},
			UserIDQuerier:     UserIDForSenderTest,
			KeyID:             keyID,
			PrivateKey:        sk,
			Verifier:          verifier,
		})
	})
}

func TestHandleSendJoinNilStoreSenderIDFromPublicID(t *testing.T) {
	remoteServer := spec.ServerName("remote")
	localServer := spec.ServerName("local")
	validRoom, err := spec.NewRoomID("!room:remote")
	require.NoError(t, err)

	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	keyID := KeyID("ed25519:1234")
	verifier := &KeyRing{[]KeyFetcher{&TestRequestKeyDummy{}}, &joinKeyDatabase{key: pk}}

	assert.Panics(t, func() {
		_, _ = HandleSendJoin(HandleSendJoinInput{
			Context:           t.Context(),
			RoomID:            *validRoom,
			EventID:           "#event",
			RoomVersion:       RoomVersionV10,
			RequestOrigin:     remoteServer,
			LocalServerName:   localServer,
			MembershipQuerier: &TestMembershipQuerier{},
			UserIDQuerier:     UserIDForSenderTest,
			KeyID:             keyID,
			PrivateKey:        sk,
			Verifier:          verifier,
		})
	})
}
