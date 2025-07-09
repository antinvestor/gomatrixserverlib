//nolint:testpackage
package gomatrixserverlib

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/antinvestor/gomatrixserverlib/spec"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ed25519"
)

func TestHandleMakeLeave(t *testing.T) {
	validUser, err := spec.NewUserID("@user:remote", true)
	require.NoError(t, err)
	validRoom, err := spec.NewRoomID("!room:remote")
	require.NoError(t, err)
	joinedUser, err := spec.NewUserID("@joined:local", true)
	require.NoError(t, err)

	_, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed generating key: %v", err)
	}
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
	if err != nil {
		t.Fatalf("Failed building create event: %v", err)
	}

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
	if err != nil {
		t.Fatalf("Failed building join_rules event: %v", err)
	}

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
	if err != nil {
		t.Fatalf("Failed building power_levels event: %v", err)
	}

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
	if err != nil {
		t.Fatalf("Failed building join event: %v", err)
	}

	stateKey = validUser.String()
	leaveEB := MustGetRoomVersion(RoomVersionV10).NewEventBuilderFromProtoEvent(&ProtoEvent{
		SenderID:   validUser.String(),
		RoomID:     validRoom.String(),
		Type:       spec.MRoomMember,
		StateKey:   &stateKey,
		PrevEvents: []interface{}{powerLevelsEvent.EventID()},
		AuthEvents: []interface{}{createEvent.EventID(), joinRulesEvent.EventID(), powerLevelsEvent.EventID()},
		Depth:      3,
		Content:    json.RawMessage(`{"membership":"leave"}`),
		Unsigned:   json.RawMessage(""),
	})
	leaveEvent, err := leaveEB.Build(time.Now(), validUser.Domain(), keyID, sk)
	if err != nil {
		t.Fatalf("Failed building join event: %v", err)
	}

	tests := []struct {
		name        string
		input       HandleMakeLeaveInput
		want        *HandleMakeLeaveResponse
		expectError bool
	}{
		{
			name: "wrong destination",
			input: HandleMakeLeaveInput{
				UserID:        *joinedUser,
				RequestOrigin: "notLocalhost",
			},
			expectError: true,
		},
		{
			name: "localhost not in room",
			input: HandleMakeLeaveInput{
				RoomID:            *validRoom,
				LocalServerInRoom: false,
				UserIDQuerier:     UserIDForSenderTest,
			},
			expectError: true,
		},
		{
			name: "template error",
			input: HandleMakeLeaveInput{
				UserID:            *validUser,
				RoomID:            *validRoom,
				RequestOrigin:     "remote",
				LocalServerInRoom: true,
				UserIDQuerier:     UserIDForSenderTest,
				BuildEventTemplate: func(protoEvent *ProtoEvent) (PDU, []PDU, error) {
					return nil, nil, errors.New("error")
				},
			},
			expectError: true,
		},
		{
			name: "template error - no event",
			input: HandleMakeLeaveInput{
				UserID:            *validUser,
				RoomID:            *validRoom,
				RequestOrigin:     "remote",
				LocalServerInRoom: true,
				UserIDQuerier:     UserIDForSenderTest,
				BuildEventTemplate: func(protoEvent *ProtoEvent) (PDU, []PDU, error) {
					return nil, nil, nil
				},
			},
			expectError: true,
		},
		{
			name: "template error - no state",
			input: HandleMakeLeaveInput{
				UserID:            *validUser,
				RoomID:            *validRoom,
				RequestOrigin:     "remote",
				LocalServerInRoom: true,
				UserIDQuerier:     UserIDForSenderTest,
				BuildEventTemplate: func(protoEvent *ProtoEvent) (PDU, []PDU, error) {
					return joinEvent, nil, nil
				},
			},
			expectError: true,
		},
		{
			name: "template error - not a membership event",
			input: HandleMakeLeaveInput{
				UserID:            *validUser,
				RoomID:            *validRoom,
				RequestOrigin:     "remote",
				LocalServerInRoom: true,
				UserIDQuerier:     UserIDForSenderTest,
				BuildEventTemplate: func(protoEvent *ProtoEvent) (PDU, []PDU, error) {
					return createEvent, []PDU{createEvent, joinRulesEvent}, nil
				},
			},
			expectError: true,
		},
		{
			name: "not allowed to leave, wrong state events",
			input: HandleMakeLeaveInput{
				UserID:            *validUser,
				RoomID:            *validRoom,
				RequestOrigin:     "remote",
				LocalServerInRoom: true,
				UserIDQuerier:     UserIDForSenderTest,
				BuildEventTemplate: func(protoEvent *ProtoEvent) (PDU, []PDU, error) {
					return leaveEvent, []PDU{joinRulesEvent}, nil
				},
			},
			expectError: true,
		},
		{
			name: "allowed to leave",
			input: HandleMakeLeaveInput{
				UserID:            *validUser,
				RequestOrigin:     "remote",
				LocalServerInRoom: true,
				UserIDQuerier:     UserIDForSenderTest,
				BuildEventTemplate: func(protoEvent *ProtoEvent) (PDU, []PDU, error) {
					return leaveEvent, []PDU{createEvent, joinRulesEvent}, nil
				},
			},
			expectError: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := HandleMakeLeave(tt.input)
			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, got, "Expected non-nil response")
			}
		})
	}
}
