// nolint:testpackage
/* Copyright 2016-2017 Vector Creations Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// nolint:testpackage
package gomatrixserverlib

import (
	"encoding/json"
	"testing"

	"github.com/antinvestor/gomatrixserverlib/spec"
	"github.com/stretchr/testify/assert"
)

func stateNeededEquals(a, b StateNeeded) bool {
	if a.Create != b.Create {
		return false
	}
	if a.JoinRules != b.JoinRules {
		return false
	}
	if a.PowerLevels != b.PowerLevels {
		return false
	}
	if len(a.Member) != len(b.Member) {
		return false
	}
	if len(a.ThirdPartyInvite) != len(b.ThirdPartyInvite) {
		return false
	}
	for i := range a.Member {
		if a.Member[i] != b.Member[i] {
			return false
		}
	}
	for i := range a.ThirdPartyInvite {
		if a.ThirdPartyInvite[i] != b.ThirdPartyInvite[i] {
			return false
		}
	}
	return true
}

type testEventList []PDU

func (tel *testEventList) UnmarshalJSON(data []byte) error {
	var eventJSONs []json.RawMessage
	var events []PDU
	if err := json.Unmarshal(data, &eventJSONs); err != nil {
		return err
	}
	for _, eventJSON := range eventJSONs {
		event, err := MustGetRoomVersion(RoomVersionV1).NewEventFromTrustedJSON(eventJSON, false)
		if err != nil {
			return err
		}
		events = append(events, event)
	}
	*tel = events
	return nil
}

func testStateNeededForAuth(t *testing.T, eventdata string, protoEvent *ProtoEvent, want StateNeeded) {
	var events testEventList
	if err := json.Unmarshal([]byte(eventdata), &events); err != nil {
		panic(err)
	}
	got := StateNeededForAuth(events)
	if !stateNeededEquals(got, want) {
		t.Errorf("Testing StateNeededForAuth(%#v), wanted %#v got %#v", events, want, got)
	}
	if protoEvent != nil {
		got, err := StateNeededForProtoEvent(protoEvent)
		if !stateNeededEquals(got, want) {
			t.Errorf("Testing StateNeededForEventBuilder(%#v), wanted %#v got %#v", events, want, got)
		}
		if err != nil {
			panic(err)
		}
	}
}

func TestStateNeededForCreate(t *testing.T) {
	// Create events don't need anything.
	skey := ""
	testStateNeededForAuth(t, `[{"type": "m.room.create", "room_id": "!r1:a"}]`, &ProtoEvent{
		Type:     "m.room.create",
		StateKey: &skey,
	}, StateNeeded{})
}

func TestStateNeededForMessage(t *testing.T) {
	// Message events need the create event, the sender and the power_levels.
	testStateNeededForAuth(t, `[{
		"type": "m.room.message",
		"sender": "@u1:a",
        "room_id": "!r1:a"
	}]`, &ProtoEvent{
		Type:     "m.room.message",
		SenderID: "@u1:a",
	}, StateNeeded{
		Create:      true,
		PowerLevels: true,
		Member:      []string{"@u1:a"},
	})
}

func TestStateNeededForAlias(t *testing.T) {
	// Alias events need only the create event.
	testStateNeededForAuth(t, `[{"type": "m.room.aliases", "room_id": "!r1:a"}]`, &ProtoEvent{
		Type: "m.room.aliases",
	}, StateNeeded{
		Create: true,
	})
}

func TestStateNeededForJoin(t *testing.T) {
	skey := "@u1:a"
	b := ProtoEvent{
		Type:     "m.room.member",
		StateKey: &skey,
		SenderID: "@u1:a",
	}
	if err := b.SetContent(newMemberContent("join", nil)); err != nil {
		t.Fatal(err)
	}
	testStateNeededForAuth(t, `[{
		"type": "m.room.member",
		"state_key": "@u1:a",
		"sender": "@u1:a",
		"content": {"membership": "join"},
        "room_id": "!r1:a"
	}]`, &b, StateNeeded{
		Create:      true,
		JoinRules:   true,
		PowerLevels: true,
		Member:      []string{"@u1:a"},
	})
}

func TestStateNeededForInvite(t *testing.T) {
	skey := "@u2:b"
	b := ProtoEvent{
		Type:     "m.room.member",
		StateKey: &skey,
		SenderID: "@u1:a",
	}
	if err := b.SetContent(newMemberContent("invite", nil)); err != nil {
		t.Fatal(err)
	}
	testStateNeededForAuth(t, `[{
		"type": "m.room.member",
		"state_key": "@u2:b",
		"sender": "@u1:a",
		"content": {"membership": "invite"},
        "room_id": "!r1:a"
	}]`, &b, StateNeeded{
		Create:      true,
		PowerLevels: true,
		JoinRules:   true,
		Member:      []string{"@u1:a", "@u2:b"},
	})
}

func TestStateNeededForInvite3PID(t *testing.T) {
	skey := "@u2:b"
	b := ProtoEvent{
		Type:     "m.room.member",
		StateKey: &skey,
		SenderID: "@u1:a",
	}

	if err := b.SetContent(newMemberContent("invite", &MemberThirdPartyInvite{
		Signed: MemberThirdPartyInviteSigned{
			Token: "my_token",
		},
	})); err != nil {
		t.Fatal(err)
	}
	testStateNeededForAuth(t, `[{
		"type": "m.room.member",
		"state_key": "@u2:b",
		"sender": "@u1:a",
		"content": {
			"membership": "invite",
			"third_party_invite": {
				"signed": {
					"token": "my_token"
				}
			}
		},
        "room_id": "!r1:a"
	}]`, &b, StateNeeded{
		Create:           true,
		PowerLevels:      true,
		JoinRules:        true,
		Member:           []string{"@u1:a", "@u2:b"},
		ThirdPartyInvite: []string{"my_token"},
	})
}

type testAuthEvents struct {
	CreateJSON           json.RawMessage            `json:"create"`
	JoinRulesJSON        json.RawMessage            `json:"join_rules"`
	PowerLevelsJSON      json.RawMessage            `json:"power_levels"`
	MemberJSON           map[string]json.RawMessage `json:"member"`
	ThirdPartyInviteJSON map[string]json.RawMessage `json:"third_party_invite"`
	roomVersion          RoomVersion
}

func (tae *testAuthEvents) Create() (PDU, error) {
	if len(tae.CreateJSON) == 0 {
		return nil, nil
	}
	event, err := MustGetRoomVersion(tae.roomVersion).NewEventFromTrustedJSON(tae.CreateJSON, false)
	if err != nil {
		return nil, err
	}
	return event, nil
}

func (tae *testAuthEvents) JoinRules() (PDU, error) {
	if len(tae.JoinRulesJSON) == 0 {
		return nil, nil
	}
	event, err := MustGetRoomVersion(tae.roomVersion).NewEventFromTrustedJSON(tae.JoinRulesJSON, false)
	if err != nil {
		return nil, err
	}
	return event, nil
}

func (tae *testAuthEvents) PowerLevels() (PDU, error) {
	if len(tae.PowerLevelsJSON) == 0 {
		return nil, nil
	}
	event, err := MustGetRoomVersion(tae.roomVersion).NewEventFromTrustedJSON(tae.PowerLevelsJSON, false)
	if err != nil {
		return nil, err
	}
	return event, nil
}

func (tae *testAuthEvents) Member(stateKey spec.SenderID) (PDU, error) {
	if len(tae.MemberJSON[string(stateKey)]) == 0 {
		return nil, nil
	}
	event, err := MustGetRoomVersion(tae.roomVersion).NewEventFromTrustedJSON(tae.MemberJSON[string(stateKey)], false)
	if err != nil {
		return nil, err
	}
	return event, nil
}

func (tae *testAuthEvents) ThirdPartyInvite(stateKey string) (PDU, error) {
	if len(tae.ThirdPartyInviteJSON[stateKey]) == 0 {
		return nil, nil
	}
	event, err := MustGetRoomVersion(tae.roomVersion).NewEventFromTrustedJSON(tae.ThirdPartyInviteJSON[stateKey], false)
	if err != nil {
		return nil, err
	}
	return event, nil
}

func (tae *testAuthEvents) Valid() bool {
	return true
}

type testCase struct {
	AuthEvents testAuthEvents    `json:"auth_events"`
	Allowed    []json.RawMessage `json:"allowed"`
	NotAllowed []json.RawMessage `json:"not_allowed"`
}

func testEventAllowed(t *testing.T, testCaseJSON string, roomVersion RoomVersion) {
	t.Helper()
	tc := testCase{
		AuthEvents: testAuthEvents{
			roomVersion: roomVersion,
		},
	}
	if err := json.Unmarshal([]byte(testCaseJSON), &tc); err != nil {
		panic(err)
	}
	for _, data := range tc.Allowed {
		event, err := MustGetRoomVersion(roomVersion).NewEventFromTrustedJSON(data, false)
		if err != nil {
			panic(err)
		}
		if err = Allowed(event, &tc.AuthEvents, UserIDForSenderTest); err != nil {
			t.Fatalf("Expected %q to be allowed but it was not: %q", string(data), err)
		}
	}
	for _, data := range tc.NotAllowed {
		event, err := MustGetRoomVersion(roomVersion).NewEventFromTrustedJSON(data, false)
		if err != nil {
			continue
		}
		if event != nil {
			if err := Allowed(event, &tc.AuthEvents, UserIDForSenderTest); err == nil {
				t.Fatalf("Expected %q to not be allowed but it was", string(data))
			} else {
				t.Logf("%#v", err)
			}
		}
	}
}

func TestAllowedEmptyRoom(t *testing.T) {
	// Test that only m.room.create events can be sent without auth events.
	// TODO: Test the events that aren't m.room.create
	testEventAllowed(t, `{
		"auth_events": {},
		"allowed": [{
			"type": "m.room.create",
			"state_key": "",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"event_id": "$e1:a",
			"content": {"creator": "@u1:a"}
		}],
		"not_allowed": [{
			"type": "m.room.create",
			"state_key": "",
			"sender": "@u1:b",
			"room_id": "!r1:a",
			"event_id": "$e2:a",
			"content": {"creator": "@u1:b"},
			"unsigned": {
				"not_allowed": "Sent by a different server than the one which made the room_id"
			}
		}, {
			"type": "m.room.create",
			"state_key": "",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"event_id": "$e3:a",
			"prev_events": [["$e1", {}]],
			"content": {"creator": "@u1:a"},
			"unsigned": {
				"not_allowed": "Was not the first event in the room"
			}
		}, {
			"type": "m.room.message",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"event_id": "$e4:a",
			"content": {"body": "Test"},
			"unsigned": {
				"not_allowed": "No create event"
			}
		}, {
			"type": "m.room.member",
			"state_key": "@u1:a",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"event_id": "$e4:a",
			"content": {"membership": "join"},
			"unsigned": {
				"not_allowed": "No create event"
			}
		}, {
			"type": "m.room.create",
			"state_key": "",
			"sender": "not_a_user_id",
			"room_id": "!r1:a",
			"event_id": "$e5:a",
			"content": {"creator": "@u1:a"},
			"unsigned": {
				"not_allowed": "Sender is not a valid user ID"
			}
		}, {
			"type": "m.room.create",
			"state_key": "",
			"sender": "@u1:a",
			"room_id": "not_a_room_id",
			"event_id": "$e6:a",
			"content": {"creator": "@u1:a"},
			"unsigned": {
				"not_allowed": "Room is not a valid room ID"
			}
		}, {
			"type": "m.room.create",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"event_id": "$e7:a",
			"content": {"creator": "@u1:a"},
			"unsigned": {
				"not_allowed": "Missing state_key"
			}
		}, {
			"type": "m.room.create",
			"state_key": "not_empty",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"event_id": "$e7:a",
			"content": {"creator": "@u1:a"},
			"unsigned": {
				"not_allowed": "The state_key is not empty"
			}
		}]
	}`, RoomVersionV1)
}

func TestAllowedFirstJoin(t *testing.T) {
	testEventAllowed(t, `{
		"auth_events": {
			"create": {
				"type": "m.room.create",
				"state_key": "",
				"sender": "@u1:a",
				"room_id": "!r1:a",
				"event_id": "$e1:a",
				"content": {"creator": "@u1:a"}
			}
		},
		"allowed": [{
			"type": "m.room.member",
			"state_key": "@u1:a",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"event_id": "$e2:a",
			"prev_events": [["$e1:a", {}]],
			"content": {"membership": "join"}
		}],
		"not_allowed": [{
			"type": "m.room.message",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"event_id": "$e3:a",
			"content": {"body": "test"},
			"unsigned": {
				"not_allowed": "Sender is not in the room"
			}
		}, {
			"type": "m.room.member",
			"state_key": "@u2:a",
			"sender": "@u2:a",
			"room_id": "!r1:a",
			"event_id": "$e4:a",
			"prev_events": [["$e1:a", {}]],
			"content": {"membership": "join"},
			"unsigned": {
				"not_allowed": "Only the creator can join the room"
			}
		}, {
			"type": "m.room.member",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"event_id": "$e4:a",
			"prev_events": [["$e1:a", {}]],
			"content": {"membership": "join"},
			"unsigned": {
				"not_allowed": "Missing state_key"
			}
		}, {
			"type": "m.room.member",
			"state_key": "@u1:a",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"event_id": "$e4:a",
			"prev_events": [["$e2:a", {}]],
			"content": {"membership": "join"},
			"unsigned": {
				"not_allowed": "The prev_event is not the create event"
			}
		}, {
			"type": "m.room.member",
			"state_key": "@u1:a",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"event_id": "$e4:a",
			"content": {"membership": "join"},
			"unsigned": {
				"not_allowed": "There are no prev_events"
			}
		}, {
			"type": "m.room.member",
			"state_key": "@u1:a",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"event_id": "$e4:a",
			"content": {"membership": "join"},
			"prev_events": [["$e1:a", {}], ["$e2:a", {}]],
			"unsigned": {
				"not_allowed": "There are too many prev_events"
			}
		}, {
			"type": "m.room.member",
			"state_key": "@u1:a",
			"sender": "@u2:a",
			"room_id": "!r1:a",
			"event_id": "$e4:a",
			"content": {"membership": "join"},
			"prev_events": [["$e1:a", {}]],
			"unsigned": {
				"not_allowed": "The sender doesn't match the joining user"
			}
		}, {
			"type": "m.room.member",
			"state_key": "@u1:a",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"event_id": "$e4:a",
			"content": {"membership": "invite"},
			"prev_events": [["$e1:a", {}]],
			"unsigned": {
				"not_allowed": "The membership is not 'join'"
			}
		}]
	}`, RoomVersionV1)
}

func TestAllowedWithNoPowerLevels(t *testing.T) {
	testEventAllowed(t, `{
		"auth_events": {
			"create": {
				"type": "m.room.create",
				"state_key": "",
				"sender": "@u1:a",
				"room_id": "!r1:a",
				"event_id": "$e1:a",
				"content": {"creator": "@u1:a"}
			},
			"member": {
				"@u1:a": {
					"type": "m.room.member",
					"sender": "@u1:a",
					"room_id": "!r1:a",
					"state_key": "@u1:a",
					"event_id": "$e2:a",
					"content": {"membership": "join"}
				}
			}
		},
		"allowed": [{
			"type": "m.room.message",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"event_id": "$e3:a",
			"content": {"body": "Test"}
		}],
		"not_allowed": [{
			"type": "m.room.message",
			"sender": "@u2:a",
			"room_id": "!r1:a",
			"event_id": "$e4:a",
			"content": {"body": "Test"},
			"unsigned": {
				"not_allowed": "Sender is not in room"
			}
		}]
	}`, RoomVersionV1)
}

func TestAllowedInviteFrom3PID(t *testing.T) {
	testEventAllowed(t, `{
		"auth_events": {
			"create": {
				"type": "m.room.create",
				"state_key": "",
				"sender": "@u1:a",
				"room_id": "!r1:a",
				"event_id": "$e1:a",
				"content": {"creator": "@u1:a"}
			},
			"member": {
				"@u1:a": {
					"type": "m.room.member",
					"sender": "@u1:a",
					"room_id": "!r1:a",
					"state_key": "@u1:a",
					"event_id": "$e2:a",
					"content": {"membership": "join"}
				}
			},
			"third_party_invite": {
				"my_token": {
					"type": "m.room.third_party_invite",
					"sender": "@u1:a",
					"room_id": "!r1:a",
					"state_key": "my_token",
					"event_id": "$e3:a",
					"content": {
						"display_name": "foo...@bar...",
						"public_key": "pubkey",
						"key_validity_url": "https://example.tld/isvalid",
						"public_keys": [
							{
								"public_key": "mrV51jApZKahGjfMhlevp+QtSSTDKCLaLVCzYc4HELY",
								"key_validity_url": "https://example.tld/isvalid"
							}
						]
					}
				}
			}
		},
		"allowed": [{
			"type": "m.room.member",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"state_key": "@u2:a",
			"event_id": "$e4:a",
			"content": {
				"membership": "invite",
				"third_party_invite": {
					"display_name": "foo...@bar...",
					"signed": {
						"token": "my_token",
						"mxid": "@u2:a",
						"signatures": {
							"example.tld": {
								"ed25519:0": "CibGFS0vX93quJFppsQbYQKJFIwxiYEK87lNmekS/fdetUMXPdR2wwNDd09J1jJ28GCH3GogUTuFDB1ScPFxBg"
							}
						}
					}
				}
			}
		}],
		"not_allowed": [{
			"type": "m.room.member",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"state_key": "@u2:a",
			"event_id": "$e4:a",
			"content": {
				"membership": "invite",
				"third_party_invite": {
					"display_name": "foo...@bar...",
					"signed": {
						"token": "my_token",
						"mxid": "@u2:a",
						"signatures": {
							"example.tld": {
								"ed25519:0": "some_signature"
							}
						}
					}
				}
			},
			"unsigned": {
				"not_allowed": "Bad signature"
			}
		}, {
			"type": "m.room.member",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"state_key": "@u2:a",
			"event_id": "$e5:a",
			"content": {
				"membership": "invite",
				"third_party_invite": {
					"display_name": "foo...@bar...",
					"signed": {
						"token": "my_token",
						"mxid": "@u3:a",
						"signatures": {
							"example.tld": {
								"ed25519:0": "CibGFS0vX93quJFppsQbYQKJFIwxiYEK87lNmekS/fdetUMXPdR2wwNDd09J1jJ28GCH3GogUTuFDB1ScPFxBg"
							}
						}
					}
				}
			},
			"unsigned": {
				"not_allowed": "MXID doesn't match state key"
			}
		}, {
			"type": "m.room.member",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"state_key": "@u2:a",
			"event_id": "$e6:a",
			"content": {
				"membership": "invite",
				"third_party_invite": {
					"display_name": "foo...@bar...",
					"signed": {
						"token": "my_other_token",
						"mxid": "@u2:a",
						"signatures": {
							"example.tld": {
								"ed25519:0": "CibGFS0vX93quJFppsQbYQKJFIwxiYEK87lNmekS/fdetUMXPdR2wwNDd09J1jJ28GCH3GogUTuFDB1ScPFxBg"
							}
						}
					}
				}
			},
			"unsigned": {
				"not_allowed": "Token doesn't refer to a known third-party invite"
			}
		}]
	}`, RoomVersionV1)
}

func TestAllowedNoFederation(t *testing.T) {
	testEventAllowed(t, `{
		"auth_events": {
			"create": {
				"type": "m.room.create",
				"sender": "@u1:a",
				"room_id": "!r1:a",
				"event_id": "$e1:a",
				"content": {
					"creator": "@u1:a",
					"m.federate": false
				}
			},
			"member": {
				"@u1:a": {
					"type": "m.room.member",
					"sender": "@u1:a",
					"room_id": "!r1:a",
					"state_key": "@u1:a",
					"event_id": "$e2:a",
					"content": {"membership": "join"}
				}
			}
		},
		"allowed": [{
			"type": "m.room.message",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"event_id": "$e3:a",
			"content": {"body": "Test"}
		}],
		"not_allowed": [{
			"type": "m.room.message",
			"sender": "@u1:b",
			"room_id": "!r1:a",
			"event_id": "$e4:a",
			"content": {"body": "Test"},
			"unsigned": {
				"not_allowed": "Sender is from a different server."
			}
		}]
	}`, RoomVersionV1)
}

func TestAllowedWithPowerLevels(t *testing.T) {
	testEventAllowed(t, `{
		"auth_events": {
			"create": {
				"type": "m.room.create",
				"sender": "@u1:a",
				"room_id": "!r1:a",
				"event_id": "$e1:a",
				"content": {"creator": "@u1:a"}
			},
			"member": {
				"@u1:a": {
					"type": "m.room.member",
					"sender": "@u1:a",
					"room_id": "!r1:a",
					"state_key": "@u1:a",
					"event_id": "$e2:a",
					"content": {"membership": "join"}
				},
				"@u2:a": {
					"type": "m.room.member",
					"sender": "@u2:a",
					"room_id": "!r1:a",
					"state_key": "@u2:a",
					"event_id": "$e3:a",
					"content": {"membership": "join"}
				},
				"@u3:b": {
					"type": "m.room.member",
					"sender": "@u3:b",
					"room_id": "!r1:a",
					"state_key": "@u3:b",
					"event_id": "$e4:a",
					"content": {"membership": "join"}
				}
			},
			"power_levels": {
				"type": "m.room.power_levels",
				"sender": "@u1:a",
				"room_id": "!r1:a",
				"event_id": "$e5:a",
				"content": {
					"users": {
						"@u1:a": 100,
						"@u2:a": 50
					},
					"users_default": 0,
					"events": {
						"m.room.join_rules": 100
					},
					"state_default": 50,
					"events_default": 0
				}
			}
		},
		"allowed": [{
			"type": "m.room.message",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"event_id": "$e6:a",
			"content": {"body": "Test from @u1:a"}
		}, {
			"type": "m.room.message",
			"sender": "@u2:a",
			"room_id": "!r1:a",
			"event_id": "$e7:a",
			"content": {"body": "Test from @u2:a"}
		}, {
			"type": "m.room.message",
			"sender": "@u3:b",
			"room_id": "!r1:a",
			"event_id": "$e8:a",
			"content": {"body": "Test from @u3:b"}
		},{
			"type": "m.room.name",
			"state_key": "",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"event_id": "$e9:a",
			"content": {"name": "Name set by @u1:a"}
		}, {
			"type": "m.room.name",
			"state_key": "",
			"sender": "@u2:a",
			"room_id": "!r1:a",
			"event_id": "$e10:a",
			"content": {"name": "Name set by @u2:a"}
		}, {
			"type": "m.room.join_rules",
			"state_key": "",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"event_id": "$e11:a",
			"content": {"join_rule": "public"}
		}, {
			"type": "my.custom.state",
			"state_key": "@u2:a",
			"sender": "@u2:a",
			"room_id": "!r1:a",
			"event_id": "@e12:a",
			"content": {}
		}],
		"not_allowed": [{
			"type": "m.room.name",
			"state_key": "",
			"sender": "@u3:b",
			"room_id": "!r1:a",
			"event_id": "$e13:a",
			"content": {"name": "Name set by @u3:b"},
			"unsigned": {
				"not_allowed": "User @u3:b's level is too low to send a state event"
			}
		}, {
			"type": "m.room.join_rules",
			"sender": "@u2:a",
			"room_id": "!r1:a",
			"event_id": "$e14:a",
			"content": {"name": "Name set by @u3:b"},
			"unsigned": {
				"not_allowed": "User @u2:a's level is too low to send m.room.join_rules"
			}
		}, {
			"type": "m.room.message",
			"sender": "@u4:a",
			"room_id": "!r1:a",
			"event_id": "$e15:a",
			"content": {"Body": "Test from @u4:a"},
			"unsigned": {
				"not_allowed": "User @u4:a is not in the room"
			}
		}, {
			"type": "m.room.message",
			"sender": "@u1:a",
			"room_id": "!r2:a",
			"event_id": "$e16:a",
			"content": {"body": "Test from @u4:a"},
			"unsigned": {
				"not_allowed": "Sent from a different room to the create event"
			}
		}, {
			"type": "my.custom.state",
			"state_key": "@u2:a",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"event_id": "@e17:a",
			"content": {},
			"unsigned": {
				"not_allowed": "State key starts with '@' and is for a different user"
			}
		}]
	}`, RoomVersionV1)
}

func TestRedactAllowed(t *testing.T) {
	// Test if redacts are allowed correctly in a room with a power level event.
	testEventAllowed(t, `{
		"auth_events": {
			"create": {
				"type": "m.room.create",
				"sender": "@u1:a",
				"room_id": "!r1:a",
				"event_id": "$e1:a",
				"content": {"creator": "@u1:a"}
			},
			"member": {
				"@u1:a": {
					"type": "m.room.member",
					"sender": "@u1:a",
					"room_id": "!r1:a",
					"state_key": "@u1:a",
					"event_id": "$e2:a",
					"content": {"membership": "join"}
				},
				"@u2:a": {
					"type": "m.room.member",
					"sender": "@u2:a",
					"room_id": "!r1:a",
					"state_key": "@u2:a",
					"event_id": "$e3:a",
					"content": {"membership": "join"}
				},
				"@u1:b": {
					"type": "m.room.member",
					"sender": "@u1:b",
					"room_id": "!r1:a",
					"state_key": "@u1:b",
					"event_id": "$e4:a",
					"content": {"membership": "join"}
				}
			},
			"power_levels": {
				"type": "m.room.power_levels",
				"state_key": "",
				"sender": "@u1:a",
				"room_id": "!r1:a",
				"event_id": "$e5:a",
				"content": {
					"users": {
						"@u1:a": 100
					},
					"redact": 100
				}
			}
		},
		"allowed": [{
			"type": "m.room.redaction",
			"sender": "@u1:b",
			"room_id": "!r1:a",
			"redacts": "$event_sent_by_b:b",
			"event_id": "$e6:b",
			"content": {"reason": ""}
		}, {
			"type": "m.room.redaction",
			"sender": "@u2:a",
			"room_id": "!r1:a",
			"redacts": "$event_sent_by_a:a",
			"event_id": "$e7:a",
			"content": {"reason": ""}
		}, {
			"type": "m.room.redaction",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"redacts": "$event_sent_by_b:b",
			"event_id": "$e8:a",
			"content": {"reason": ""}
		}],
		"not_allowed": [{
			"type": "m.room.redaction",
			"sender": "@u2:a",
			"room_id": "!r1:a",
			"redacts": "$event_sent_by_b:b",
			"event_id": "$e9:a",
			"content": {"reason": ""},
			"unsigned": {
				"not_allowed": "User power level is too low and event is from different server"
			}
		}, {
			"type": "m.room.redaction",
			"sender": "@u1:c",
			"room_id": "!r1:a",
			"redacts": "$event_sent_by_c:c",
			"event_id": "$e10:a",
			"content": {"reason": ""},
			"unsigned": {
				"not_allowed": "User is not in the room"
			}
		}, {
			"type": "m.room.redaction",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"redacts": "not_a_valid_event_id",
			"event_id": "$e11:a",
			"content": {"reason": ""},
			"unsigned": {
				"not_allowed": "Invalid redacts event ID"
			}
		}, {
			"type": "m.room.redaction",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"event_id": "$e11:a",
			"content": {"reason": ""},
			"unsigned": {
				"not_allowed": "Missing redacts event ID"
			}
		}]
	}`, RoomVersionV1)
}

func TestAuthEvents(t *testing.T) {
	power, err := MustGetRoomVersion(RoomVersionV1).NewEventFromTrustedJSON(json.RawMessage(`{
		"type": "m.room.power_levels",
		"state_key": "",
		"sender": "@u1:a",
		"room_id": "!r1:a",
		"event_id": "$e5:a",
		"content": {
			"users": {
				"@u1:a": 100
			},
			"redact": 100
		}
	}`), false)
	if err != nil {
		t.Fatalf("TestAuthEvents: failed to create power_levels event: %s", err)
	}
	a, _ := NewAuthEvents([]PDU{power})
	var e PDU
	if e, err = a.PowerLevels(); err != nil || e != power {
		t.Errorf("TestAuthEvents: failed to get same power_levels event")
	}
	create, err := MustGetRoomVersion(RoomVersionV1).NewEventFromTrustedJSON(json.RawMessage(`{
		"type": "m.room.create",
		"state_key": "",
		"sender": "@u1:a",
		"room_id": "!r1:a",
		"event_id": "$e1:a",
		"content": {
			"creator": "@u1:a"
		}
	}`), false)
	if err != nil {
		t.Fatalf("TestAuthEvents: failed to create create event: %s", err)
	}
	if err = a.AddEvent(create); err != nil {
		t.Errorf("TestAuthEvents: Failed to AddEvent: %s", err)
	}
	if e, err = a.Create(); err != nil || e != create {
		t.Errorf("TestAuthEvents: failed to get same create event")
	}
}

var powerLevelTestRoom = &testAuthEvents{
	roomVersion: RoomVersionV1,
	CreateJSON: json.RawMessage(`{
		"type": "m.room.create",
		"state_key": "",
		"sender": "@u1:a",
		"room_id": "!r1:a",
		"event_id": "$e1:a",
		"content": {
			"room_version": "1"
		}
	}`),
	PowerLevelsJSON: json.RawMessage(`{
		"type": "m.room.power_levels",
		"state_key": "",
		"sender": "@u1:a",
		"room_id": "!r1:a",
		"event_id": "$e3:a",
		"content": {
			"users_default": 100,
			"users": {
				"@u1:a": 100
			},
			"redact": 100
		}
	}`),
	MemberJSON: map[string]json.RawMessage{
		"@u1:a": json.RawMessage(`{
			"type": "m.room.member",
			"state_key": "@u1:a",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"event_id": "$e2:a",
			"content": {
				"membership": "join"
			}
		}`),
	},
}

func TestDemoteUserDefaultPowerLevelBelowOwn(t *testing.T) {
	// User should be able to demote the user default level
	// below their own effective level.
	powerChangeShouldSucceed, err := MustGetRoomVersion(RoomVersionV1).NewEventFromTrustedJSON(json.RawMessage(`{
		"type": "m.room.power_levels",
		"state_key": "",
		"sender": "@u1:a",
		"room_id": "!r1:a",
		"event_id": "$e5:a",
		"content": {
			"users_default": 50,
			"users": {
				"@u1:a": 100
			},
			"redact": 100
		}
	}`), false)
	if err != nil {
		t.Fatal(err)
	}
	if err = Allowed(powerChangeShouldSucceed, powerLevelTestRoom, UserIDForSenderTest); err != nil {
		t.Error("TestDemoteUserDefaultPowerLevel should have succeeded but it didn't:", err)
	}
}

func NilUserIDForBadSenderTest(roomID spec.RoomID, senderID spec.SenderID) (*spec.UserID, error) {
	if senderID == "@baduser" {
		return nil, nil
	}

	return spec.NewUserID(string(senderID), true)
}

var nilPowerLevelTestRoom = &testAuthEvents{
	roomVersion: RoomVersionV1,
	CreateJSON: json.RawMessage(`{
		"type": "m.room.create",
		"state_key": "",
		"sender": "@baduser",
		"room_id": "!r1:a",
		"event_id": "$e1:a",
		"content": {
			"room_version": "1"
		}
	}`),
	PowerLevelsJSON: json.RawMessage(`{
		"type": "m.room.power_levels",
		"state_key": "",
		"sender": "@u1:a",
		"room_id": "!r1:a",
		"event_id": "$e3:a",
		"content": {
			"users_default": 100,
			"users": {
				"@u1:a": 100
			},
			"redact": 100
		}
	}`),
	MemberJSON: map[string]json.RawMessage{
		"@u1:a": json.RawMessage(`{
			"type": "m.room.member",
			"state_key": "@u1:a",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"event_id": "$e2:a",
			"content": {
				"membership": "join"
			}
		}`),
	},
}

func TestPowerLevelCheckShouldNotPanic(t *testing.T) {
	powerChangeBadUser, err := MustGetRoomVersion(RoomVersionV1).NewEventFromTrustedJSON(json.RawMessage(`{
		"type": "m.room.power_levels",
		"state_key": "",
		"sender": "@u1:a",
		"room_id": "!r1:a",
		"event_id": "$e5:a",
		"content": {
			"users_default": 50,
			"users": {
				"@baduser": 0
			},
			"redact": 100
		}
	}`), false)
	if err != nil {
		t.Fatal(err)
	}
	assert.NotPanics(t, func() {
		if err := Allowed(powerChangeBadUser, powerLevelTestRoom, NilUserIDForBadSenderTest); err == nil {
			panic("Event should not be allowed")
		}
	})

	powerChange, err := MustGetRoomVersion(RoomVersionV1).NewEventFromTrustedJSON(json.RawMessage(`{
		"type": "m.room.power_levels",
		"state_key": "",
		"sender": "@u1:a",
		"room_id": "!r1:a",
		"event_id": "$e5:a",
		"content": {
			"users_default": 50,
			"users": {
                "@u1:a": 0
			},
			"redact": 100
		}
	}`), false)
	if err != nil {
		t.Fatal(err)
	}
	assert.NotPanics(t, func() {
		if err := Allowed(powerChange, nilPowerLevelTestRoom, NilUserIDForBadSenderTest); err == nil {
			panic("Event should not be allowed")
		}
	})
}

func TestPromoteUserDefaultLevelAboveOwn(t *testing.T) {
	// User shouldn't be able to promote the user default
	// level above their own effective level.
	powerChangeShouldFail, err := MustGetRoomVersion(RoomVersionV1).NewEventFromTrustedJSON(json.RawMessage(`{
		"type": "m.room.power_levels",
		"state_key": "",
		"sender": "@u2:a",
		"room_id": "!r1:a",
		"event_id": "$e5:a",
		"content": {
			"users_default": 500,
			"users": {
				"@u1:a": 100
			},
			"redact": 100
		}
	}`), false)
	if err != nil {
		t.Fatal(err)
	}
	if err = Allowed(powerChangeShouldFail, powerLevelTestRoom, UserIDForSenderTest); err == nil {
		t.Error("TestPromoteUserDefaultLevelAboveOwn event should have failed but it didn't")
	}
}

func newMemberContent(
	membership string, thirdPartyInvite *MemberThirdPartyInvite,
) MemberContent {
	return MemberContent{
		Membership:       membership,
		ThirdPartyInvite: thirdPartyInvite,
	}
}

var negativePowerLevelTestRoom = &testAuthEvents{
	roomVersion: RoomVersionV1,
	CreateJSON: json.RawMessage(`{
		"type": "m.room.create",
		"state_key": "",
		"sender": "@u1:a",
		"room_id": "!r1:a",
		"event_id": "$e1:a",
		"content": {
			"room_version": "10"
		}
	}`),
	PowerLevelsJSON: json.RawMessage(`{
		"type": "m.room.power_levels",
		"state_key": "",
		"sender": "@u1:a",
		"room_id": "!r1:a",
		"event_id": "$e3:a",
		"content": {
			"events_default": -9007199254740990,
			"state_default": -9007199254740990,
			"users_default": -9007199254740990,
			"users": {
			}
		}
	}`),
	MemberJSON: map[string]json.RawMessage{
		"@u1:a": json.RawMessage(`{
			"type": "m.room.member",
			"state_key": "@u1:a",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"event_id": "$e2:a",
			"content": {
				"membership": "join"
			}
		}`),
	},
}

func TestNegativePowerLevels(t *testing.T) {
	// User should be able to demote the user default level
	// below their own effective level.
	eventShouldSucceed, err := MustGetRoomVersion(RoomVersionV1).NewEventFromTrustedJSON(json.RawMessage(`{
		"type": "m.room.message",
		"sender": "@u1:a",
		"room_id": "!r1:a",
		"event_id": "$e5:a",
		"content": {
			"stuff": "i am a message event"
		}
	}`), false)
	if err != nil {
		t.Fatal(err)
	}
	if err = Allowed(eventShouldSucceed, negativePowerLevelTestRoom, UserIDForSenderTest); err != nil {
		t.Error("TestNegativePowerLevels should have succeeded but it didn't:", err)
	}
}

func Test_checkUserLevels(t *testing.T) {
	senderID := "@alice:test"

	type args struct {
		senderLevel    int64
		oldPowerLevels PowerLevelContent
		newPowerLevels PowerLevelContent
	}

	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name:    "removing other user level if equal our own is forbidden",
			wantErr: true,
			args: args{
				senderLevel: 100,
				oldPowerLevels: PowerLevelContent{
					Users: map[string]int64{
						senderID:    100,
						"@bob:test": 100,
					},
				},
				newPowerLevels: PowerLevelContent{
					Users: map[string]int64{
						senderID: 100,
					},
				},
			},
		},
		{
			name: "removing other user level if below our own is allowed",
			args: args{
				senderLevel: 100,
				oldPowerLevels: PowerLevelContent{
					Users: map[string]int64{
						senderID:    100,
						"@bob:test": 99,
					},
				},
				newPowerLevels: PowerLevelContent{
					Users: map[string]int64{
						senderID: 100,
					},
				},
			},
		},
		{
			name:    "removing other user level if above our own is forbidden",
			wantErr: true,
			args: args{
				senderLevel: 100,
				oldPowerLevels: PowerLevelContent{
					Users: map[string]int64{
						senderID:    100,
						"@bob:test": 9001,
					},
				},
				newPowerLevels: PowerLevelContent{
					Users: map[string]int64{
						senderID: 100,
					},
				},
			},
		},
		{
			name:    "setting other user level equal our own to below own is forbidden",
			wantErr: true,
			args: args{
				senderLevel: 100,
				oldPowerLevels: PowerLevelContent{
					Users: map[string]int64{
						senderID:    100,
						"@bob:test": 100,
					},
				},
				newPowerLevels: PowerLevelContent{
					Users: map[string]int64{
						senderID:    100,
						"@bob:test": 50,
					},
				},
			},
		},
		{
			name:    "setting other user level above own is forbidden",
			wantErr: true,
			args: args{
				senderLevel: 100,
				oldPowerLevels: PowerLevelContent{
					Users: map[string]int64{
						senderID:    100,
						"@bob:test": 100,
					},
				},
				newPowerLevels: PowerLevelContent{
					Users: map[string]int64{
						senderID:    100,
						"@bob:test": 9001,
					},
				},
			},
		},
		{
			name:    "setting own user level above own is forbidden",
			wantErr: true,
			args: args{
				senderLevel: 100,
				oldPowerLevels: PowerLevelContent{
					Users: map[string]int64{
						senderID: 100,
					},
				},
				newPowerLevels: PowerLevelContent{
					Users: map[string]int64{
						senderID: 101,
					},
				},
			},
		},
		{
			name: "setting own user level below own is allowed",
			args: args{
				senderLevel: 100,
				oldPowerLevels: PowerLevelContent{
					Users: map[string]int64{
						senderID: 100,
					},
				},
				newPowerLevels: PowerLevelContent{
					Users: map[string]int64{
						senderID: 10,
					},
				},
			},
		},
		{
			name: "setting own user level to the same level is allowed",
			args: args{
				senderLevel: 100,
				oldPowerLevels: PowerLevelContent{
					Users: map[string]int64{
						senderID: 100,
					},
				},
				newPowerLevels: PowerLevelContent{
					Users: map[string]int64{
						senderID: 100,
					},
				},
			},
		},
		{
			name: "removing own user level is allowed",
			args: args{
				senderLevel: 100,
				oldPowerLevels: PowerLevelContent{
					Users: map[string]int64{
						senderID: 100,
					},
				},
				newPowerLevels: PowerLevelContent{
					Users: map[string]int64{},
				},
			},
		},
		{
			name: "adding new user level is allowed below own",
			args: args{
				senderLevel: 100,
				oldPowerLevels: PowerLevelContent{
					Users: map[string]int64{
						senderID: 100,
					},
				},
				newPowerLevels: PowerLevelContent{
					Users: map[string]int64{
						senderID:    100,
						"@bob:test": 10,
					},
				},
			},
		},
		{
			name: "adding new user level is allowed if equal our own",
			args: args{
				senderLevel: 100,
				oldPowerLevels: PowerLevelContent{
					Users: map[string]int64{
						senderID: 100,
					},
				},
				newPowerLevels: PowerLevelContent{
					Users: map[string]int64{
						senderID:    100,
						"@bob:test": 100,
					},
				},
			},
		},
		{
			name:    "adding new user level is forbidden if above our own",
			wantErr: true,
			args: args{
				senderLevel: 100,
				oldPowerLevels: PowerLevelContent{
					Users: map[string]int64{
						senderID: 100,
					},
				},
				newPowerLevels: PowerLevelContent{
					Users: map[string]int64{
						senderID:    100,
						"@bob:test": 110,
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkUserLevels(
				tt.args.senderLevel,
				spec.SenderID(senderID),
				tt.args.oldPowerLevels,
				tt.args.newPowerLevels,
			)
			if err != nil && !tt.wantErr {
				t.Errorf("checkUserLevels() error = %v, wantErr %v", err, tt.wantErr)
			} else {
				if err != nil {
					t.Logf("Error: %s", err)
				}
			}
		})
	}
}

// displayname is boolean, an object or array.
func TestMembershipAllowed(t *testing.T) {
	testEventAllowed(t, `{
		"auth_events": {
			"create": {
				"type": "m.room.create",
				"state_key": "",
				"sender": "@u1:a",
				"room_id": "!r1:a",
				"event_id": "$e1:a",
				"content": {"creator": "@u1:a"}
			}
		},
		"allowed": [{
			"type": "m.room.member",
			"state_key": "@u1:a",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"event_id": "$e2:a",
			"prev_events": [["$e1:a", {}]],
			"content": {"membership": "join", "displayname": false}
		},
		{
			"type": "m.room.member",
			"state_key": "@u1:a",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"event_id": "$e2:a",
			"prev_events": [["$e1:a", {}]],
			"content": {"membership": "join", "displayname": {}}
		},
		{
			"type": "m.room.member",
			"state_key": "@u1:a",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"event_id": "$e2:a",
			"prev_events": [["$e1:a", {}]],
			"content": {"membership": "join", "displayname": 0}
		},
		{
			"type": "m.room.member",
			"state_key": "@u1:a",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"event_id": "$e2:a",
			"prev_events": [["$e1:a", {}]],
			"content": {"membership": "join", "displayname": []}
		}],
		"not_allowed": []
	}`, RoomVersionV1)
}

func TestMembershipBanned(t *testing.T) {
	testEventAllowed(t, `{
		"auth_events": {
			"create": {
				"type": "m.room.create",
				"state_key": "",
				"sender": "@u1:a",
				"room_id": "!r1:a",
				"event_id": "$e1:a",
				"content": {"creator": "@u1:a"}
			},
			"join_rules": {
				"type": "m.room.join_rules",
				"state_key": "",
				"sender": "@u2:a",
				"room_id": "!r1:a",
				"event_id": "$e1:a",
				"content": {"join_rule": "knock" }
			},
			"power_levels": {
				"type": "m.room.power_levels",
				"sender": "@u1:a",
				"room_id": "!r1:a",
				"event_id": "$e5:a",
				"content": {
					"users": {
						"@u2:a": 100
					},
					"ban": 50
				}
			},
			"member": {
				"@u1:a": {
					"type": "m.room.member",
					"sender": "@u1:a",
					"room_id": "!r1:a",
					"state_key": "@u1:a",
					"event_id": "$e2:a",
					"content": {"membership": "ban"}
				},
				"@u2:a": {
					"type": "m.room.member",
					"sender": "@u2:a",
					"room_id": "!r1:a",
					"state_key": "@u2:a",
					"event_id": "$e2:a",
					"content": {"membership": "join"}
				},
				"@u3:a": {
					"type": "m.room.member",
					"sender": "@u3:a",
					"room_id": "!r1:a",
					"state_key": "@u3:a",
					"event_id": "$e2:a",
					"content": {"membership": "knock"}
				},
				"@u4:a": {
					"type": "m.room.member",
					"sender": "@u2:a",
					"room_id": "!r1:a",
					"state_key": "@u4:a",
					"event_id": "$e2:a",
					"content": {"membership": "invite"}
				}
			}
		},
		"allowed": [{
			"type": "m.room.member",
			"sender": "@u2:a",
			"room_id": "!r1:a",
			"state_key": "@u1:a",
			"event_id": "$e4:a",
			"content": {"membership": "leave"}
		}, {
			"type": "m.room.member",
			"sender": "@u2:a",
			"room_id": "!r1:a",
			"state_key": "@u3:a",
			"event_id": "$e4:a",
			"content": {"membership": "ban"}
		},
		{
			"type": "m.room.member",
			"sender": "@u2:a",
			"room_id": "!r1:a",
			"state_key": "@u3:a",
			"event_id": "$e4:a",
			"content": {"membership": "ban"}
		},
		{
			"type": "m.room.member",
			"sender": "@u2:a",
			"room_id": "!r1:a",
			"state_key": "@u4:a",
			"event_id": "$e4:a",
			"content": {"membership": "ban"}
		}
		],
		"not_allowed": [{
			"type": "m.room.member",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"state_key": "@u1:a",
			"event_id": "$e4:a",
			"content": {"membership": "join"},
			"unsigned": {
				"not_allowed": "Sender should not be able to ban->join themselves"
			}
		},
		{
			"type": "m.room.member",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"state_key": "@u1:a",
			"event_id": "$e4:a",
			"content": {"membership": "knock"},
			"unsigned": {
				"not_allowed": "Sender should not be able to ban->knock themselves"
			}
		},
		{
			"type": "m.room.member",
			"sender": "@u2:a",
			"room_id": "!r1:a",
			"state_key": "@u1:a",
			"event_id": "$e4:a",
			"content": {"membership": "invite"},
			"unsigned": {
				"not_allowed": "Sender should not be able to ban->invite themselves"
			}
		}]
	}`, RoomVersionV10)
}

func TestJoinRuleInvite(t *testing.T) {
	testEventAllowed(t, `{
		"auth_events": {
			"create": {
				"type": "m.room.create",
				"state_key": "",
				"sender": "@u1:a",
				"room_id": "!r1:a",
				"event_id": "$e1:a",
				"content": {"creator": "@u1:a"}
			},
			"join_rules": {
				"type": "m.room.join_rules",
				"state_key": "",
				"sender": "@u1:a",
				"room_id": "!r1:a",
				"event_id": "$e1:a",
				"content": {"join_rule": "invite" }
			},
			"member": {
				"@u2:a": {
					"type": "m.room.member",
					"sender": "@u2:a",
					"room_id": "!r1:a",
					"state_key": "@u2:a",
					"event_id": "$e2:a",
					"content": {"membership": "invite"}
				}
			}
		},
		"allowed": [{
			"type": "m.room.member",
			"sender": "@u2:a",
			"room_id": "!r1:a",
			"state_key": "@u2:a",
			"event_id": "$e2:a",
			"content": {"membership": "join"}
		}],
		"not_allowed": [{
			"type": "m.room.member",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"state_key": "@u1:a",
			"event_id": "$e2:a",
			"content": {"membership": "join"},
			"unsigned": {
				"not_allowed": "Sender not invited or joined"
			}
		}]
	}`, RoomVersionV1)
}

func TestJoinRuleKnock(t *testing.T) {
	testEventAllowed(t, `{
		"auth_events": {
			"create": {
				"type": "m.room.create",
				"state_key": "",
				"sender": "@u1:a",
				"room_id": "!r1:a",
				"event_id": "$e1:a",
				"content": {"creator": "@u1:a"}
			},
			"join_rules": {
				"type": "m.room.join_rules",
				"state_key": "",
				"sender": "@u1:a",
				"room_id": "!r1:a",
				"event_id": "$e1:a",
				"content": {"join_rule": "knock" }
			},
			"member": {
				"@u2:a": {
					"type": "m.room.member",
					"sender": "@u2:a",
					"room_id": "!r1:a",
					"state_key": "@u2:a",
					"event_id": "$e2:a",
					"content": {"membership": "invite"}
				},
				"@u3:a": {
					"type": "m.room.member",
					"sender": "@u3:a",
					"room_id": "!r1:a",
					"state_key": "@u3:a",
					"event_id": "$e2:a",
					"content": {"membership": "join"}
				},
				"@u4:a": {
					"type": "m.room.member",
					"sender": "@u4:a",
					"room_id": "!r1:a",
					"state_key": "@u4:a",
					"event_id": "$e2:a",
					"content": {"membership": "knock"}
				},
				"@u5:a": {
					"type": "m.room.member",
					"sender": "@u5:a",
					"room_id": "!r1:a",
					"state_key": "@u5:a",
					"event_id": "$e2:a",
					"content": {"membership": "ban"}
				}
			}
		},
		"allowed": [{
			"type": "m.room.member",
			"sender": "@u2:a",
			"room_id": "!r1:a",
			"state_key": "@u2:a",
			"event_id": "$e2:a",
			"content": {"membership": "join"}
		}, {
			"type": "m.room.member",
			"sender": "@u3:a",
			"room_id": "!r1:a",
			"state_key": "@u3:a",
			"event_id": "$e2:a",
			"content": {"membership": "join"}
		}],
		"not_allowed": [{
			"type": "m.room.member",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"state_key": "@u1:a",
			"event_id": "$e2:a",
			"content": {"membership": "join"},
			"unsigned": {
				"not_allowed": "Sender not invited or joined"
			}
		},
		{
			"type": "m.room.member",
			"sender": "@u4:a",
			"room_id": "!r1:a",
			"state_key": "@u4:a",
			"event_id": "$e2:a",
			"content": {"membership": "join"},
			"unsigned": {
				"not_allowed": "Sender not invited or joined"
			}
		},
		{
			"type": "m.room.member",
			"sender": "@u3:a",
			"room_id": "!r1:a",
			"state_key": "@u3:a",
			"event_id": "$e2:a",
			"content": {"membership": "knock"},
			"unsigned": {
				"not_allowed": "Sender is already joined"
			}
		},
		{
			"type": "m.room.member",
			"sender": "@u5:a",
			"room_id": "!r1:a",
			"state_key": "@u5:a",
			"event_id": "$e2:a",
			"content": {"membership": "knock"},
			"unsigned": {
				"not_allowed": "Sender is banned"
			}
		}]
	}`, RoomVersionV10)
}

func TestJoinRuleKnockRestricted(t *testing.T) {
	testEventAllowed(t, `{
		"auth_events": {
			"create": {
				"type": "m.room.create",
				"state_key": "",
				"sender": "@u1:a",
				"room_id": "!r1:a",
				"event_id": "$e1:a",
				"content": {"creator": "@u1:a"}
			},
			"join_rules": {
				"type": "m.room.join_rules",
				"state_key": "",
				"sender": "@u1:a",
				"room_id": "!r1:a",
				"event_id": "$e1:a",
				"content": {"join_rule": "knock_restricted" }
			},
			"member": {
				"@u2:a": {
					"type": "m.room.member",
					"sender": "@u2:a",
					"room_id": "!r1:a",
					"state_key": "@u2:a",
					"event_id": "$e2:a",
					"content": {"membership": "invite"}
				},
				"@u3:a": {
					"type": "m.room.member",
					"sender": "@u3:a",
					"room_id": "!r1:a",
					"state_key": "@u3:a",
					"event_id": "$e2:a",
					"content": {"membership": "join"}
				},
				"@u4:a": {
					"type": "m.room.member",
					"sender": "@u4:a",
					"room_id": "!r1:a",
					"state_key": "@u4:a",
					"event_id": "$e2:a",
					"content": {"membership": "knock"}
				}
			}
		},
		"allowed": [{
			"type": "m.room.member",
			"sender": "@u2:a",
			"room_id": "!r1:a",
			"state_key": "@u2:a",
			"event_id": "$e2:a",
			"content": {"membership": "join"}
		}, {
			"type": "m.room.member",
			"sender": "@u3:a",
			"room_id": "!r1:a",
			"state_key": "@u3:a",
			"event_id": "$e2:a",
			"content": {"membership": "join"}
		}, {
			"type": "m.room.member",
			"sender": "@u4:a",
			"room_id": "!r1:a",
			"state_key": "@u4:a",
			"event_id": "$e2:a",
			"content": {"membership": "join", "join_authorised_via_users_server": "@u3:a"}
		}],
		"not_allowed": [{
			"type": "m.room.member",
			"sender": "@u1:a",
			"room_id": "!r1:a",
			"state_key": "@u1:a",
			"event_id": "$e2:a",
			"content": {"membership": "join"},
			"unsigned": {
				"not_allowed": "Sender not invited or joined"
			}
		},
		{
			"type": "m.room.member",
			"sender": "@u4:a",
			"room_id": "!r1:a",
			"state_key": "@u4:a",
			"event_id": "$e2:a",
			"content": {"membership": "join"},
			"unsigned": {
				"not_allowed": "Sender not invited or joined"
			}
		}]
	}`, RoomVersionV10)
}
