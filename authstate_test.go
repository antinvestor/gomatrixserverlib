//nolint:testpackage
package gomatrixserverlib

import (
	"context"
	"testing"

	"github.com/antinvestor/gomatrixserverlib/spec"
)

func UserIDForSenderTest(roomID spec.RoomID, senderID spec.SenderID) (*spec.UserID, error) {
	return spec.NewUserID(string(senderID), true)
}

type TestStateProvider struct {
	StateIDs []string
	Events   []PDU
}

func (p *TestStateProvider) StateIDsBeforeEvent(ctx context.Context, atEvent PDU) ([]string, error) {
	return p.StateIDs, nil
}

func (p *TestStateProvider) StateBeforeEvent(
	ctx context.Context,
	roomVer RoomVersion,
	event PDU,
	eventIDs []string,
) (map[string]PDU, error) {
	result := make(map[string]PDU, len(p.Events))
	for i := range p.Events {
		result[p.Events[i].EventID()] = p.Events[i]
	}
	return result, nil
}

// The purpose of this test is to check that short-circuiting works correctly. In this test, the auth_events listed
// in the event are all in the returned state IDs, so there shouldn't be any requests to fetch the entire room state,
// which will return nothing if requested.
func TestVerifyAuthRulesAtStateValidate(t *testing.T) {
	ctx := t.Context()
	tsp := &TestStateProvider{
		StateIDs: []string{
			"$WCraVpPZe5TtHAqs:baba.is.you",
			"$fnwGrQEpiOIUoDU2:baba.is.you",
		},
		Events: nil,
	}
	eventToVerify, err := MustGetRoomVersion(RoomVersionV1).NewEventFromTrustedJSON(
		[]byte(
			`{"auth_events":[["$WCraVpPZe5TtHAqs:baba.is.you",{"sha256":"gBxQI2xzDLMoyIjkrpCJFBXC5NnrSemepc7SninSARI"}],["$fnwGrQEpiOIUoDU2:baba.is.you",{"sha256":"gUr26K5Tt7GQlNs8BlUup92gOzAZHbT8WNEobkrEIqk"}]],"content":{"body":"Test Message"},"depth":2,"event_id":"$xOJZshi3NeKKJiCf:baba.is.you","hashes":{"sha256":"lu5fF5HE090AXdu/+NpJ/RjRVRk/2tWCUozUc5t7Ru4"},"origin":"baba.is.you","origin_server_ts":0,"prev_events":[["$fnwGrQEpiOIUoDU2:baba.is.you",{"sha256":"gUr26K5Tt7GQlNs8BlUup92gOzAZHbT8WNEobkrEIqk"}]],"room_id":"!roomid:baba.is.you","sender":"@userid:baba.is.you","signatures":{"baba.is.you":{"ed25519:auto":"5KoVSLOBesqH9vciKXDExdu95lKFDtK1I72Hq1GG/UeEsH9jx7wL3V4jGYSKDnX2aLYp/VPiBQje7DFjde+hDQ"}},"type":"m.room.message"}`,
		),
		false,
	)
	if err != nil {
		t.Fatalf("Failed to load test event: %s", err)
	}

	err = VerifyAuthRulesAtState(ctx, tsp, eventToVerify, true, UserIDForSenderTest)
	if err != nil {
		t.Fatalf("VerifyAuthRulesAtState expect no error, got %s", err)
	}
}

// The purpose of this test is to check that verification of the event works correctly. Validation is disabled in this test,
// so the events should be fetched and a complete check should occur.
func TestVerifyAuthRulesAtStateVerify(t *testing.T) {
	ctx := t.Context()
	tsp := &TestStateProvider{
		StateIDs: []string{
			"$WCraVpPZe5TtHAqs:baba.is.you",
			"$fnwGrQEpiOIUoDU2:baba.is.you",
		},
		Events: makeEvents(t, [][]byte{
			[]byte(
				`{"auth_events":[],"content":{"creator":"@userid:baba.is.you"},"depth":0,"event_id":"$WCraVpPZe5TtHAqs:baba.is.you","hashes":{"sha256":"EehWNbKy+oDOMC0vIvYl1FekdDxMNuabXKUVzV7DG74"},"origin":"baba.is.you","origin_server_ts":0,"prev_events":[],"prev_state":[],"room_id":"!roomid:baba.is.you","sender":"@userid:baba.is.you","signatures":{"baba.is.you":{"ed25519:auto":"08aF4/bYWKrdGPFdXmZCQU6IrOE1ulpevmWBM3kiShJPAbRbZ6Awk7buWkIxlMF6kX3kb4QpbAlZfHLQgncjCw"}},"state_key":"","type":"m.room.create"}`,
			),
			[]byte(
				`{"auth_events":[["$WCraVpPZe5TtHAqs:baba.is.you",{"sha256":"gBxQI2xzDLMoyIjkrpCJFBXC5NnrSemepc7SninSARI"}]],"content":{"membership":"join"},"depth":1,"event_id":"$fnwGrQEpiOIUoDU2:baba.is.you","hashes":{"sha256":"DqOjdFgvFQ3V/jvQW2j3ygHL4D+t7/LaIPZ/tHTDZtI"},"origin":"baba.is.you","origin_server_ts":0,"prev_events":[["$WCraVpPZe5TtHAqs:baba.is.you",{"sha256":"gBxQI2xzDLMoyIjkrpCJFBXC5NnrSemepc7SninSARI"}]],"prev_state":[],"room_id":"!roomid:baba.is.you","sender":"@userid:baba.is.you","signatures":{"baba.is.you":{"ed25519:auto":"qBWLb42zicQVsbh333YrcKpHfKokcUOM/ytldGlrgSdXqDEDDxvpcFlfadYnyvj3Z/GjA2XZkqKHanNEh575Bw"}},"state_key":"@userid:baba.is.you","type":"m.room.member"}`,
			),
		}),
	}
	eventToVerify, err := MustGetRoomVersion(RoomVersionV1).NewEventFromTrustedJSON(
		[]byte(
			`{"auth_events":[["$WCraVpPZe5TtHAqs:baba.is.you",{"sha256":"gBxQI2xzDLMoyIjkrpCJFBXC5NnrSemepc7SninSARI"}],["$fnwGrQEpiOIUoDU2:baba.is.you",{"sha256":"gUr26K5Tt7GQlNs8BlUup92gOzAZHbT8WNEobkrEIqk"}]],"content":{"body":"Test Message"},"depth":2,"event_id":"$xOJZshi3NeKKJiCf:baba.is.you","hashes":{"sha256":"lu5fF5HE090AXdu/+NpJ/RjRVRk/2tWCUozUc5t7Ru4"},"origin":"baba.is.you","origin_server_ts":0,"prev_events":[["$fnwGrQEpiOIUoDU2:baba.is.you",{"sha256":"gUr26K5Tt7GQlNs8BlUup92gOzAZHbT8WNEobkrEIqk"}]],"room_id":"!roomid:baba.is.you","sender":"@userid:baba.is.you","signatures":{"baba.is.you":{"ed25519:auto":"5KoVSLOBesqH9vciKXDExdu95lKFDtK1I72Hq1GG/UeEsH9jx7wL3V4jGYSKDnX2aLYp/VPiBQje7DFjde+hDQ"}},"type":"m.room.message"}`,
		),
		false)
	if err != nil {
		t.Fatalf("Failed to load test event: %s", err)
	}

	err = VerifyAuthRulesAtState(ctx, tsp, eventToVerify, false, UserIDForSenderTest)
	if err != nil {
		t.Fatalf("VerifyAuthRulesAtState expect no error, got %s", err)
	}
}

// The purpose of this test is to check that verification of the event works correctly. Validation is disabled in this test,
// so the events should be fetched and a complete check should occur. The check should fail because the membership of the user
// is set to 'leave'.
func TestVerifyAuthRulesAtStateVerifyFailure(t *testing.T) {
	ctx := t.Context()
	tsp := &TestStateProvider{
		StateIDs: []string{
			"$WCraVpPZe5TtHAqs:baba.is.you",
			"$fnwGrQEpiOIUoDU2:baba.is.you",
		},
		Events: makeEvents(t, [][]byte{
			[]byte(
				`{"auth_events":[],"content":{"creator":"@userid:baba.is.you"},"depth":0,"event_id":"$WCraVpPZe5TtHAqs:baba.is.you","hashes":{"sha256":"EehWNbKy+oDOMC0vIvYl1FekdDxMNuabXKUVzV7DG74"},"origin":"baba.is.you","origin_server_ts":0,"prev_events":[],"prev_state":[],"room_id":"!roomid:baba.is.you","sender":"@userid:baba.is.you","signatures":{"baba.is.you":{"ed25519:auto":"08aF4/bYWKrdGPFdXmZCQU6IrOE1ulpevmWBM3kiShJPAbRbZ6Awk7buWkIxlMF6kX3kb4QpbAlZfHLQgncjCw"}},"state_key":"","type":"m.room.create"}`,
			),
			[]byte(
				`{"auth_events":[["$WCraVpPZe5TtHAqs:baba.is.you",{"sha256":"gBxQI2xzDLMoyIjkrpCJFBXC5NnrSemepc7SninSARI"}]],"content":{"membership":"leave"},"depth":1,"event_id":"$fnwGrQEpiOIUoDU2:baba.is.you","hashes":{"sha256":"DqOjdFgvFQ3V/jvQW2j3ygHL4D+t7/LaIPZ/tHTDZtI"},"origin":"baba.is.you","origin_server_ts":0,"prev_events":[["$WCraVpPZe5TtHAqs:baba.is.you",{"sha256":"gBxQI2xzDLMoyIjkrpCJFBXC5NnrSemepc7SninSARI"}]],"prev_state":[],"room_id":"!roomid:baba.is.you","sender":"@userid:baba.is.you","signatures":{"baba.is.you":{"ed25519:auto":"qBWLb42zicQVsbh333YrcKpHfKokcUOM/ytldGlrgSdXqDEDDxvpcFlfadYnyvj3Z/GjA2XZkqKHanNEh575Bw"}},"state_key":"@userid:baba.is.you","type":"m.room.member"}`,
			),
		}),
	}
	eventToVerify, err := MustGetRoomVersion(RoomVersionV1).NewEventFromTrustedJSON(
		[]byte(
			`{"auth_events":[["$WCraVpPZe5TtHAqs:baba.is.you",{"sha256":"gBxQI2xzDLMoyIjkrpCJFBXC5NnrSemepc7SninSARI"}],["$fnwGrQEpiOIUoDU2:baba.is.you",{"sha256":"gUr26K5Tt7GQlNs8BlUup92gOzAZHbT8WNEobkrEIqk"}]],"content":{"body":"Test Message"},"depth":2,"event_id":"$xOJZshi3NeKKJiCf:baba.is.you","hashes":{"sha256":"lu5fF5HE090AXdu/+NpJ/RjRVRk/2tWCUozUc5t7Ru4"},"origin":"baba.is.you","origin_server_ts":0,"prev_events":[["$fnwGrQEpiOIUoDU2:baba.is.you",{"sha256":"gUr26K5Tt7GQlNs8BlUup92gOzAZHbT8WNEobkrEIqk"}]],"room_id":"!roomid:baba.is.you","sender":"@userid:baba.is.you","signatures":{"baba.is.you":{"ed25519:auto":"5KoVSLOBesqH9vciKXDExdu95lKFDtK1I72Hq1GG/UeEsH9jx7wL3V4jGYSKDnX2aLYp/VPiBQje7DFjde+hDQ"}},"type":"m.room.message"}`,
		),
		false,
	)
	if err != nil {
		t.Fatalf("Failed to load test event: %s", err)
	}

	err = VerifyAuthRulesAtState(ctx, tsp, eventToVerify, false, UserIDForSenderTest)
	if err == nil {
		t.Fatalf("VerifyAuthRulesAtState expected error, got none")
	}
	// conversely the check should PASS if validation is enabled, as validation assumes Allowed checks were already run
	err = VerifyAuthRulesAtState(ctx, tsp, eventToVerify, true, UserIDForSenderTest)
	if err != nil {
		t.Fatalf("VerifyAuthRulesAtState expect no error, got %s", err)
	}
}

// The purpose of this test is to check that verification of the event works correctly. Validation is disabled in this test,
// so the events should be fetched and a complete check should occur. The check should succeed as even though the room state
// does NOT have the auth events listed on the event, the action is still allowed to be performed based off the room state at this time.
func TestVerifyAuthRulesAtStateBadAuthRuleButValidState(t *testing.T) {
	ctx := t.Context()
	tsp := &TestStateProvider{
		StateIDs: []string{
			"$createevent:baba.is.you",
			"$membershipevent:baba.is.you",
		},
		Events: makeEvents(t, [][]byte{
			[]byte(
				`{"auth_events":[],"content":{"creator":"@userid:baba.is.you"},"depth":0,"event_id":"$createevent:baba.is.you","hashes":{"sha256":"EehWNbKy+oDOMC0vIvYl1FekdDxMNuabXKUVzV7DG74"},"origin":"baba.is.you","origin_server_ts":0,"prev_events":[],"prev_state":[],"room_id":"!roomid:baba.is.you","sender":"@userid:baba.is.you","signatures":{"baba.is.you":{"ed25519:auto":"08aF4/bYWKrdGPFdXmZCQU6IrOE1ulpevmWBM3kiShJPAbRbZ6Awk7buWkIxlMF6kX3kb4QpbAlZfHLQgncjCw"}},"state_key":"","type":"m.room.create"}`,
			),
			[]byte(
				`{"auth_events":[["$WCraVpPZe5TtHAqs:baba.is.you",{"sha256":"gBxQI2xzDLMoyIjkrpCJFBXC5NnrSemepc7SninSARI"}]],"content":{"membership":"leave"},"depth":1,"event_id":"$membershipevent:baba.is.you","hashes":{"sha256":"DqOjdFgvFQ3V/jvQW2j3ygHL4D+t7/LaIPZ/tHTDZtI"},"origin":"baba.is.you","origin_server_ts":0,"prev_events":[["$WCraVpPZe5TtHAqs:baba.is.you",{"sha256":"gBxQI2xzDLMoyIjkrpCJFBXC5NnrSemepc7SninSARI"}]],"prev_state":[],"room_id":"!roomid:baba.is.you","sender":"@userid:baba.is.you","signatures":{"baba.is.you":{"ed25519:auto":"qBWLb42zicQVsbh333YrcKpHfKokcUOM/ytldGlrgSdXqDEDDxvpcFlfadYnyvj3Z/GjA2XZkqKHanNEh575Bw"}},"state_key":"@userid:baba.is.you","type":"m.room.member"}`,
			),
		}),
	}
	eventToVerify, err := MustGetRoomVersion(RoomVersionV1).NewEventFromTrustedJSON(
		[]byte(
			`{"auth_events":[["$WCraVpPZe5TtHAqs:baba.is.you",{"sha256":"gBxQI2xzDLMoyIjkrpCJFBXC5NnrSemepc7SninSARI"}],["$fnwGrQEpiOIUoDU2:baba.is.you",{"sha256":"gUr26K5Tt7GQlNs8BlUup92gOzAZHbT8WNEobkrEIqk"}]],"content":{"body":"Test Message"},"depth":2,"event_id":"$xOJZshi3NeKKJiCf:baba.is.you","hashes":{"sha256":"lu5fF5HE090AXdu/+NpJ/RjRVRk/2tWCUozUc5t7Ru4"},"origin":"baba.is.you","origin_server_ts":0,"prev_events":[["$fnwGrQEpiOIUoDU2:baba.is.you",{"sha256":"gUr26K5Tt7GQlNs8BlUup92gOzAZHbT8WNEobkrEIqk"}]],"room_id":"!roomid:baba.is.you","sender":"@userid:baba.is.you","signatures":{"baba.is.you":{"ed25519:auto":"5KoVSLOBesqH9vciKXDExdu95lKFDtK1I72Hq1GG/UeEsH9jx7wL3V4jGYSKDnX2aLYp/VPiBQje7DFjde+hDQ"}},"type":"m.room.message"}`,
		),
		false,
	)
	if err != nil {
		t.Fatalf("Failed to load test event: %s", err)
	}
	// this should still pass with or without validation checks
	for _, b := range []bool{true, false} {
		err = VerifyAuthRulesAtState(ctx, tsp, eventToVerify, b, UserIDForSenderTest)
		if err == nil {
			t.Fatalf("VerifyAuthRulesAtState expected error, got none")
		}
	}
}

func makeEvents(t *testing.T, in [][]byte) (out []PDU) {
	for _, raw := range in {
		ev, err := MustGetRoomVersion(RoomVersionV1).NewEventFromTrustedJSON(raw, false)
		if err != nil {
			t.Fatalf("makeEvent failed: %s", err)
		}
		out = append(out, ev)
	}
	return out
}
