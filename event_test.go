// nolint:testpackage
/* Copyright 2017 New Vector Ltd
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
	"bytes"
	"encoding/base64"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/antinvestor/gomatrixserverlib/spec"
	"golang.org/x/crypto/ed25519"
)

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

func benchmarkParse(b *testing.B, eventJSON string) {
	// run the Unparse function b.N times
	for range b.N {
		if _, err := newEventFromUntrustedJSONV1([]byte(eventJSON), MustGetRoomVersion(RoomVersionV1)); err != nil {
			b.Error("Failed to parse event")
		}
	}
}

// Benchmark a more complicated event, in this case a power levels event.

func BenchmarkParseLargerEvent(b *testing.B) {
	benchmarkParse(
		b,
		`{"auth_events":[["$Stdin0028C5qBjz5:localhost",{"sha256":"PvTyW+Mfb0aCajkIlBk1XlQE+1uVco3to8C2+/1J7iQ"}],["$klXtjBwwDQIGglax:localhost",{"sha256":"hLoiSkcGLZJr5wkIDA8+bujNJPsYX1SOCCXIErHEcgM"}]],"content":{"ban":50,"events":{"m.room.avatar":50,"m.room.canonical_alias":50,"m.room.history_visibility":100,"m.room.name":50,"m.room.power_levels":100},"events_default":0,"invite":0,"kick":50,"redact":50,"state_default":50,"users":{"@test:localhost":100},"users_default":0},"depth":3,"event_id":"$7gPR7SLdkfDsMvJL:localhost","hashes":{"sha256":"/kQnrzO5vhbnwyGvKso4CVMRyyryiyanq6t27mt5kSw"},"origin":"localhost","origin_server_ts":1510854446548,"prev_events":[["$klXtjBwwDQIGglax:localhost",{"sha256":"hLoiSkcGLZJr5wkIDA8+bujNJPsYX1SOCCXIErHEcgM"}]],"prev_state":[],"room_id":"!pUjJbIC8V32G0FLt:localhost","sender":"@test:localhost","signatures":{"localhost":{"ed25519:u9kP":"NOxjrcci7AIRhcTVmJ6nrsslLsaOJzB0iusDZ6cOFrv2OXkDY7mrBM3cQQS3DhGWltEtu3OC0nsvkfeYtwr9DQ"}},"state_key":"","type":"m.room.power_levels"}`,
	)
}

// Lets now test parsing a smaller name event, first one that is valid, then wrong hash, and then the redacted one

func BenchmarkParseSmallerEvent(b *testing.B) {
	benchmarkParse(
		b,
		`{"auth_events":[["$oXL79cT7fFxR7dPH:localhost",{"sha256":"abjkiDSg1RkuZrbj2jZoGMlQaaj1Ue3Jhi7I7NlKfXY"}],["$IVUsaSkm1LBAZYYh:localhost",{"sha256":"X7RUj46hM/8sUHNBIFkStbOauPvbDzjSdH4NibYWnko"}],["$VS2QT0EeArZYi8wf:localhost",{"sha256":"k9eM6utkCH8vhLW9/oRsH74jOBS/6RVK42iGDFbylno"}]],"content":{"name":"test3"},"depth":7,"event_id":"$yvN1b43rlmcOs5fY:localhost","hashes":{"sha256":"Oh1mwI1jEqZ3tgJ+V1Dmu5nOEGpCE4RFUqyJv2gQXKs"},"origin":"localhost","origin_server_ts":1510854416361,"prev_events":[["$FqI6TVvWpcbcnJ97:localhost",{"sha256":"upCsBqUhNUgT2/+zkzg8TbqdQpWWKQnZpGJc6KcbUC4"}]],"prev_state":[],"room_id":"!19Mp0U9hjajeIiw1:localhost","sender":"@test:localhost","signatures":{"localhost":{"ed25519:u9kP":"5IzSuRXkxvbTp0vZhhXYZeOe+619iG3AybJXr7zfNn/4vHz4TH7qSJVQXSaHHvcTcDodAKHnTG1WDulgO5okAQ"}},"state_key":"","type":"m.room.name"}`,
	)
}

func BenchmarkParseSmallerEventFailedHash(b *testing.B) {
	benchmarkParse(
		b,
		`{"auth_events":[["$oXL79cT7fFxR7dPH:localhost",{"sha256":"abjkiDSg1RkuZrbj2jZoGMlQaaj1Ue3Jhi7I7NlKfXY"}],["$IVUsaSkm1LBAZYYh:localhost",{"sha256":"X7RUj46hM/8sUHNBIFkStbOauPvbDzjSdH4NibYWnko"}],["$VS2QT0EeArZYi8wf:localhost",{"sha256":"k9eM6utkCH8vhLW9/oRsH74jOBS/6RVK42iGDFbylno"}]],"content":{"name":"test4"},"depth":7,"event_id":"$yvN1b43rlmcOs5fY:localhost","hashes":{"sha256":"Oh1mwI1jEqZ3tgJ+V1Dmu5nOEGpCE4RFUqyJv2gQXKs"},"origin":"localhost","origin_server_ts":1510854416361,"prev_events":[["$FqI6TVvWpcbcnJ97:localhost",{"sha256":"upCsBqUhNUgT2/+zkzg8TbqdQpWWKQnZpGJc6KcbUC4"}]],"prev_state":[],"room_id":"!19Mp0U9hjajeIiw1:localhost","sender":"@test:localhost","signatures":{"localhost":{"ed25519:u9kP":"5IzSuRXkxvbTp0vZhhXYZeOe+619iG3AybJXr7zfNn/4vHz4TH7qSJVQXSaHHvcTcDodAKHnTG1WDulgO5okAQ"}},"state_key":"","type":"m.room.name"}`,
	)
}

func BenchmarkParseSmallerEventRedacted(b *testing.B) {
	benchmarkParse(
		b,
		`{"event_id":"$yvN1b43rlmcOs5fY:localhost","sender":"@test:localhost","room_id":"!19Mp0U9hjajeIiw1:localhost","hashes":{"sha256":"Oh1mwI1jEqZ3tgJ+V1Dmu5nOEGpCE4RFUqyJv2gQXKs"},"signatures":{"localhost":{"ed25519:u9kP":"5IzSuRXkxvbTp0vZhhXYZeOe+619iG3AybJXr7zfNn/4vHz4TH7qSJVQXSaHHvcTcDodAKHnTG1WDulgO5okAQ"}},"content":{},"type":"m.room.name","state_key":"","depth":7,"prev_events":[["$FqI6TVvWpcbcnJ97:localhost",{"sha256":"upCsBqUhNUgT2/+zkzg8TbqdQpWWKQnZpGJc6KcbUC4"}]],"prev_state":[],"auth_events":[["$oXL79cT7fFxR7dPH:localhost",{"sha256":"abjkiDSg1RkuZrbj2jZoGMlQaaj1Ue3Jhi7I7NlKfXY"}],["$IVUsaSkm1LBAZYYh:localhost",{"sha256":"X7RUj46hM/8sUHNBIFkStbOauPvbDzjSdH4NibYWnko"}],["$VS2QT0EeArZYi8wf:localhost",{"sha256":"k9eM6utkCH8vhLW9/oRsH74jOBS/6RVK42iGDFbylno"}]],"origin":"localhost","origin_server_ts":1510854416361}`,
	)
}

func TestAddUnsignedField(t *testing.T) {
	initialEventJSON := `{"auth_events":[["$oXL79cT7fFxR7dPH:localhost",{"sha256":"abjkiDSg1RkuZrbj2jZoGMlQaaj1Ue3Jhi7I7NlKfXY"}],["$IVUsaSkm1LBAZYYh:localhost",{"sha256":"X7RUj46hM/8sUHNBIFkStbOauPvbDzjSdH4NibYWnko"}],["$VS2QT0EeArZYi8wf:localhost",{"sha256":"k9eM6utkCH8vhLW9/oRsH74jOBS/6RVK42iGDFbylno"}]],"content":{"name":"test3"},"depth":7,"event_id":"$yvN1b43rlmcOs5fY:localhost","hashes":{"sha256":"Oh1mwI1jEqZ3tgJ+V1Dmu5nOEGpCE4RFUqyJv2gQXKs"},"origin":"localhost","origin_server_ts":1510854416361,"prev_events":[["$FqI6TVvWpcbcnJ97:localhost",{"sha256":"upCsBqUhNUgT2/+zkzg8TbqdQpWWKQnZpGJc6KcbUC4"}]],"prev_state":[],"room_id":"!19Mp0U9hjajeIiw1:localhost","sender":"@test:localhost","signatures":{"localhost":{"ed25519:u9kP":"5IzSuRXkxvbTp0vZhhXYZeOe+619iG3AybJXr7zfNn/4vHz4TH7qSJVQXSaHHvcTcDodAKHnTG1WDulgO5okAQ"}},"state_key":"","type":"m.room.name"}`
	expectedEventJSON := `{"auth_events":[["$oXL79cT7fFxR7dPH:localhost",{"sha256":"abjkiDSg1RkuZrbj2jZoGMlQaaj1Ue3Jhi7I7NlKfXY"}],["$IVUsaSkm1LBAZYYh:localhost",{"sha256":"X7RUj46hM/8sUHNBIFkStbOauPvbDzjSdH4NibYWnko"}],["$VS2QT0EeArZYi8wf:localhost",{"sha256":"k9eM6utkCH8vhLW9/oRsH74jOBS/6RVK42iGDFbylno"}]],"content":{"name":"test3"},"depth":7,"event_id":"$yvN1b43rlmcOs5fY:localhost","hashes":{"sha256":"Oh1mwI1jEqZ3tgJ+V1Dmu5nOEGpCE4RFUqyJv2gQXKs"},"origin":"localhost","origin_server_ts":1510854416361,"prev_events":[["$FqI6TVvWpcbcnJ97:localhost",{"sha256":"upCsBqUhNUgT2/+zkzg8TbqdQpWWKQnZpGJc6KcbUC4"}]],"prev_state":[],"room_id":"!19Mp0U9hjajeIiw1:localhost","sender":"@test:localhost","signatures":{"localhost":{"ed25519:u9kP":"5IzSuRXkxvbTp0vZhhXYZeOe+619iG3AybJXr7zfNn/4vHz4TH7qSJVQXSaHHvcTcDodAKHnTG1WDulgO5okAQ"}},"state_key":"","type":"m.room.name","unsigned":{"foo":"bar","x":1}}`

	event, err := newEventFromTrustedJSONV1([]byte(initialEventJSON), false, MustGetRoomVersion(RoomVersionV1))
	if err != nil {
		t.Error(err)
	}

	err = event.SetUnsignedField("foo", "bar")
	if err != nil {
		t.Error("Failed to insert foo")
	}

	err = event.SetUnsignedField("x", 1)
	if err != nil {
		t.Error("Failed to insert x")
	}

	if expectedEventJSON != string(event.JSON()) {
		t.Fatalf("Serialized event does not match expected: %s != %s", string(event.JSON()), initialEventJSON)
	}
}

// TestRedact makes sure Redact works as expected.
func TestRedact(t *testing.T) {
	// v1 event
	nameEvent := ` {"auth_events":[["$oXL79cT7fFxR7dPH:localhost",{"sha256":"abjkiDSg1RkuZrbj2jZoGMlQaaj1Ue3Jhi7I7NlKfXY"}],["$IVUsaSkm1LBAZYYh:localhost",{"sha256":"X7RUj46hM/8sUHNBIFkStbOauPvbDzjSdH4NibYWnko"}],["$VS2QT0EeArZYi8wf:localhost",{"sha256":"k9eM6utkCH8vhLW9/oRsH74jOBS/6RVK42iGDFbylno"}]],"content":{"name":"test3"},"depth":7,"event_id":"$yvN1b43rlmcOs5fY:localhost","hashes":{"sha256":"Oh1mwI1jEqZ3tgJ+V1Dmu5nOEGpCE4RFUqyJv2gQXKs"},"origin":"localhost","origin_server_ts":1510854416361,"prev_events":[["$FqI6TVvWpcbcnJ97:localhost",{"sha256":"upCsBqUhNUgT2/+zkzg8TbqdQpWWKQnZpGJc6KcbUC4"}]],"prev_state":[],"room_id":"!19Mp0U9hjajeIiw1:localhost","sender":"@test:localhost","signatures":{"localhost":{"ed25519:u9kP":"5IzSuRXkxvbTp0vZhhXYZeOe+619iG3AybJXr7zfNn/4vHz4TH7qSJVQXSaHHvcTcDodAKHnTG1WDulgO5okAQ"}},"state_key":"","type":"m.room.name"}`
	event, err := newEventFromTrustedJSONV1([]byte(nameEvent), false, MustGetRoomVersion(RoomVersionV1))
	if err != nil {
		t.Fatal(err)
	}
	event.Redact()
	if !reflect.DeepEqual([]byte(`{}`), event.Content()) {
		t.Fatalf("content not redacted: %s", string(event.Content()))
	}

	// v5 event
	nameEvent = `{"auth_events":["$x4MKEPRSF6OGlo0qpnsP3BfSmYX5HhVlykOsQH3ECyg","$BcEcbZnlFLB5rxSNSZNBn6fO3jU_TKAJ79wfKyCQLiU"],"content":{"name":"test123"},"depth":2,"hashes":{"sha256":"5S025c0BhumelvCXMXWlislPnDYJn18mm9XMClL1OZ8"},"origin":"localhost","origin_server_ts":0,"prev_events":["$BcEcbZnlFLB5rxSNSZNBn6fO3jU_TKAJ79wfKyCQLiU"],"prev_state":[],"room_id":"!roomid:localhost","sender":"@userid:localhost","signatures":{"localhost":{"ed25519:auto":"VHCB/tai3S2nBpvYWnOlJfjt2KcxsgBJ1W6xDYUMOxGehDOd+lI2wy5ZBZydy1xFdIBzuERn9t9aiFThIHHcCA"}},"state_key":"","type":"m.room.name"}`
	event, err = newEventFromTrustedJSONV2([]byte(nameEvent), false, MustGetRoomVersion(RoomVersionV5))
	if err != nil {
		t.Fatal(err)
	}
	event.Redact()
	if !reflect.DeepEqual([]byte(`{}`), event.Content()) {
		t.Fatalf("content not redacted: %s", string(event.Content()))
	}
}

func TestEventMembership(t *testing.T) {
	eventJSON := `{"auth_events":[["$BqcTUuCsN3g6Rj1z:localhost",{"sha256":"QHTrdwE/XVTmAWlxFwHPW7fp3JioRu6OBBRs+FI/at8"}]],"content":{"membership":"join"},"depth":1,"event_id":"$9fmIxbx4IX8w1JVo:localhost","hashes":{"sha256":"mXgoJxvMyI8ZTdhUMYwWzi0F3M50tiAQkmk0F08tQl4"},"origin":"localhost","origin_server_ts":0,"prev_events":[["$BqcTUuCsN3g6Rj1z:localhost",{"sha256":"QHTrdwE/XVTmAWlxFwHPW7fp3JioRu6OBBRs+FI/at8"}]],"prev_state":[],"room_id":"!roomid:localhost","sender":"@userid:localhost","signatures":{"localhost":{"ed25519:auto":"ndobFGFV9i2XExPHfYVI4rd10Vw6GKtmdz2Wv0WSFohtm/FqFNUnDYVTsY/qZ1vkuEjHqgb5nscKD/i7TyURBw"}},"state_key":"@userid:localhost","type":"m.room.member"}`
	event, err := newEventFromTrustedJSONV1([]byte(eventJSON), false, MustGetRoomVersion(RoomVersionV1))
	if err != nil {
		t.Fatal(err)
	}
	got, err := event.Membership()
	if err != nil {
		t.Fatal(err)
	}
	want := "join"
	if got != want {
		t.Errorf("membership: got %s want %s", got, want)
	}
}

func TestEventJoinRule(t *testing.T) {
	eventJSON := `{"auth_events":[["$BqcTUuCsN3g6Rj1z:localhost",{"sha256":"QHTrdwE/XVTmAWlxFwHPW7fp3JioRu6OBBRs+FI/at8"}],["$9fmIxbx4IX8w1JVo:localhost",{"sha256":"gee+f1VoNeYGGczs5lwnUO1qeKAh70Hw23ws+YfDYGY"}]],"content":{"join_rule":"public"},"depth":2,"event_id":"$5hL9YWgJCtDzjlAQ:localhost","hashes":{"sha256":"CetHe0Na5HKphg5iYmLThfwQyM19w3PMCrve3Bwv8rw"},"origin":"localhost","origin_server_ts":0,"prev_events":[["$9fmIxbx4IX8w1JVo:localhost",{"sha256":"gee+f1VoNeYGGczs5lwnUO1qeKAh70Hw23ws+YfDYGY"}]],"prev_state":[],"room_id":"!roomid:localhost","sender":"@userid:localhost","signatures":{"localhost":{"ed25519:auto":"dxwQWiH6ppF+VVFQ8IEAWeB30hrYiZWLsWNTrE1B0/vUWMp+qLhU+My65XhmE5XreHvgY3fOh4Le6OYUcxNTAw"}},"state_key":"","type":"m.room.join_rules"}`
	event, err := newEventFromTrustedJSONV1([]byte(eventJSON), false, MustGetRoomVersion(RoomVersionV1))
	if err != nil {
		t.Fatal(err)
	}
	got, err := event.JoinRule()
	if err != nil {
		t.Fatal(err)
	}
	want := "public"
	if got != want {
		t.Errorf("join rule: got %s want %s", got, want)
	}
}

func TestEventHistoryVisibility(t *testing.T) {
	eventJSON := `{"auth_events":[["$BqcTUuCsN3g6Rj1z:localhost",{"sha256":"QHTrdwE/XVTmAWlxFwHPW7fp3JioRu6OBBRs+FI/at8"}],["$9fmIxbx4IX8w1JVo:localhost",{"sha256":"gee+f1VoNeYGGczs5lwnUO1qeKAh70Hw23ws+YfDYGY"}]],"content":{"history_visibility":"shared"},"depth":3,"event_id":"$QAhQsLNIMdumtpOi:localhost","hashes":{"sha256":"tssm21TZjY36w9ND9h50h5zL0vqJgz5U432l45WWGaI"},"origin":"localhost","origin_server_ts":0,"prev_events":[["$5hL9YWgJCtDzjlAQ:localhost",{"sha256":"UztZf0/CBZ8UoCHuYdrxlfyUZ5nf5h8aKZkg5GVhWI0"}]],"prev_state":[],"room_id":"!roomid:localhost","sender":"@userid:localhost","signatures":{"localhost":{"ed25519:auto":"FwBwMZnGjkZFt8aiWQODSmLmy1cxVZGOFkeu3JEUVEI5r4/2BMcwdYw6+am7ov4VfDRJ/ehp9wv3Bo93XLEJCQ"}},"state_key":"","type":"m.room.history_visibility"}`
	event, err := newEventFromTrustedJSONV1([]byte(eventJSON), false, MustGetRoomVersion(RoomVersionV1))
	if err != nil {
		t.Fatal(err)
	}
	got, err := event.HistoryVisibility()
	if err != nil {
		t.Fatal(err)
	}
	want := HistoryVisibilityShared
	if got != want {
		t.Errorf("history visibility: got %s want %s", got, want)
	}
}

func TestEventPowerLevels(t *testing.T) {
	eventJSON := `{"auth_events":[["$BqcTUuCsN3g6Rj1z:localhost",{"sha256":"QHTrdwE/XVTmAWlxFwHPW7fp3JioRu6OBBRs+FI/at8"}],["$9fmIxbx4IX8w1JVo:localhost",{"sha256":"gee+f1VoNeYGGczs5lwnUO1qeKAh70Hw23ws+YfDYGY"}]],"content":{"ban":50,"events":null,"events_default":0,"invite":0,"kick":50,"redact":50,"state_default":50,"users":null,"users_default":0,"notifications":{"room":50}},"depth":4,"event_id":"$1570trwyGMovM5uU:localhost","hashes":{"sha256":"QvWo2OZufVTMUkPcYQinGVeeHEODWY6RUMaHRxdT31Y"},"origin":"localhost","origin_server_ts":0,"prev_events":[["$QAhQsLNIMdumtpOi:localhost",{"sha256":"RqoKwu8u8qL+wDoka23xvd7t9UoOXLRQse/bK3o9qLE"}]],"prev_state":[],"room_id":"!roomid:localhost","sender":"@userid:localhost","signatures":{"localhost":{"ed25519:auto":"0oPZsvPkbNNVwRrLAP+fEyxFRAIUh0Zn7NPH3LybNC8lMz0GyPtN1bKlTVQYMwZBTXCV795s+CEgoIX+M5gkAQ"}},"state_key":"","type":"m.room.power_levels"}`
	event, err := newEventFromTrustedJSONV1([]byte(eventJSON), false, MustGetRoomVersion(RoomVersionV1))
	if err != nil {
		t.Fatal(err)
	}
	got, err := event.PowerLevels()
	if err != nil {
		t.Fatal(err)
	}
	var want PowerLevelContent
	want.Defaults()
	if !reflect.DeepEqual(*got, want) {
		t.Errorf("power levels: got %+v want %+v", got, want)
	}
}

func TestHeaderedEventToNewEventFromUntrustedJSON(t *testing.T) {
	eventJSON := `{"auth_events":[["$BqcTUuCsN3g6Rj1z:localhost",{"sha256":"QHTrdwE/XVTmAWlxFwHPW7fp3JioRu6OBBRs+FI/at8"}],["$9fmIxbx4IX8w1JVo:localhost",{"sha256":"gee+f1VoNeYGGczs5lwnUO1qeKAh70Hw23ws+YfDYGY"}]],"content":{"ban":50,"events":null,"events_default":0,"invite":0,"kick":50,"redact":50,"state_default":50,"users":null,"users_default":0},"depth":4,"event_id":"$1570trwyGMovM5uU:localhost","hashes":{"sha256":"QvWo2OZufVTMUkPcYQinGVeeHEODWY6RUMaHRxdT31Y"},"origin":"localhost","origin_server_ts":0,"prev_events":[["$QAhQsLNIMdumtpOi:localhost",{"sha256":"RqoKwu8u8qL+wDoka23xvd7t9UoOXLRQse/bK3o9qLE"}]],"prev_state":[],"room_id":"!roomid:localhost","sender":"@userid:localhost","signatures":{"localhost":{"ed25519:auto":"0oPZsvPkbNNVwRrLAP+fEyxFRAIUh0Zn7NPH3LybNC8lMz0GyPtN1bKlTVQYMwZBTXCV795s+CEgoIX+M5gkAQ"}},"state_key":"","type":"m.room.power_levels"}`
	event, err := newEventFromTrustedJSONV1([]byte(eventJSON), false, MustGetRoomVersion(RoomVersionV1))
	if err != nil {
		t.Fatal(err)
	}
	j, err := event.ToHeaderedJSON()
	if err != nil {
		t.Fatal(err)
	}
	_, err = newEventFromUntrustedJSONV1(j, MustGetRoomVersion(RoomVersionV1))
	if err == nil {
		t.Fatal("expected an error but got none:")
	}
}

func TestEventBuilderBuildsEvent(t *testing.T) {
	sender := "@sender:id"
	builder := MustGetRoomVersion(RoomVersionV10).NewEventBuilderFromProtoEvent(&ProtoEvent{
		SenderID: sender,
		RoomID:   "!room:id",
		Type:     "m.room.member",
		StateKey: &sender,
	})

	err := builder.SetContent(newMemberContent("join", nil))
	if err != nil {
		t.Fatal(err)
	}

	eventStruct, err := builder.Build(time.Now(), "origin", "ed25519:test", privateKey1)
	if err != nil {
		t.Fatal(err)
	}

	expectedEvent := eventV2{eventV1: eventV1{redacted: false, roomVersion: RoomVersionV10}}
	if eventStruct.Redacted() != expectedEvent.redacted {
		t.Fatal("Event Redacted state doesn't match")
	}
	if eventStruct.Version() != expectedEvent.roomVersion {
		t.Fatal("Event Room Version doesn't match")
	}
	if eventStruct.Type() != "m.room.member" {
		t.Fatal("Event Type doesn't match")
	}
	if eventStruct.SenderID() != spec.SenderID(sender) {
		t.Fatal("Event Sender doesn't match")
	}
	if *eventStruct.StateKey() != sender {
		t.Fatal("Event State Key doesn't match")
	}
}

func TestEventBuilderBuildsEventWithAuth(t *testing.T) {
	sender := "@sender:id"
	builder := MustGetRoomVersion(RoomVersionV10).NewEventBuilderFromProtoEvent(&ProtoEvent{
		SenderID: sender,
		RoomID:   "!room:id",
		Type:     "m.room.create",
		StateKey: &sender,
	})

	provider := &authProvider{valid: true}
	content, err := NewCreateContentFromAuthEvents(provider, UserIDForSenderTest)
	if err != nil {
		t.Fatal(err)
	}

	err = builder.SetContent(content)
	if err != nil {
		t.Fatal(err)
	}
	if err = builder.AddAuthEvents(provider); err != nil {
		t.Fatal(err)
	}

	eventStruct, err := builder.Build(time.Now(), "origin", "ed25519:test", privateKey1)
	if err != nil {
		t.Fatal(err)
	}

	expectedEvent := eventV2{eventV1: eventV1{redacted: false, roomVersion: RoomVersionV10}}
	if eventStruct.Redacted() != expectedEvent.redacted {
		t.Fatal("Event Redacted state doesn't match")
	}
	if eventStruct.Version() != expectedEvent.roomVersion {
		t.Fatal("Event Room Version doesn't match")
	}
	if eventStruct.Type() != "m.room.create" {
		t.Fatal("Event Type doesn't match")
	}
	if eventStruct.SenderID() != spec.SenderID(sender) {
		t.Fatal("Event Sender doesn't match")
	}
	if *eventStruct.StateKey() != sender {
		t.Fatal("Event State Key doesn't match")
	}
}

func TestEventBuilderBuildsEventWithAuthError(t *testing.T) {
	sender := "@sender3:id"
	builder := MustGetRoomVersion(RoomVersionV10).NewEventBuilderFromProtoEvent(&ProtoEvent{
		SenderID: sender,
		RoomID:   "!room:id",
		Type:     "m.room.member",
		StateKey: &sender,
	})

	err := builder.SetContent(newMemberContent("join", nil))
	if err != nil {
		t.Fatal(err)
	}

	provider := &authProvider{valid: true, fail: true}
	if err = builder.AddAuthEvents(provider); err == nil {
		t.Fatal("Building didn't fail")
	}
	println(err.Error())
}

type authProvider struct {
	valid bool
	fail  bool
}

func (a *authProvider) Valid() bool {
	return a.valid
}

func (a *authProvider) Create() (PDU, error) {
	const validEventJSON = `{
        "auth_events":[
            "$urlsafe_base64_encoded_eventid"
        ],
        "content":{
            "creator":"@neilalexander:dendrite.matrix.org",
                "room_version":"PowerDAG"
        },
        "depth":1,
        "hashes":{
            "sha256":"jqOqdNEH5r0NiN3xJtj0u5XUVmRqq9YvGbki1wxxuuM"
        },
        "origin_server_ts":1644595362726,
        "prev_events":[
            "$other_base64_encoded_eventid"
        ],
        "room_id":"!jSZZRknA6GkTBXNP:dendrite.matrix.org",
        "sender":"@neilalexander:dendrite.matrix.org",
        "signatures":{
            "dendrite.matrix.org":{
                "ed25519:6jB2aB":"bsQXO1wketf1OSe9xlndDIWe71W9KIundc6rBw4KEZdGPW7x4Tv4zDWWvbxDsG64sS2IPWfIm+J0OOozbrWIDw"
            }
        },
        "state_key":"",
        "type":"m.room.create"
    }`
	event, _ := newEventFromTrustedJSONV2([]byte(validEventJSON), false, MustGetRoomVersion(RoomVersionV10))

	var err error
	if a.fail {
		err = errors.New("Failed")
	}
	return event, err
}

func (a *authProvider) PowerLevels() (PDU, error) {
	return &eventV2{}, nil
}

func (a *authProvider) JoinRules() (PDU, error) {
	return &eventV2{}, nil
}

func (a *authProvider) Member(stateKey spec.SenderID) (PDU, error) {
	return &eventV2{}, nil
}

func (a *authProvider) ThirdPartyInvite(stateKey string) (PDU, error) {
	return &eventV2{}, nil
}
