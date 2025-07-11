package gomatrixserverlib

import (
	"encoding/json"
)

// For satisfying "Upon receipt of a redaction event, the server must strip off any keys not in the following list:".
type unredactableEventFieldsV1 struct {
	EventID        json.RawMessage        `json:"event_id,omitempty"`
	Type           string                 `json:"type"`
	RoomID         json.RawMessage        `json:"room_id,omitempty"`
	Sender         json.RawMessage        `json:"sender,omitempty"`
	StateKey       json.RawMessage        `json:"state_key,omitempty"`
	Content        map[string]interface{} `json:"content"`
	Hashes         json.RawMessage        `json:"hashes,omitempty"`
	Signatures     json.RawMessage        `json:"signatures,omitempty"`
	Depth          json.RawMessage        `json:"depth,omitempty"`
	PrevEvents     json.RawMessage        `json:"prev_events,omitempty"`
	PrevState      json.RawMessage        `json:"prev_state,omitempty"`
	AuthEvents     json.RawMessage        `json:"auth_events,omitempty"`
	Origin         json.RawMessage        `json:"origin,omitempty"`
	OriginServerTS json.RawMessage        `json:"origin_server_ts,omitempty"`
	Membership     json.RawMessage        `json:"membership,omitempty"`
}

func (u *unredactableEventFieldsV1) GetType() string {
	return u.Type
}

func (u *unredactableEventFieldsV1) GetContent() map[string]interface{} {
	return u.Content
}

func (u *unredactableEventFieldsV1) SetContent(content map[string]interface{}) {
	u.Content = content
}

// For satisfying "Upon receipt of a redaction event, the server must strip off any keys not in the following list:".
type unredactableEventFieldsV2 struct {
	EventID        json.RawMessage        `json:"event_id,omitempty"`
	Type           string                 `json:"type"`
	RoomID         json.RawMessage        `json:"room_id,omitempty"`
	Sender         json.RawMessage        `json:"sender,omitempty"`
	StateKey       json.RawMessage        `json:"state_key,omitempty"`
	Content        map[string]interface{} `json:"content"`
	Hashes         json.RawMessage        `json:"hashes,omitempty"`
	Signatures     json.RawMessage        `json:"signatures,omitempty"`
	Depth          json.RawMessage        `json:"depth,omitempty"`
	PrevEvents     json.RawMessage        `json:"prev_events,omitempty"`
	AuthEvents     json.RawMessage        `json:"auth_events,omitempty"`
	OriginServerTS json.RawMessage        `json:"origin_server_ts,omitempty"`
}

func (u *unredactableEventFieldsV2) GetType() string {
	return u.Type
}

func (u *unredactableEventFieldsV2) GetContent() map[string]interface{} {
	return u.Content
}

func (u *unredactableEventFieldsV2) SetContent(content map[string]interface{}) {
	u.Content = content
}

// For satisfying "The content object must also be stripped of all keys, unless it is one of one of the following event types:".
var (
	unredactableContentFieldsV1 = map[string][]string{
		"m.room.member":     {"membership"},
		"m.room.create":     {"creator"},
		"m.room.join_rules": {"join_rule"},
		"m.room.power_levels": {
			"ban",
			"events",
			"events_default",
			"kick",
			"redact",
			"state_default",
			"users",
			"users_default",
		},
		"m.room.aliases":            {"aliases"},
		"m.room.history_visibility": {"history_visibility"},
	}
	unredactableContentFieldsV2 = map[string][]string{
		"m.room.member":     {"membership"},
		"m.room.create":     {"creator"},
		"m.room.join_rules": {"join_rule"},
		"m.room.power_levels": {
			"ban",
			"events",
			"events_default",
			"kick",
			"redact",
			"state_default",
			"users",
			"users_default",
		},
		"m.room.history_visibility": {"history_visibility"},
	}
	unredactableContentFieldsV3 = map[string][]string{
		"m.room.member":     {"membership"},
		"m.room.create":     {"creator"},
		"m.room.join_rules": {"join_rule", "allow"},
		"m.room.power_levels": {
			"ban",
			"events",
			"events_default",
			"kick",
			"redact",
			"state_default",
			"users",
			"users_default",
		},
		"m.room.history_visibility": {"history_visibility"},
	}
	unredactableContentFieldsV4 = map[string][]string{
		"m.room.member":     {"membership", "join_authorised_via_users_server"},
		"m.room.create":     {"creator"},
		"m.room.join_rules": {"join_rule", "allow"},
		"m.room.power_levels": {
			"ban",
			"events",
			"events_default",
			"kick",
			"redact",
			"state_default",
			"users",
			"users_default",
		},
		"m.room.history_visibility": {"history_visibility"},
	}
	unredactableContentFieldsV5 = map[string][]string{
		"m.room.member":     {"membership", "join_authorised_via_users_server"},
		"m.room.create":     {}, // NOTE: Keep all fields
		"m.room.join_rules": {"join_rule", "allow"},
		"m.room.power_levels": {
			"ban",
			"events",
			"events_default",
			"kick",
			"redact",
			"state_default",
			"users",
			"users_default",
			"invite",
		},
		"m.room.history_visibility": {"history_visibility"},
		"m.room.redaction":          {"redacts"},
	}
)

// which protects membership 'join_authorised_via_users_server' key.
func redactEventJSONV5(eventJSON []byte) ([]byte, error) {
	return redactEventJSON(eventJSON, &unredactableEventFieldsV2{}, unredactableContentFieldsV5)
}

// which protects membership 'join_authorised_via_users_server' key.
func redactEventJSONV4(eventJSON []byte) ([]byte, error) {
	return redactEventJSON(eventJSON, &unredactableEventFieldsV1{}, unredactableContentFieldsV4)
}

// which protects join rules 'allow' key.
func redactEventJSONV3(eventJSON []byte) ([]byte, error) {
	return redactEventJSON(eventJSON, &unredactableEventFieldsV1{}, unredactableContentFieldsV3)
}

// which has no special meaning for m.room.aliases.
func redactEventJSONV2(eventJSON []byte) ([]byte, error) {
	return redactEventJSON(eventJSON, &unredactableEventFieldsV1{}, unredactableContentFieldsV2)
}

// RedactEvent strips the user controlled fields from an event, but leaves the
// fields necessary for authenticating the event. Implements https://spec.matrix.org/unstable/rooms/v1/#redactions
func redactEventJSONV1(eventJSON []byte) ([]byte, error) {
	return redactEventJSON(eventJSON, &unredactableEventFieldsV1{}, unredactableContentFieldsV1)
}

type unredactableEvent interface {
	*unredactableEventFieldsV1 | *unredactableEventFieldsV2
	GetType() string
	GetContent() map[string]interface{}
	SetContent(map[string]interface{})
}

func redactEventJSON[T unredactableEvent](
	eventJSON []byte,
	unredactableEvent T,
	eventTypeToKeepContentFields map[string][]string,
) ([]byte, error) {
	// Unmarshalling into a struct will discard any extra fields from the event.
	if err := json.Unmarshal(eventJSON, &unredactableEvent); err != nil {
		return nil, err
	}
	newContent := map[string]interface{}{}
	keepContentFields, ok := eventTypeToKeepContentFields[unredactableEvent.GetType()]
	if ok && len(keepContentFields) == 0 {
		// An unredactable content entry with no provided fields should keep all fields.
		newContent = unredactableEvent.GetContent()
	} else {
		for _, contentKey := range keepContentFields {
			val, ok := unredactableEvent.GetContent()[contentKey]
			if ok {
				newContent[contentKey] = val
			}
		}
	}

	// Replace the content with our new filtered content.
	// This will zero out any keys that weren't copied in the loop above.
	unredactableEvent.SetContent(newContent)
	// Return the redacted event encoded as JSON.
	return json.Marshal(&unredactableEvent)
}
