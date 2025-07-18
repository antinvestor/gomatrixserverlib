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

package gomatrixserverlib

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/tidwall/gjson"
)

type EventJSONs []json.RawMessage

func (e EventJSONs) TrustedEvents(roomVersion RoomVersion, redacted bool) []PDU {
	verImpl, err := GetRoomVersion(roomVersion)
	if err != nil {
		return nil
	}
	events := make([]PDU, 0, len(e))
	for _, js := range e {
		event, err := verImpl.NewEventFromTrustedJSON(js, redacted)
		if err != nil {
			continue
		}
		events = append(events, event)
	}
	return events
}

func (e EventJSONs) UntrustedEvents(roomVersion RoomVersion) []PDU {
	verImpl, err := GetRoomVersion(roomVersion)
	if err != nil {
		return nil
	}
	events := make([]PDU, 0, len(e))
	for _, js := range e {
		event, err := verImpl.NewEventFromUntrustedJSON(js)
		switch e := err.(type) {
		case EventValidationError:
			if !e.Persistable {
				continue
			}
		case nil:
		default:
			continue
		}
		events = append(events, event)
	}
	return events
}

func NewEventJSONsFromEvents(he []PDU) EventJSONs {
	events := make(EventJSONs, len(he))
	for i := range he {
		events[i] = he[i].JSON()
	}
	return events
}

// CanonicalJSON re-encodes the JSON in a canonical encoding. The encoding is
// the shortest possible encoding using integer values with sorted object keys.
// At present this function performs:
//   - shortest encoding, sorted lexicographically by UTF-8 codepoint:
//     https://matrix.org/docs/spec/appendices#canonical-json
//
// Returns a gomatrixserverlib.BadJSONError if JSON validation fails.
func CanonicalJSON(input []byte) ([]byte, error) {
	if !gjson.Valid(string(input)) {
		return nil, BadJSONError{errors.New("gjson validation failed")}
	}

	return CanonicalJSONAssumeValid(input), nil
}

// Returns a gomatrixserverlib.BadJSONError if the canonical JSON fails enforced
// checks or if JSON validation fails. At present this function performs:
//   - integer bounds checking for room version 6 and above:
//     https://matrix.org/docs/spec/rooms/v6#canonical-json
//   - shortest encoding, sorted lexicographically by UTF-8 codepoint:
//     https://matrix.org/docs/spec/appendices#canonical-json
//
// Returns a gomatrixserverlib.BadJSONError if JSON validation fails.
func EnforcedCanonicalJSON(input []byte, roomVersion RoomVersion) ([]byte, error) {
	roomVersionImpl, err := GetRoomVersion(roomVersion)
	if err != nil {
		return nil, err
	}
	if err := roomVersionImpl.CheckCanonicalJSON(input); err != nil {
		return nil, BadJSONError{err}
	}

	return CanonicalJSON(input)
}

var ErrCanonicalJSON = errors.New("value is outside of safe range")

func noVerifyCanonicalJSON(input []byte) error { return nil }

func verifyEnforcedCanonicalJSON(input []byte) error {
	valid := true
	res := gjson.ParseBytes(input)
	var iter func(key, value gjson.Result) bool
	iter = func(_, value gjson.Result) bool {
		if value.IsArray() || value.IsObject() {
			value.ForEach(iter)
			return true
		}
		if value.Num < -9007199254740991 || value.Num > 9007199254740991 {
			valid = false
			return false
		}
		if value.Num != 0 && strings.ContainsRune(value.Raw, '.') {
			valid = false
			return false
		}
		if value.Num != 0 && strings.ContainsRune(value.Raw, 'e') {
			valid = false
			return false
		}
		if value.Num == 0 && value.Raw == "-0" {
			valid = false
			return false
		}
		return true
	}
	res.ForEach(iter)
	if !valid {
		return ErrCanonicalJSON
	}
	return nil
}

// input is valid JSON.
func CanonicalJSONAssumeValid(input []byte) []byte {
	input = CompactJSON(input, make([]byte, 0, len(input)))
	return SortJSON(input, make([]byte, 0, len(input)))
}

// SortJSON reencodes the JSON with the object keys sorted by lexicographically
// by codepoint. The input must be valid JSON.
func SortJSON(input, output []byte) []byte {
	result := gjson.ParseBytes(input)
	return sortJSONValue(result, output)
}

// sortJSONValue takes a gjson.Result and sorts it. inputJSON must be the
// raw JSON bytes that gjson.Result points to.
func sortJSONValue(input gjson.Result, output []byte) []byte {
	if input.IsArray() {
		return sortJSONArray(input, output)
	}
	if input.IsObject() {
		return sortJSONObject(input, output)
	}
	// If its neither an object nor an array then there is no sub structure
	// to sort, so just append the raw bytes.
	return append(output, input.Raw...)
}

// sortJSONArray takes a gjson.Result and sorts it, assuming its an array.
// inputJSON must be the raw JSON bytes that gjson.Result points to.
func sortJSONArray(input gjson.Result, output []byte) []byte {
	sep := byte('[')

	// Iterate over each value in the array and sort it.
	input.ForEach(func(_, value gjson.Result) bool {
		output = append(output, sep)
		sep = ','
		output = sortJSONValue(value, output)
		return true // keep iterating
	})

	if sep == '[' {
		// If sep is still '[' then the array was empty and we never wrote the
		// initial '[', so we write it now along with the closing ']'.
		output = append(output, '[', ']')
	} else {
		// Otherwise we end the array by writing a single ']'
		output = append(output, ']')
	}
	return output
}

// sortJSONObject takes a gjson.Result and sorts it, assuming its an object.
// inputJSON must be the raw JSON bytes that gjson.Result points to.
func sortJSONObject(input gjson.Result, output []byte) []byte {
	type entry struct {
		key   string // The parsed key string
		value gjson.Result
	}

	// Try to stay on the stack here if we can.
	var _entries [128]entry
	entries := _entries[:0]

	// Iterate over each key/value pair and add it to a slice
	// that we can sort
	input.ForEach(func(key, value gjson.Result) bool {
		entries = append(entries, entry{
			key:   key.String(),
			value: value,
		})
		return true // keep iterating
	})

	// Using slices.SortFunc here instead of sort.Slice avoids
	// heap escapes due to reflection.
	slices.SortFunc(entries, func(a, b entry) int {
		return strings.Compare(a.key, b.key)
	})

	sep := byte('{')

	for _, entry := range entries {
		output = append(output, sep)
		sep = ','

		// Append the raw unparsed JSON key, *not* the parsed key
		output = append(output, '"')
		output = append(output, entry.key...)
		output = append(output, '"', ':')
		output = sortJSONValue(entry.value, output)
	}
	if sep == '{' {
		// If sep is still '{' then the object was empty and we never wrote the
		// initial '{', so we write it now along with the closing '}'.
		output = append(output, '{', '}')
	} else {
		// Otherwise we end the object by writing a single '}'
		output = append(output, '}')
	}
	return output
}

// whitespace and unneeded unicode escapes.
func CompactJSON(input, output []byte) []byte {
	var i int
	for i < len(input) {
		c := input[i]
		i++
		// The valid whitespace characters are all less than or equal to SPACE 0x20.
		// The valid non-white characters are all greater than SPACE 0x20.
		// So we can check for whitespace by comparing against SPACE 0x20.
		if c <= ' ' {
			// Skip over whitespace.
			continue
		}
		if c == '-' && input[i] == '0' {
			// Negative 0 is changed to '0', skip the '-'.
			continue
		}
		// Add the non-whitespace character to the output.
		output = append(output, c)
		if c == '"' {
			// We are inside a string.
			for i < len(input) {
				c = input[i]
				i++
				// Check if this is an escape sequence.
				if c == '\\' {
					escape := input[i]
					i++
					switch escape {
					case 'u':
						// If this is a unicode escape then we need to handle it specially
						output, i = compactUnicodeEscape(input, output, i)
					case '/':
						// JSON does not require escaping '/', but allows encoders to escape it as a special case.
						// Since the escape isn't required we remove it.
						output = append(output, escape)
					default:
						// All other permitted escapes are single charater escapes that are already in their shortest form.
						output = append(output, '\\', escape)
					}
				} else {
					output = append(output, c)
				}
				if c == '"' {
					break
				}
			}
		}
	}
	return output
}

// compactUnicodeEscape unpacks a 4 byte unicode escape starting at index.
// Returns the output slice and a new input index.
func compactUnicodeEscape(input, output []byte, index int) ([]byte, int) {
	appendUTF8 := func(c rune) {
		var buffer [4]byte
		n := utf8.EncodeRune(buffer[:], c)
		output = append(output, buffer[:n]...)
	}
	const (
		ESCAPES = "uuuuuuuubtnufruuuuuuuuuuuuuuuuuu"
		HEX     = "0123456789abcdef"
	)
	// If there aren't enough bytes to decode the hex escape then return.
	if len(input)-index < 4 {
		return output, len(input)
	}
	// Decode the 4 hex digits.
	c := readHexDigits(input[index : index+4])
	index += 4
	if c < ' ' {
		// If the character is less than SPACE 0x20 then it will need escaping.
		escape := ESCAPES[c]
		output = append(output, '\\', escape)
		if escape == 'u' {
			output = append(output, '0', '0', byte('0'+(c>>4)), HEX[c&0xF])
		}
	} else if c == '\\' || c == '"' {
		// Otherwise the character only needs escaping if it is a QUOTE '"' or BACKSLASH '\\'.
		output = append(output, '\\', byte(c))
	} else if utf16.IsSurrogate(c) {
		if input[index] != '\\' || input[index+1] != 'u' {
			return output, index
		}
		index += 2 // skip the \u"
		if len(input)-index < 4 {
			return output, index
		}
		c2 := readHexDigits(input[index : index+4])
		index += 4
		appendUTF8(utf16.DecodeRune(c, c2))
	} else {
		appendUTF8(c)
	}
	return output, index
}

// Read 4 hex digits from the input slice.
// Taken from https://github.com/NegativeMjark/indolentjson-rust/blob/8b959791fe2656a88f189c5d60d153be05fe3deb/src/readhex.rs#L21
func readHexDigits(input []byte) rune {
	hex := binary.BigEndian.Uint32(input)
	// subtract '0'
	hex -= 0x30303030
	// strip the higher bits, maps 'a' => 'A'
	hex &= 0x1F1F1F1F
	mask := hex & 0x10101010
	// subtract 'A' - 10 - '9' - 9 = 7 from the letters.
	hex -= mask >> 1
	hex += mask >> 4
	// collect the nibbles
	hex |= hex >> 4
	hex &= 0xFF00FF
	hex |= hex >> 8
	return rune(hex & 0xFFFF)
}
