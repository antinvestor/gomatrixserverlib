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
	"encoding/json"
	"errors"
	"fmt"

	"github.com/antinvestor/gomatrixserverlib/spec"
	"github.com/tidwall/sjson"
	"golang.org/x/crypto/ed25519"
)

// A KeyID is the ID of a ed25519 key used to sign JSON.
// The key IDs have a format of "ed25519:[0-9A-Za-z]+"
// If we switch to using a different signing algorithm then we will change the
// prefix used.
type KeyID string

// SignJSON signs a JSON object returning a copy signed with the given key.
// https://matrix.org/docs/spec/server_server/unstable.html#signing-json
func SignJSON(
	signingName string,
	keyID KeyID,
	privateKey ed25519.PrivateKey,
	message []byte,
) (signed []byte, err error) {
	preserve := struct {
		Signatures map[string]map[KeyID]spec.Base64Bytes `json:"signatures"`
		Unsigned   json.RawMessage                       `json:"unsigned"`
	}{
		Signatures: map[string]map[KeyID]spec.Base64Bytes{},
	}
	if err = json.Unmarshal(message, &preserve); err != nil {
		return nil, err
	}
	if message, err = sjson.DeleteBytes(message, "signatures"); err != nil {
		return nil, err
	}
	if message, err = sjson.DeleteBytes(message, "unsigned"); err != nil {
		return nil, err
	}
	canonical, err := CanonicalJSON(message)
	if err != nil {
		return nil, err
	}
	signature := spec.Base64Bytes(ed25519.Sign(privateKey, canonical))
	if _, ok := preserve.Signatures[signingName]; ok {
		preserve.Signatures[signingName][keyID] = signature
	} else {
		preserve.Signatures[signingName] = map[KeyID]spec.Base64Bytes{
			keyID: signature,
		}
	}
	signatures, err := json.Marshal(preserve.Signatures)
	if err != nil {
		return nil, err
	}
	if signed, err = sjson.SetRawBytes(canonical, "signatures", signatures); err != nil {
		return nil, err
	}
	if len(preserve.Unsigned) > 0 {
		if signed, err = sjson.SetRawBytes(signed, "unsigned", preserve.Unsigned); err != nil {
			return nil, err
		}
	}
	if signed, err = CanonicalJSON(signed); err != nil {
		return nil, err
	}
	return signed, err
}

// ListKeyIDs lists the key IDs a given entity has signed a message with.
func ListKeyIDs(signingName string, message []byte) ([]KeyID, error) {
	var object struct {
		Signatures map[string]map[KeyID]json.RawMessage `json:"signatures"`
	}
	if err := json.Unmarshal(message, &object); err != nil {
		return nil, err
	}
	var result []KeyID
	for keyID := range object.Signatures[signingName] {
		result = append(result, keyID)
	}
	return result, nil
}

// VerifyJSON checks that the entity has signed the message using a particular key.
func VerifyJSON(signingName string, keyID KeyID, publicKey ed25519.PublicKey, message []byte) error {
	// Unpack the top-level key of the JSON object without unpacking the contents of the keys.
	// This allows us to add and remove the top-level keys from the JSON object.
	// It also ensures that the JSON is actually a valid JSON object.
	var object map[string]*json.RawMessage
	var signatures map[string]map[KeyID]spec.Base64Bytes
	if err := json.Unmarshal(message, &object); err != nil {
		return err
	}

	// Check that there is a signature from the entity that we are expecting a signature from.
	if object["signatures"] == nil {
		return errors.New("no signatures")
	}
	if err := json.Unmarshal(*object["signatures"], &signatures); err != nil {
		return err
	}
	signature, ok := signatures[signingName][keyID]
	if !ok {
		return fmt.Errorf("no signature from %q with ID %q", signingName, keyID)
	}
	if len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("bad signature length from %q with ID %q", signingName, keyID)
	}

	// The "unsigned" key and "signatures" keys aren't covered by the signature so remove them.
	delete(object, "unsigned")
	delete(object, "signatures")

	// Encode the JSON without the "unsigned" and "signatures" keys in the canonical format.
	unsorted, err := json.Marshal(object)
	if err != nil {
		return err
	}
	canonical, err := CanonicalJSON(unsorted)
	if err != nil {
		return err
	}

	// Verify the ed25519 signature.
	if !ed25519.Verify(publicKey, canonical, signature) {
		return fmt.Errorf("bad signature from %q with ID %q", signingName, keyID)
	}

	return nil
}
