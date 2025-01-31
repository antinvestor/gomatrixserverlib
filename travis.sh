#!/bin/sh

set -eux

cd `dirname $0`

# -u so that if this is run on a dev box, we get the latest deps, as
# we do on travis.

go get -u \
   github.com/client9/misspell/cmd/misspell \
   golang.org/x/crypto/ed25519 \
   github.com/pitabwire/util \
   github.com/antinvestor/gomatrix \
   github.com/tidwall/gjson \
   github.com/tidwall/sjson \
   github.com/pkg/errors \
   gopkg.in/yaml.v2 \
   gopkg.in/macaroon.v2 \

./hooks/pre-commit
