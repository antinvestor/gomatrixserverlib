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

package fclient

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"

	"github.com/antinvestor/gomatrixserverlib/spec"
)

// ResolutionResult is a result of looking up a Matrix homeserver according to
// the federation specification.
type ResolutionResult struct {
	Destination   string          // The hostname and port to send federation requests to.
	Host          spec.ServerName // The value of the Host headers.
	TLSServerName string          // The TLS server name to request a certificate for.
}

// ResolveServer implements the server name resolution algorithm described at
// https://matrix.org/docs/spec/server_server/r0.1.1.html#resolving-server-names
// Returns a slice of ResolutionResult that can be used to send a federation
// request to the server using a given server name.
// Returns an error if the server name isn't valid.
func ResolveServer(ctx context.Context, serverName spec.ServerName) (results []ResolutionResult, err error) {
	return resolveServer(ctx, serverName, true)
}

// resolveServer does the same thing as ResolveServer, except it also requires
// the checkWellKnown parameter, which indicates whether a .well-known file
// should be looked up.
func resolveServer(
	ctx context.Context,
	serverName spec.ServerName,
	checkWellKnown bool,
) (results []ResolutionResult, err error) {
	host, port, valid := spec.ParseAndValidateServerName(serverName)
	if !valid {
		err = errors.New("invalid server name")
		return results, err
	}

	// 1. If the hostname is an IP literal
	// Check if we're dealing with an IPv6 literal with square brackets. If so,
	// remove the brackets.
	if host[0] == '[' && host[len(host)-1] == ']' {
		host = host[1 : len(host)-1]
	}
	if net.ParseIP(host) != nil {
		var destination string

		if port == -1 {
			destination = net.JoinHostPort(host, strconv.Itoa(8448))
		} else {
			destination = string(serverName)
		}

		results = []ResolutionResult{
			{
				Destination:   destination,
				Host:          serverName,
				TLSServerName: host,
			},
		}

		return results, err
	}

	// 2. If the hostname is not an IP literal, and the server name includes an
	// explicit port
	if port != -1 {
		results = []ResolutionResult{
			{
				Destination:   string(serverName),
				Host:          serverName,
				TLSServerName: host,
			},
		}

		return results, err
	}

	if checkWellKnown {
		// 3. If the hostname is not an IP literal
		var result *WellKnownResult
		result, err = LookupWellKnown(ctx, serverName)
		if err == nil {
			// We don't want to check .well-known on the result
			return resolveServer(ctx, result.NewAddress, false)
		}
	}

	return handleNoWellKnown(ctx, serverName), nil
}

// well as 3.3 and 3.4).
func handleNoWellKnown(ctx context.Context, serverName spec.ServerName) (results []ResolutionResult) {
	// 4. If the /.well-known request resulted in an error response
	records, err := lookupSRV(ctx, serverName)
	if err == nil && len(records) > 0 {
		for _, rec := range records {
			// If the domain is a FQDN, remove the trailing dot at the end. This
			// isn't critical to send the request, as Go's HTTP client and most
			// servers understand FQDNs quite well, but it makes automated
			// testing easier.
			target := rec.Target
			if target[len(target)-1] == '.' {
				target = target[:len(target)-1]
			}

			results = append(results, ResolutionResult{
				Destination:   fmt.Sprintf("%s:%d", target, rec.Port),
				Host:          serverName,
				TLSServerName: string(serverName),
			})
		}

		return results
	}

	// 5. If the /.well-known request returned an error response, and the SRV
	// record was not found
	results = []ResolutionResult{
		{
			Destination:   fmt.Sprintf("%s:%d", serverName, 8448),
			Host:          serverName,
			TLSServerName: string(serverName),
		},
	}

	return results
}

func lookupSRV(ctx context.Context, serverName spec.ServerName) ([]*net.SRV, error) {
	// Check matrix-fed service first, as of Matrix 1.8
	_, records, err := net.DefaultResolver.LookupSRV(ctx, "matrix-fed", "tcp", string(serverName))
	if err != nil {
		if dnserr, ok := err.(*net.DNSError); ok {
			if !dnserr.IsNotFound {
				// not found errors are expected, but everything else is very much not
				return records, err
			}
		} else {
			return records, err
		}
	} else {
		return records, nil // we got a hit on the matrix-fed service, so use that
	}

	// we didn't get a hit on matrix-fed, so try deprecated matrix service
	_, records, err = net.DefaultResolver.LookupSRV(ctx, "matrix", "tcp", string(serverName))
	return records, err // we don't need to process this here
}
