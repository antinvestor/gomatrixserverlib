package spec

import (
	"net"
	"strconv"
	"strings"
)

// A ServerName is the name a matrix homeserver is identified by.
// It is a DNS name or IP address optionally followed by a port.
//
// https://matrix.org/docs/spec/appendices.html#server-name
type ServerName string

// ParseAndValidateServerName splits a ServerName into a host and port part,
// and checks that it is a valid server name according to the spec.
//
// if there is no explicit port, returns '-1' as the port.
func ParseAndValidateServerName(serverName ServerName) (host string, port int, valid bool) {
	// Don't go any further if the server name is an empty string.
	if len(serverName) == 0 {
		return host, port, valid
	}

	host, port = splitServerName(serverName)

	// the host part must be one of:
	//  - a valid (ascii) dns name
	//  - an IPv4 address
	//  - an IPv6 address

	if len(host) == 0 {
		return host, port, valid
	}

	if host[0] == '[' {
		// must be a valid IPv6 address
		if host[len(host)-1] != ']' {
			return host, port, valid
		}
		ip := host[1 : len(host)-1]
		if net.ParseIP(ip) == nil {
			return host, port, valid
		}
		valid = true
		return host, port, valid
	}

	// try parsing as an IPv4 address
	ip := net.ParseIP(host)
	if ip != nil && ip.To4() != nil {
		valid = true
		return host, port, valid
	}

	// must be a valid DNS Name
	for _, r := range host {
		if !isDNSNameChar(r) {
			return host, port, valid
		}
	}

	valid = true
	return host, port, valid
}

func isDNSNameChar(r rune) bool {
	if r >= 'A' && r <= 'Z' {
		return true
	}
	if r >= 'a' && r <= 'z' {
		return true
	}
	if r >= '0' && r <= '9' {
		return true
	}
	if r == '-' || r == '.' {
		return true
	}
	return false
}

// if there is no explicit port, returns '-1' as the port.
func splitServerName(serverName ServerName) (string, int) {
	nameStr := string(serverName)

	lastColon := strings.LastIndex(nameStr, ":")
	if lastColon < 0 {
		// no colon: no port
		return nameStr, -1
	}

	portStr := nameStr[lastColon+1:]
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		// invalid port (possibly an ipv6 host)
		return nameStr, -1
	}

	return nameStr[:lastColon], int(port)
}
