package main

import (
	"net"
	"strings"
	"unsafe"
)

// b2s converts byte slice to a string without memory allocation.
// See https://groups.google.com/forum/#!msg/Golang-Nuts/ENgbUzYvCuU/90yGx7GUAgAJ .
//
// Note it may break if string and/or slice header will change
// in the future go versions.
func b2s(b []byte) string {
	/* #nosec G103 */
	return *(*string)(unsafe.Pointer(&b))
}

func splitHostnameDefaultPort(addr, defaultPort string) (string, string, error) {
	// no suitable address found => ipv6 can not dial to ipv4,..
	hostname, port, err := net.SplitHostPort(addr)
	if err != nil {
		if err1, ok := err.(*net.AddrError); ok && strings.Index(err1.Err, "missing port") != -1 {
			hostname, port, err = net.SplitHostPort(strings.TrimRight(addr, ":") + ":" + defaultPort)
		}
		if err != nil {
			return "", "", err
		}
	}
	if len(port) == 0 {
		port = defaultPort
	}
	return hostname, port, nil
}
