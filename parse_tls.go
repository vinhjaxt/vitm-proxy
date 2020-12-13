package main

// https://github.com/ge0rg/tls-hello-dump/blob/master/tls-hello-dump.c
const TLS_HANDSHAKE = 0x16
const SSL_MIN_GOOD_VERSION = 0x002
const SSL_MAX_GOOD_VERSION = 0x304 // let's be optimistic here!
const TLS_CLIENT_HELLO = 1
const OFFSET_HELLO_VERSION = 9
const OFFSET_SESSION_LENGTH = 43

func ParseTLSHelloPhrase(payload []byte) (finished, isTLS bool, tlsSNI string, tlsVer uint32) {
	payloadLen := uint32(len(payload))
	if payloadLen < 11 {
		// Not enough
		// prevent DPI technique
		finished = false
		return
	}
	if payload[0] != 0x16 {
		// Not a TLS handshake
		finished = true
		return
	}
	protoVersion := uint32(payload[1])*256 + uint32(payload[2])
	helloVersion := uint32(payload[OFFSET_HELLO_VERSION])*256 + uint32(payload[OFFSET_HELLO_VERSION+1])
	if protoVersion < SSL_MIN_GOOD_VERSION || protoVersion >= SSL_MAX_GOOD_VERSION ||
		helloVersion < SSL_MIN_GOOD_VERSION || helloVersion >= SSL_MAX_GOOD_VERSION {
		// Bad version
		finished = true
		return
	}

	expectPayloadLen := uint32(payload[6])*256*256 + uint32(payload[7])*256 + uint32(payload[8]) + 9
	if payloadLen < expectPayloadLen {
		// Wait for whole phrase sent
		finished = false
		return
	}

	if payloadLen <= OFFSET_SESSION_LENGTH {
		// Bad packet
		finished = true
		return
	}
	sessionIDLen := payload[OFFSET_SESSION_LENGTH]

	offsetCipherSuite := uint32(sessionIDLen + OFFSET_SESSION_LENGTH + 1)

	if payloadLen <= offsetCipherSuite+1 {
		// Bad packet
		finished = true
		return
	}
	cipherSuiteLen := uint32(payload[offsetCipherSuite])*256 + uint32(payload[offsetCipherSuite+1])

	offsetCompressMethodLen := offsetCipherSuite + cipherSuiteLen + 2

	if payloadLen <= offsetCompressMethodLen {
		// Bad packet
		finished = true
		return
	}
	compressMethodLen := uint32(payload[offsetCompressMethodLen])
	offsetExtensionLen := compressMethodLen + offsetCompressMethodLen + 1
	isTLS = true
	tlsVer = helloVersion

	// extensionLen := uint32(payload[offsetExtensionLen])*256 + uint32(payload[offsetExtensionLen+1])

	if payloadLen < offsetExtensionLen+2 {
		// Bad packet
		finished = true
		return
	}
	nextExtension := payload[offsetExtensionLen+2:]
	for {
		// loop over extensions
		nextExtensionLen := uint32(len(nextExtension))
		if nextExtensionLen < 4 {
			break
		}
		etype := uint32(nextExtension[0])*256 + uint32(nextExtension[1])
		elen := uint32(nextExtension[2])*256 + uint32(nextExtension[3])
		ende := elen + 4
		if etype == 0x00 {
			// SNIs
			if nextExtensionLen < 6 {
				break
			}
			nextSNI := nextExtension[6:ende] // 6 = 4 (etype + elen) + 2 (server name list length)
			for {
				// loop over sni
				nextSNILen := uint32(len(nextSNI))
				if nextSNILen < 3 {
					break
				}
				stype := uint32(nextSNI[0])
				slen := uint32(nextSNI[1])*256 + uint32(nextSNI[2])
				ends := slen + 3
				if stype == 0x00 {
					// Hostname
					tlsSNI = string(nextSNI[3:ends])
					finished = true
					return
				}
				if nextSNILen <= ends {
					finished = true
					return
				}
				nextSNI = nextSNI[ends:]
			}
		}
		if nextExtensionLen <= ende {
			finished = true
			return
		}
		nextExtension = nextExtension[ende:]
	}
	finished = true
	return
}
