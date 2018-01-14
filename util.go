package bgpls

import (
	"errors"
	"net"
)

func bytesToIPAddress(b []byte) (net.IP, error) {
	l := len(b)
	if l != 4 && l != 16 {
		return nil, errors.New("invalid byte length")
	}

	var addr net.IP
	for i := 0; i < l; i++ {
		addr = append(addr, b[i])
	}

	return addr, nil
}

func reverseByteOrder(b []byte) []byte {
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}

	return b
}
