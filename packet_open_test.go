package bgpls

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestOpenMessage(t *testing.T) {
	asn := uint16(64512)
	holdTime := time.Second * 30
	bgpID := net.ParseIP("172.16.0.1")

	o, err := newOpenMessage(uint32(asn), holdTime, bgpID)
	if err != nil {
		t.Error(err)
	}

	b, err := o.serialize()
	if err != nil {
		t.Error(err)
	}

	m, err := messagesFromBytes(b)
	if err != nil {
		t.Error(err)
	}

	if len(m) != 1 {
		t.Errorf("invalid number of messages deserialized: %d", len(m))
	}

	f, ok := m[0].(*openMessage)
	if !ok {
		t.Error("not an open message")
	}

	assert.Equal(t, asn, f.asn)
	assert.Equal(t, uint16(holdTime/time.Second), f.holdTime)
	assert.Equal(t, binary.BigEndian.Uint32(bgpID[12:16]), f.bgpID)
	assert.Equal(t, f.MessageType(), OpenMessageType)
	assert.Equal(t, len(o.optParams), len(f.optParams))
	assert.Equal(t, f.version, uint8(4))
}
