package bgpls

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKeepaliveMessage(t *testing.T) {
	k := &keepAliveMessage{}

	b, err := k.serialize()
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

	f, ok := m[0].(*keepAliveMessage)
	if !ok {
		t.Error("not a keep alive message")
	}

	assert.Equal(t, f.MessageType(), KeepAliveMessageType)
}
