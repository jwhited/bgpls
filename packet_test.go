package bgpls

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMessageTypeString(t *testing.T) {
	assert.Equal(t, OpenMessageType.String(), "open")
	assert.Equal(t, UpdateMessageType.String(), "update")
	assert.Equal(t, NotificationMessageType.String(), "notification")
	assert.Equal(t, KeepAliveMessageType.String(), "keepalive")
}

func TestMessageFromBytes(t *testing.T) {
	k := &keepAliveMessage{}
	b, err := k.serialize()
	if err != nil {
		t.Fatal(err)
	}

	// invalid message header length
	binary.BigEndian.PutUint16(b[16:18], 0)
	_, err = messagesFromBytes(b)
	assert.NotNil(t, err)

	// error on keepalive deserialization
	b = append(b, 0)
	binary.BigEndian.PutUint16(b[16:18], 20)
	_, err = messagesFromBytes(b)
	assert.NotNil(t, err)

	// invalid marker
	b[15] = 0
	_, err = messagesFromBytes(b)
	assert.NotNil(t, err)

	// message < 19 bytes
	b = b[:18]
	_, err = messagesFromBytes(b)
	assert.NotNil(t, err)

	// error on open message deserialization
	o := &openMessage{}
	b, err = o.serialize()
	if err != nil {
		t.Fatal(err)
	}
	_, err = messagesFromBytes(b)
	assert.NotNil(t, err)

	// error on update message deserialization
	u := &UpdateMessage{}
	b, err = u.serialize()
	if err != nil {
		t.Fatal(err)
	}
	_, err = messagesFromBytes(b)
	assert.NotNil(t, err)

	// error on notification message deserialization
	n := &NotificationMessage{}
	b, err = n.serialize()
	if err != nil {
		t.Fatal(err)
	}
	b = b[:len(b)-2]
	binary.BigEndian.PutUint16(b[16:18], 19)
	_, err = messagesFromBytes(b)
	assert.NotNil(t, err)

	// invalid message type
	b[18] = 5
	_, err = messagesFromBytes(b)
	assert.NotNil(t, err)
}
