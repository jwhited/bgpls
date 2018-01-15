package bgpls

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNotificationMessage(t *testing.T) {
	code := NotifErrCodeUpdateMessage
	subcode := NotifErrSubcodeMalformedAttr
	data := []byte{1, 1, 1, 1}
	n := &NotificationMessage{
		Code:    code,
		Subcode: subcode,
		Data:    data,
	}

	b, err := n.serialize()
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

	f, ok := m[0].(*NotificationMessage)
	if !ok {
		t.Error("not a notification message")
	}

	assert.Equal(t, f.MessageType(), NotificationMessageType)
	assert.Equal(t, code, f.Code)
	assert.Equal(t, subcode, f.Subcode)
	assert.Equal(t, len(data), len(f.Data))

	for i, d := range data {
		assert.Equal(t, d, f.Data[i])
	}
}
