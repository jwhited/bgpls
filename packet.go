package bgpls

import (
	"encoding/binary"
)

func prependHeader(b []byte, t MessageType) []byte {
	buff := make([]byte, 19, 512)

	// marker
	for i := 0; i < 16; i++ {
		buff[i] = 0xFF
	}

	// length
	binary.BigEndian.PutUint16(buff[16:18], uint16(len(b)+19))

	// type
	buff[18] = uint8(t)

	// value
	buff = append(buff, b...)
	return buff
}

// MessageType describes the type of bgp message
type MessageType uint8

// MessageType values
const (
	OpenMessageType         MessageType = 1
	UpdateMessageType       MessageType = 2
	NotificationMessageType MessageType = 3
	KeepAliveMessageType    MessageType = 4
)

func (t MessageType) String() string {
	switch t {
	case OpenMessageType:
		return "open"
	case UpdateMessageType:
		return "update"
	case NotificationMessageType:
		return "notification"
	case KeepAliveMessageType:
		return "keepalive"
	default:
		return "unknown"
	}
}

// Message is a bgp message
type Message interface {
	MessageType() MessageType
	serialize() ([]byte, error)
	deserialize(b []byte) error
}

type errWithNotification struct {
	error
	code    NotifErrCode
	subcode NotifErrSubcode
	data    []byte
}
