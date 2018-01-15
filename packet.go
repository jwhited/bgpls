package bgpls

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// MessageType describes the type of bgp message.
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

// Message is a bgp message.
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

func messagesFromBytes(b []byte) ([]Message, error) {
	messages := make([]Message, 0)

	for {
		if len(b) < 19 {
			return nil, &errWithNotification{
				error:   errors.New("message < 19 bytes"),
				code:    NotifErrCodeMessageHeader,
				subcode: NotifErrSubcodeBadLength,
			}
		}

		for i := 0; i < 16; i++ {
			if b[i] != 0xFF {
				return nil, &errWithNotification{
					error:   errors.New("invalid message header marker value"),
					code:    NotifErrCodeMessageHeader,
					subcode: NotifErrSubcodeConnNotSynch,
				}
			}
		}

		msgLen := binary.BigEndian.Uint16(b[16:18])
		if len(b) < int(msgLen) {
			return nil, &errWithNotification{
				error:   errors.New("message header length invalid"),
				code:    NotifErrCodeMessageHeader,
				subcode: NotifErrSubcodeBadLength,
			}
		}

		msgType := MessageType(b[18])
		msgBytes := b[19:msgLen]

		switch msgType {
		case OpenMessageType:
			m := &openMessage{}
			err := m.deserialize(msgBytes)
			if err != nil {
				return nil, err
			}
			messages = append(messages, m)
		case KeepAliveMessageType:
			m := &keepAliveMessage{}
			err := m.deserialize(msgBytes)
			if err != nil {
				return nil, err
			}
			messages = append(messages, m)
		case UpdateMessageType:
			m := &UpdateMessage{}
			err := m.deserialize(msgBytes)
			if err != nil {
				return nil, err
			}
			messages = append(messages, m)
		case NotificationMessageType:
			m := &NotificationMessage{}
			err := m.deserialize(msgBytes)
			if err != nil {
				return nil, err
			}
			messages = append(messages, m)
		default:
			return nil, &errWithNotification{
				error:   fmt.Errorf("invalid message type %s", msgType),
				code:    NotifErrCodeMessageHeader,
				subcode: NotifErrSubcodeBadType,
			}
		}

		if len(b) > int(msgLen) {
			b = b[msgLen:]
		} else {
			break
		}
	}

	return messages, nil
}

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
