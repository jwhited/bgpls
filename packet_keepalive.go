package bgpls

import "errors"

type keepAliveMessage struct{}

func (k *keepAliveMessage) MessageType() MessageType {
	return KeepAliveMessageType
}

func (k *keepAliveMessage) serialize() ([]byte, error) {
	buff := prependHeader(make([]byte, 0), KeepAliveMessageType)
	return buff, nil
}

func (k *keepAliveMessage) deserialize(b []byte) error {
	if len(b) > 0 {
		return &errWithNotification{
			error:   errors.New("keep alive message invalid length"),
			code:    NotifErrCodeMessageHeader,
			subcode: NotifErrSubcodeBadLength,
		}
	}
	return nil
}
