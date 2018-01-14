package bgpls

type keepAliveMessage struct{}

func (k *keepAliveMessage) MessageType() MessageType {
	return KeepAliveMessageType
}

func (k *keepAliveMessage) serialize() ([]byte, error) {
	buff := prependHeader(make([]byte, 0), KeepAliveMessageType)
	return buff, nil
}

func (k *keepAliveMessage) deserialize(b []byte) error {
	return nil
}
