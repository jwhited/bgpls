package bgpls

import "errors"

// NotifErrCode is a notifcation message error code
type NotifErrCode uint8

// NotifErrCode values
const (
	_ NotifErrCode = iota
	NotifErrCodeMessageHeader
	NotifErrCodeOpenMessage
	NotifErrCodeUpdateMessage
	NotifErrCodeHoldTimerExpired
	NotifErrCodeFsmError
	NotifErrCodeCease
)

// NotifErrSubcode is a notification message error subcode
type NotifErrSubcode uint8

// message header subcodes
const (
	_ NotifErrSubcode = iota
	NotifErrSubcodeConnNotSynch
	NotifErrSubcodeBadLength
	NotifErrSubcodeBadType
)

// open message subcodes
const (
	_ NotifErrSubcode = iota
	NotifErrSubcodeUnsupportedVersionNumber
	NotifErrSubcodeBadPeerAS
	NotifErrSubcodeBadBgpID
	NotifErrSubcodeUnsupportedOptParam
	_
	NotifErrSubcodeUnacceptableHoldTime
	NotifErrSubcodeUnsupportedCapability
)

// update message subcodes
const (
	_ NotifErrSubcode = iota
	NotifErrSubcodeMalformedAttr
	NotifErrSubcodeUnrecognizedWellKnownAttr
	NotifErrSubcodeMissingWellKnownAttr
	NotifErrSubcodeAttrFlagsError
	NotifErrSubcodeAttrLenError
	NotifErrSubcodeInvalidOrigin
	_
	NotifErrSubcodeInvalidNextHop
	NotifErrSubcodeOptionalAttrError
	NotifErrSubcodeInvalidNetworkField
	NotifErrSubcodeMalformedAsPath
)

// NotificationMessage is a bgp message
type NotificationMessage struct {
	Code    NotifErrCode
	Subcode NotifErrSubcode
	Data    []byte
}

// MessageType returns the appropriate MessageType for NotificationMessage
func (n *NotificationMessage) MessageType() MessageType {
	return NotificationMessageType
}

func (n *NotificationMessage) serialize() ([]byte, error) {
	buff := make([]byte, 2)
	buff[0] = uint8(n.Code)
	buff[1] = uint8(n.Subcode)
	if len(n.Data) > 0 {
		buff = append(buff, n.Data...)
	}

	return buff, nil
}

func (n *NotificationMessage) deserialize(b []byte) error {
	if len(b) < 2 {
		return errors.New("incomplete notification message")
	}

	n.Code = NotifErrCode(b[0])
	n.Subcode = NotifErrSubcode(b[1])

	if len(b) > 2 {
		n.Data = b[2:]
	}

	return nil
}
