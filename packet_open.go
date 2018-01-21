package bgpls

import (
	"encoding/binary"
	"errors"
	"math"
	"net"
	"time"
)

func newOpenMessage(asn uint32, holdTime time.Duration, bgpID net.IP) (*openMessage, error) {
	o := &openMessage{
		version:  4,
		holdTime: uint16(holdTime.Seconds()),
		optParams: []optParam{
			&capabilityOptParam{
				caps: []capability{
					&capFourOctetAs{
						asn: asn,
					},
					&capMultiproto{
						afi:  BgpLsAfi,
						safi: BgpLsSafi,
					},
				},
			},
		},
	}

	switch len(bgpID) {
	case 4:
		o.bgpID = binary.BigEndian.Uint32(bgpID[0:4])
	case 16:
		o.bgpID = binary.BigEndian.Uint32(bgpID[12:16])
	default:
		return nil, errors.New("invalid bgp ID")
	}

	/*
		rfc4893 page2
		To represent 4-octet AS numbers (which are not mapped from 2-octets)
		as 2-octet AS numbers in the AS path information encoded with 2-octet
		AS numbers, this document reserves a 2-octet AS number.  We denote
		this special AS number as AS_TRANS for ease of description in the
		rest of this specification.  This AS number is also placed in the "My
		Autonomous System" field of the OPEN message originated by a NEW BGP
		speaker, if the speaker does not have a (globally unique) 2-octet AS
		number.
	*/
	if asn > math.MaxUint16 {
		o.asn = asTrans
	} else {
		o.asn = uint16(asn)
	}

	return o, nil
}

type openMessage struct {
	version   uint8
	asn       uint16
	holdTime  uint16
	bgpID     uint32
	optParams []optParam
}

const (
	asTrans uint16 = 23456
)

func (o *openMessage) MessageType() MessageType {
	return OpenMessageType
}

func (o *openMessage) serialize() ([]byte, error) {
	buff := make([]byte, 9)

	// version
	buff[0] = o.version

	// asn
	binary.BigEndian.PutUint16(buff[1:3], o.asn)

	// holdTime
	binary.BigEndian.PutUint16(buff[3:5], o.holdTime)

	// bgpID
	binary.BigEndian.PutUint32(buff[5:9], o.bgpID)

	// optional parameters
	params := make([]byte, 0, 512)
	for _, p := range o.optParams {
		b, err := p.serialize()
		if err != nil {
			return buff, err
		}

		params = append(params, b...)
	}

	buff = append(buff, uint8(len(params)))
	buff = append(buff, params...)

	buff = prependHeader(buff, OpenMessageType)

	return buff, nil
}

func (o *openMessage) deserialize(b []byte) error {
	if len(b) < 10 {
		return &errWithNotification{
			error:   errors.New("open message too short"),
			code:    NotifErrCodeOpenMessage,
			subcode: NotifErrSubcodeBadLength,
		}
	}

	// version
	o.version = b[0]

	// asn
	o.asn = binary.BigEndian.Uint16(b[1:3])

	// hold time
	o.holdTime = binary.BigEndian.Uint16(b[3:5])

	// bgpID
	o.bgpID = binary.BigEndian.Uint32(b[5:9])

	// optional parameters
	optParamsLen := int(b[9])
	if optParamsLen != len(b)-10 {
		return &errWithNotification{
			error:   errors.New("optional parameter length field does not match actual length"),
			code:    NotifErrCodeOpenMessage,
			subcode: 0,
		}
	}

	optParams, err := deserializeOptParams(b[10:])
	if err != nil {
		return err
	}

	o.optParams = optParams

	return nil
}

func deserializeOptParams(b []byte) ([]optParam, error) {
	params := make([]optParam, 0, 1)

	for {
		if len(b) < 2 {
			return nil, &errWithNotification{
				error:   errors.New("optional parameter too short"),
				code:    NotifErrCodeOpenMessage,
				subcode: 0,
			}
		}

		paramCode := b[0]
		paramLen := b[1]
		if len(b) < int(paramLen)+2 {
			return nil, &errWithNotification{
				error:   errors.New("optional parameter length does not match length field"),
				code:    NotifErrCodeOpenMessage,
				subcode: 0,
			}
		}

		paramToDecode := make([]byte, 0)
		if paramLen > 0 {
			paramToDecode = b[2 : paramLen+2]
		}

		nextParam := 2 + int(paramLen)
		b = b[nextParam:]

		switch paramCode {
		case uint8(capabilityOptParamType):
			cap := &capabilityOptParam{}

			err := cap.deserialize(paramToDecode)
			if err != nil {
				return nil, err
			}

			params = append(params, cap)
		default:
		}

		if len(b) == 0 {
			break
		}
	}

	return params, nil
}

func validateOpenMessage(msg *openMessage, neighborASN uint32) error {
	if msg.version != 4 {
		version := make([]byte, 2)
		binary.BigEndian.PutUint16(version, uint16(4))
		return &errWithNotification{
			error:   errors.New("unsupported version number"),
			code:    NotifErrCodeOpenMessage,
			subcode: NotifErrSubcodeUnsupportedVersionNumber,
			data:    version,
		}
	}

	var fourOctetAS, fourOctetAsFound, bgpLsAfFound bool
	if msg.asn == asTrans {
		fourOctetAS = true
	} else {
		if msg.asn != uint16(neighborASN) {
			return &errWithNotification{
				error:   errors.New("bad peer AS"),
				code:    NotifErrCodeOpenMessage,
				subcode: NotifErrSubcodeBadPeerAS,
			}
		}
	}

	if msg.holdTime < 3 {
		return &errWithNotification{
			error:   errors.New("hold time must be >=3"),
			code:    NotifErrCodeOpenMessage,
			subcode: NotifErrSubcodeUnacceptableHoldTime,
		}
	}

	if msg.bgpID == 0 {
		return &errWithNotification{
			error:   errors.New("bgp ID cannot be 0"),
			code:    NotifErrCodeOpenMessage,
			subcode: NotifErrSubcodeBadBgpID,
		}
	}

	for _, p := range msg.optParams {
		capOptParam, isCapability := p.(*capabilityOptParam)
		if !isCapability {
			return &errWithNotification{
				error:   errors.New("non-capability optional parameter found"),
				code:    NotifErrCodeOpenMessage,
				subcode: NotifErrSubcodeUnsupportedOptParam,
			}
		}

		for _, c := range capOptParam.caps {
			switch cap := c.(type) {
			case *capFourOctetAs:
				fourOctetAsFound = true
				if cap.asn != neighborASN {
					return &errWithNotification{
						error:   errors.New("bad peer AS"),
						code:    NotifErrCodeOpenMessage,
						subcode: NotifErrSubcodeBadPeerAS,
					}
				}
			case *capMultiproto:
				if cap.afi == BgpLsAfi && cap.safi == BgpLsSafi {
					bgpLsAfFound = true
				}
			case *capUnknown:
			}
		}
	}

	if !bgpLsAfFound {
		bgpLsCap := &capMultiproto{
			afi:  BgpLsAfi,
			safi: BgpLsSafi,
		}
		b, err := bgpLsCap.serialize()
		if err != nil {
			panic("error serializing bgp-ls multiprotocol capability")
		}
		return &errWithNotification{
			error:   errors.New("bgp-ls capability not found"),
			code:    NotifErrCodeOpenMessage,
			subcode: NotifErrSubcodeUnsupportedCapability,
			data:    b,
		}
	}

	if fourOctetAS && !fourOctetAsFound {
		return &errWithNotification{
			error:   errors.New("4-octet AS indicated in as field but not found in capabilities"),
			code:    NotifErrCodeOpenMessage,
			subcode: NotifErrSubcodeBadPeerAS,
		}
	}

	return nil
}

type optParamType uint8

const (
	capabilityOptParamType optParamType = 2
)

type optParam interface {
	optParamType() optParamType
	serialize() ([]byte, error)
	deserialize(b []byte) error
}

type capabilityOptParam struct {
	caps []capability
}

func (c *capabilityOptParam) optParamType() optParamType {
	return capabilityOptParamType
}

func (c *capabilityOptParam) serialize() ([]byte, error) {
	buff := make([]byte, 0, 512)
	caps := make([]byte, 0, 512)

	if len(c.caps) > 0 {
		for _, c := range c.caps {
			b, err := c.serialize()
			if err != nil {
				return buff, err
			}
			caps = append(caps, b...)
		}
	} else {
		return buff, errors.New("empty caps in cap opt param")
	}

	buff = append(buff, uint8(capabilityOptParamType))
	buff = append(buff, uint8(len(caps)))
	buff = append(buff, caps...)

	return buff, nil
}

func (c *capabilityOptParam) deserialize(b []byte) error {
	for {
		if len(b) < 2 {
			return &errWithNotification{
				error:   errors.New("capability too short"),
				code:    NotifErrCodeOpenMessage,
				subcode: 0,
			}
		}

		capCode := b[0]
		capLen := b[1]
		if len(b) < int(capLen)+2 {
			return &errWithNotification{
				error:   errors.New("capability length does not match length field"),
				code:    NotifErrCodeOpenMessage,
				subcode: 0,
			}
		}

		capToDecode := make([]byte, 0)
		if capLen > 0 {
			capToDecode = b[2 : capLen+2]
		}

		nextCap := 2 + int(capLen)
		b = b[nextCap:]

		switch capCode {
		case uint8(capCodeMultiproto):
			cap := &capMultiproto{}
			err := cap.deserialize(capToDecode)
			if err != nil {
				return err
			}

			c.caps = append(c.caps, cap)
		case uint8(capCodeFourOctetAs):
			cap := &capFourOctetAs{}
			err := cap.deserialize(capToDecode)
			if err != nil {
				return err
			}

			c.caps = append(c.caps, cap)
		default:
			cap := &capUnknown{
				code: capCode,
			}
			err := cap.deserialize(capToDecode)
			if err != nil {
				return err
			}

			c.caps = append(c.caps, cap)
		}

		if len(b) == 0 {
			return nil
		}
	}
}

type capabilityCode uint8

const (
	capCodeMultiproto  capabilityCode = 1
	capCodeFourOctetAs capabilityCode = 65
)

type capability interface {
	capabilityCode() capabilityCode
	serialize() ([]byte, error)
	deserialize(b []byte) error
}

type capUnknown struct {
	code uint8
	data []byte
}

func (u *capUnknown) capabilityCode() capabilityCode {
	return capabilityCode(u.code)
}

func (u *capUnknown) serialize() ([]byte, error) {
	buff := make([]byte, 2)
	buff[0] = u.code
	buff[1] = uint8(len(u.data))

	if len(u.data) > 0 {
		buff = append(buff, u.data...)
	}

	return buff, nil
}

func (u *capUnknown) deserialize(b []byte) error {
	if len(b) > 2 {
		u.data = b[2:]
	}

	return nil
}

// MultiprotoAfi identifies the address family for multiprotocol bgp.
type MultiprotoAfi uint16

// MultiprotoAfi values
const (
	BgpLsAfi MultiprotoAfi = 16388
)

// MultiprotoSafi identifies the subsequent address family for multiprotocol bgp.
type MultiprotoSafi uint8

// MultiprotoSafi values
const (
	BgpLsSafi MultiprotoSafi = 71
)

type capMultiproto struct {
	afi  MultiprotoAfi
	safi MultiprotoSafi
}

func (m *capMultiproto) serialize() ([]byte, error) {
	buff := make([]byte, 6)

	// type
	buff[0] = uint8(capCodeMultiproto)

	// length
	buff[1] = uint8(4)

	// afi
	binary.BigEndian.PutUint16(buff[2:4], uint16(m.afi))

	// reserved
	buff[4] = 0

	// safi
	buff[5] = uint8(m.safi)

	return buff, nil
}

func (m *capMultiproto) deserialize(b []byte) error {
	if len(b) != 4 {
		return &errWithNotification{
			error:   errors.New("multiprotocol capability length does not equal 4"),
			code:    NotifErrCodeOpenMessage,
			subcode: 0,
		}
	}

	m.afi = MultiprotoAfi(binary.BigEndian.Uint16(b[:2]))
	m.safi = MultiprotoSafi(b[3])

	return nil
}

func (m *capMultiproto) capabilityCode() capabilityCode {
	return capCodeMultiproto
}

type capFourOctetAs struct {
	asn uint32
}

func (f *capFourOctetAs) serialize() ([]byte, error) {
	buff := make([]byte, 6)

	// type
	buff[0] = uint8(capCodeFourOctetAs)

	// length
	buff[1] = uint8(4)

	// asn
	binary.BigEndian.PutUint32(buff[2:], f.asn)

	return buff, nil
}

func (f *capFourOctetAs) deserialize(b []byte) error {
	if len(b) != 4 {
		return &errWithNotification{
			error:   errors.New("4-octet AS capability length does not equal 4"),
			code:    NotifErrCodeOpenMessage,
			subcode: 0,
		}
	}

	f.asn = binary.BigEndian.Uint32(b)

	return nil
}

func (f *capFourOctetAs) capabilityCode() capabilityCode {
	return capCodeFourOctetAs
}
