package bgpls

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
)

/*
4.3.  UPDATE Message Format

   UPDATE messages are used to transfer routing information between BGP
   peers.  The information in the UPDATE message can be used to
   construct a graph that describes the relationships of the various
   Autonomous Systems.  By applying rules to be discussed, routing
   information loops and some other anomalies may be detected and
   removed from inter-AS routing.

   An UPDATE message is used to advertise feasible routes that share
   common path attributes to a peer, or to withdraw multiple unfeasible
   routes from service (see 3.1).  An UPDATE message MAY simultaneously
   advertise a feasible route and withdraw multiple unfeasible routes
   from service.  The UPDATE message always includes the fixed-size BGP
   header, and also includes the other fields, as shown below (note,
   some of the shown fields may not be present in every UPDATE message):

      +-----------------------------------------------------+
      |   Withdrawn Routes Length (2 octets)                |
      +-----------------------------------------------------+
      |   Withdrawn Routes (variable)                       |
      +-----------------------------------------------------+
      |   Total Path Attribute Length (2 octets)            |
      +-----------------------------------------------------+
      |   Path Attributes (variable)                        |
      +-----------------------------------------------------+
      |   Network Layer Reachability Information (variable) |
      +-----------------------------------------------------+
*/

// UpdateMessage is a bgp message.
type UpdateMessage struct {
	PathAttrs []PathAttr
}

// MessageType returns the appropriate MessageType for UpdateMessage.
func (u *UpdateMessage) MessageType() MessageType {
	return UpdateMessageType
}

func (u *UpdateMessage) serialize() ([]byte, error) {
	buff := make([]byte, 4)

	// withdrawn routes len
	binary.BigEndian.PutUint16(buff[0:2], 0)

	params := make([]byte, 0, 512)
	for _, p := range u.PathAttrs {
		b, err := p.serialize()
		if err != nil {
			return nil, err
		}

		params = append(params, b...)
	}

	// path attribute length
	binary.BigEndian.PutUint16(buff[2:4], uint16(len(params)))

	// path attributes
	buff = append(buff, params...)

	buff = prependHeader(buff, UpdateMessageType)

	return buff, nil
}

func (u *UpdateMessage) deserialize(b []byte) error {
	tooShortErr := &errWithNotification{
		error:   errors.New("update message is too short"),
		code:    NotifErrCodeUpdateMessage,
		subcode: NotifErrSubcodeMalformedAttr,
	}

	if len(b) < 4 {
		return tooShortErr
	}

	withdrawnRoutesLen := binary.BigEndian.Uint16(b[:2])
	if len(b) < int(withdrawnRoutesLen)+4 {
		return tooShortErr
	}
	b = b[2+withdrawnRoutesLen:]

	pathAttrLen := binary.BigEndian.Uint16(b[:2])
	if len(b) < int(pathAttrLen)+2 {
		return tooShortErr
	}
	b = b[2:]

	attrs, err := deserializePathAttrs(b[:pathAttrLen])
	if err != nil {
		return err
	}
	u.PathAttrs = attrs

	return nil
}

func deserializePathAttrs(b []byte) ([]PathAttr, error) {
	attrs := make([]PathAttr, 0)

	tooShortErr := &errWithNotification{
		error:   errors.New("path attribute too short"),
		code:    NotifErrCodeUpdateMessage,
		subcode: 0,
	}

	for {
		if len(b) < 2 {
			return nil, tooShortErr
		}

		flags := pathAttrFlagsFromByte(b[0])
		attrType := b[1]

		/*
			The fourth high-order bit (bit 3) of the Attribute Flags octet
			is the Extended Length bit.  It defines whether the Attribute
			Length is one octet (if set to 0) or two octets (if set to 1).
		*/
		var attrLen int
		if flags.ExtendedLength {
			attrLen = int(binary.BigEndian.Uint16(b[2:4]))
			b = b[4:]
		} else {
			attrLen = int(b[2])
			b = b[3:]
		}
		if len(b) < attrLen {
			return nil, tooShortErr
		}

		attrToDecode := b[:attrLen]

		switch attrType {
		case uint8(PathAttrOriginType):
			err := validatePathAttrFlags(flags, pathAttrCatWellKnownMandatory)
			if err != nil {
				return nil, err
			}

			attr := &PathAttrOrigin{}
			err = attr.deserialize(flags, attrToDecode)
			if err != nil {
				return nil, err
			}
			attrs = append(attrs, attr)
		case uint8(PathAttrAsPathType):
			err := validatePathAttrFlags(flags, pathAttrCatWellKnownMandatory)
			if err != nil {
				return nil, err
			}

			attr := &PathAttrAsPath{}
			err = attr.deserialize(flags, attrToDecode)
			if err != nil {
				return nil, err
			}
			attrs = append(attrs, attr)
		case uint8(PathAttrLocalPrefType):
			err := validatePathAttrFlags(flags, pathAttrCatWellKnownDiscretionary)
			if err != nil {
				return nil, err
			}

			attr := &PathAttrLocalPref{}
			err = attr.deserialize(flags, attrToDecode)
			if err != nil {
				return nil, err
			}
			attrs = append(attrs, attr)
		case uint8(PathAttrMpReachType):
			err := validatePathAttrFlags(flags, pathAttrCatOptionalNonTransitive)
			if err != nil {
				return nil, err
			}

			attr := &PathAttrMpReach{}
			err = attr.deserialize(flags, attrToDecode)
			if err != nil {
				return nil, err
			}
			attrs = append(attrs, attr)
		case uint8(PathAttrMpUnreachType):
			err := validatePathAttrFlags(flags, pathAttrCatOptionalNonTransitive)
			if err != nil {
				return nil, err
			}

			attr := &PathAttrMpUnreach{}
			err = attr.deserialize(flags, attrToDecode)
			if err != nil {
				return nil, err
			}
			attrs = append(attrs, attr)
		case uint8(PathAttrLinkStateType):
			err := validatePathAttrFlags(flags, pathAttrCatOptionalNonTransitive)
			if err != nil {
				return nil, err
			}

			attr := &PathAttrLinkState{}
			err = attr.deserialize(flags, attrToDecode)
			if err != nil {
				return nil, err
			}
			attrs = append(attrs, attr)
		}

		b = b[attrLen:]

		if len(b) == 0 {
			break
		}
	}

	return attrs, nil
}

type pathAttrCategory uint8

const (
	pathAttrCatWellKnownMandatory pathAttrCategory = iota
	pathAttrCatWellKnownDiscretionary
	pathAttrCatOptionalTransitive
	pathAttrCatOptionalNonTransitive
)

func validatePathAttrFlags(f PathAttrFlags, c pathAttrCategory) error {
	switch c {
	case pathAttrCatWellKnownMandatory:
		if !f.Optional && !f.Partial && f.Transitive {
			return nil
		}
	case pathAttrCatWellKnownDiscretionary:
		if !f.Optional {
			return nil
		}
	case pathAttrCatOptionalTransitive:
		if f.Optional && f.Transitive {
			return nil
		}
	case pathAttrCatOptionalNonTransitive:
		if f.Optional && !f.Transitive {
			return nil
		}
	}

	return &errWithNotification{
		error:   errors.New("invalid path attribute flags"),
		code:    NotifErrCodeUpdateMessage,
		subcode: NotifErrSubcodeAttrFlagsError,
	}
}

/*
	0                   1
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|  Attr. Flags  |Attr. Type Code|
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	The high-order bit (bit 0) of the Attribute Flags octet is the
	Optional bit.  It defines whether the attribute is optional (if
	set to 1) or well-known (if set to 0).

	The second high-order bit (bit 1) of the Attribute Flags octet
	is the Transitive bit.  It defines whether an optional
	attribute is transitive (if set to 1) or non-transitive (if set
	to 0).

	For well-known attributes, the Transitive bit MUST be set to 1.
	(See Section 5 for a discussion of transitive attributes.)

	The third high-order bit (bit 2) of the Attribute Flags octet
	is the Partial bit.  It defines whether the information
	contained in the optional transitive attribute is partial (if
	set to 1) or complete (if set to 0).  For well-known attributes
	and for optional non-transitive attributes, the Partial bit
	MUST be set to 0.

	The fourth high-order bit (bit 3) of the Attribute Flags octet
	is the Extended Length bit.  It defines whether the Attribute
	Length is one octet (if set to 0) or two octets (if set to 1).
*/
func pathAttrFlagsFromByte(b uint8) PathAttrFlags {
	flags := PathAttrFlags{}
	flags.Optional = (128 & b) != 0
	flags.Transitive = (64 & b) != 0
	flags.Partial = (32 & b) != 0
	flags.ExtendedLength = (16 & b) != 0

	return flags
}

// PathAttrFlags contains the flags for a bgp path attribute.
type PathAttrFlags struct {
	Optional       bool
	Transitive     bool
	Partial        bool
	ExtendedLength bool
}

func (f *PathAttrFlags) serialize() (byte, error) {
	var val uint8
	if f.Optional {
		val += 128
	}
	if f.Transitive {
		val += 64
	}
	if f.Partial {
		val += 32
	}
	if f.ExtendedLength {
		val += 16
	}
	return val, nil
}

// PathAttr is a bgp path attribute.
type PathAttr interface {
	serialize() ([]byte, error)
	Flags() PathAttrFlags
	Type() PathAttrType
}

// PathAttrType describes the type of a bgp path attribute.
type PathAttrType uint8

// PathAttrType values
const (
	PathAttrOriginType    PathAttrType = 1
	PathAttrAsPathType    PathAttrType = 2
	PathAttrLocalPrefType PathAttrType = 5
	PathAttrMpReachType   PathAttrType = 14
	PathAttrMpUnreachType PathAttrType = 15
	PathAttrLinkStateType PathAttrType = 29
)

// PathAttrLinkState is a bgp path attribute.
//
// https://tools.ietf.org/html/rfc7752#section-3.3
type PathAttrLinkState struct {
	f           PathAttrFlags
	NodeAttrs   []NodeAttr
	LinkAttrs   []LinkAttr
	PrefixAttrs []PrefixAttr
}

// Flags returns the flags for a link state path attribute.
func (p *PathAttrLinkState) Flags() PathAttrFlags {
	return p.f
}

// Type returns the appropriate PathAttrType for PathAttrLinkState.
func (p *PathAttrLinkState) Type() PathAttrType {
	return PathAttrLinkStateType
}

func (p *PathAttrLinkState) deserialize(f PathAttrFlags, b []byte) error {
	p.f = f

	if len(b) == 0 {
		return nil
	}

	tooShortErr := &errWithNotification{
		error:   errors.New("link state path attribute too short"),
		code:    NotifErrCodeUpdateMessage,
		subcode: NotifErrSubcodeMalformedAttr,
	}

	if len(b) < 4 {
		return tooShortErr
	}

	for {
		lsAttrType := binary.BigEndian.Uint16(b[:2])
		lsAttrLen := int(binary.BigEndian.Uint16(b[2:4]))
		b = b[4:]

		if len(b) < lsAttrLen {
			return tooShortErr
		}

		attrToDecode := b[:lsAttrLen]
		b = b[lsAttrLen:]

		switch lsAttrType {
		case uint16(NodeAttrCodeIsIsAreaID):
			attr := &NodeAttrIsIsAreaID{}
			err := attr.deserialize(attrToDecode)
			if err != nil {
				return err
			}
			p.NodeAttrs = append(p.NodeAttrs, attr)
		case uint16(NodeAttrCodeLocalIPv4RouterID):
			attr := &NodeAttrLocalIPv4RouterID{}
			err := attr.deserialize(attrToDecode)
			if err != nil {
				return err
			}
			p.NodeAttrs = append(p.NodeAttrs, attr)
		case uint16(NodeAttrCodeLocalIPv6RouterID):
			attr := &NodeAttrLocalIPv6RouterID{}
			err := attr.deserialize(attrToDecode)
			if err != nil {
				return err
			}
			p.NodeAttrs = append(p.NodeAttrs, attr)
		case uint16(NodeAttrCodeMultiTopologyID):
			attr := &NodeAttrMultiTopologyID{}
			err := attr.deserialize(attrToDecode)
			if err != nil {
				return err
			}
			p.NodeAttrs = append(p.NodeAttrs, attr)
		case uint16(NodeAttrCodeNodeFlagBits):
			attr := &NodeAttrNodeFlagBits{}
			err := attr.deserialize(attrToDecode)
			if err != nil {
				return err
			}
			p.NodeAttrs = append(p.NodeAttrs, attr)
		case uint16(NodeAttrCodeNodeName):
			attr := &NodeAttrNodeName{}
			err := attr.deserialize(attrToDecode)
			if err != nil {
				return err
			}
			p.NodeAttrs = append(p.NodeAttrs, attr)
		case uint16(NodeAttrCodeOpaqueNodeAttr):
			attr := &NodeAttrOpaqueNodeAttr{}
			err := attr.deserialize(attrToDecode)
			if err != nil {
				return err
			}
			p.NodeAttrs = append(p.NodeAttrs, attr)
		case uint16(LinkAttrCodeAdminGroup):
			attr := &LinkAttrAdminGroup{}
			err := attr.deserialize(attrToDecode)
			if err != nil {
				return err
			}
			p.LinkAttrs = append(p.LinkAttrs, attr)
		case uint16(LinkAttrCodeIgpMetric):
			attr := &LinkAttrIgpMetric{}
			err := attr.deserialize(attrToDecode)
			if err != nil {
				return err
			}
			p.LinkAttrs = append(p.LinkAttrs, attr)
		case uint16(LinkAttrCodeLinkName):
			attr := &LinkAttrLinkName{}
			err := attr.deserialize(attrToDecode)
			if err != nil {
				return err
			}
			p.LinkAttrs = append(p.LinkAttrs, attr)
		case uint16(LinkAttrCodeLinkProtectionType):
			attr := &LinkAttrLinkProtectionType{}
			err := attr.deserialize(attrToDecode)
			if err != nil {
				return err
			}
			p.LinkAttrs = append(p.LinkAttrs, attr)
		case uint16(LinkAttrCodeMaxLinkBandwidth):
			attr := &LinkAttrMaxLinkBandwidth{}
			err := attr.deserialize(attrToDecode)
			if err != nil {
				return err
			}
			p.LinkAttrs = append(p.LinkAttrs, attr)
		case uint16(LinkAttrCodeMaxReservableLinkBandwidth):
			attr := &LinkAttrMaxReservableLinkBandwidth{}
			err := attr.deserialize(attrToDecode)
			if err != nil {
				return err
			}
			p.LinkAttrs = append(p.LinkAttrs, attr)
		case uint16(LinkAttrCodeMplsProtocolMask):
			attr := &LinkAttrMplsProtocolMask{}
			err := attr.deserialize(attrToDecode)
			if err != nil {
				return err
			}
			p.LinkAttrs = append(p.LinkAttrs, attr)
		case uint16(LinkAttrCodeOpaqueLinkAttr):
			attr := &LinkAttrOpaqueLinkAttr{}
			err := attr.deserialize(attrToDecode)
			if err != nil {
				return err
			}
			p.LinkAttrs = append(p.LinkAttrs, attr)
		case uint16(LinkAttrCodeRemoteIPv4RouterID):
			attr := &LinkAttrRemoteIPv4RouterID{}
			err := attr.deserialize(attrToDecode)
			if err != nil {
				return err
			}
			p.LinkAttrs = append(p.LinkAttrs, attr)
		case uint16(LinkAttrCodeRemoteIPv6RouterID):
			attr := &LinkAttrRemoteIPv6RouterID{}
			err := attr.deserialize(attrToDecode)
			if err != nil {
				return err
			}
			p.LinkAttrs = append(p.LinkAttrs, attr)
		case uint16(LinkAttrCodeSharedRiskLinkGroup):
			attr := &LinkAttrSharedRiskLinkGroup{}
			err := attr.deserialize(attrToDecode)
			if err != nil {
				return err
			}
			p.LinkAttrs = append(p.LinkAttrs, attr)
		case uint16(LinkAttrCodeTEDefaultMetric):
			attr := &LinkAttrTEDefaultMetric{}
			err := attr.deserialize(attrToDecode)
			if err != nil {
				return err
			}
			p.LinkAttrs = append(p.LinkAttrs, attr)
		case uint16(LinkAttrCodeUnreservedBandwidth):
			attr := &LinkAttrUnreservedBandwidth{}
			err := attr.deserialize(attrToDecode)
			if err != nil {
				return err
			}
			p.LinkAttrs = append(p.LinkAttrs, attr)
		case uint16(PrefixAttrCodeIgpExtendedRouteTag):
			attr := &PrefixAttrIgpExtendedRouteTag{}
			err := attr.deserialize(attrToDecode)
			if err != nil {
				return err
			}
			p.PrefixAttrs = append(p.PrefixAttrs, attr)
		case uint16(PrefixAttrCodeIgpFlags):
			attr := &PrefixAttrIgpFlags{}
			err := attr.deserialize(attrToDecode)
			if err != nil {
				return err
			}
			p.PrefixAttrs = append(p.PrefixAttrs, attr)
		case uint16(PrefixAttrCodeIgpRouteTag):
			attr := &PrefixAttrIgpRouteTag{}
			err := attr.deserialize(attrToDecode)
			if err != nil {
				return err
			}
			p.PrefixAttrs = append(p.PrefixAttrs, attr)
		case uint16(PrefixAttrCodeOpaquePrefixAttribute):
			attr := &PrefixAttrOpaquePrefixAttribute{}
			err := attr.deserialize(attrToDecode)
			if err != nil {
				return err
			}
			p.PrefixAttrs = append(p.PrefixAttrs, attr)
		case uint16(PrefixAttrCodeOspfForwardingAddress):
			attr := &PrefixAttrOspfForwardingAddress{}
			err := attr.deserialize(attrToDecode)
			if err != nil {
				return err
			}
			p.PrefixAttrs = append(p.PrefixAttrs, attr)
		case uint16(PrefixAttrCodePrefixMetric):
			attr := &PrefixAttrPrefixMetric{}
			err := attr.deserialize(attrToDecode)
			if err != nil {
				return err
			}
			p.PrefixAttrs = append(p.PrefixAttrs, attr)
		default:
			return &errWithNotification{
				error:   errors.New("unknown link state attr type"),
				code:    NotifErrCodeUpdateMessage,
				subcode: NotifErrSubcodeMalformedAttr,
			}
		}

		if len(b) == 0 {
			break
		}
	}

	return nil
}

func (p *PathAttrLinkState) serialize() ([]byte, error) {
	p.f = PathAttrFlags{
		Optional: true,
	}

	// node attrs
	nodeAttrs := make([]byte, 0, 512)
	for _, n := range p.NodeAttrs {
		b, err := n.serialize()
		if err != nil {
			return nil, err
		}
		nodeAttrs = append(nodeAttrs, b...)
	}

	// link attrs
	linkAttrs := make([]byte, 0, 512)
	for _, l := range p.LinkAttrs {
		b, err := l.serialize()
		if err != nil {
			return nil, err
		}
		linkAttrs = append(linkAttrs, b...)
	}

	// prefix attrs
	prefixAttrs := make([]byte, 0, 512)
	for _, p := range p.PrefixAttrs {
		b, err := p.serialize()
		if err != nil {
			return nil, err
		}
		prefixAttrs = append(prefixAttrs, b...)
	}

	nodeAttrs = append(nodeAttrs, linkAttrs...)
	nodeAttrs = append(nodeAttrs, prefixAttrs...)
	if len(nodeAttrs) > math.MaxUint8 {
		p.f.ExtendedLength = true
	}
	flags, err := p.f.serialize()
	if err != nil {
		return nil, err
	}

	b := make([]byte, 2)
	b[0] = flags
	b[1] = byte(PathAttrLinkStateType)
	if p.f.ExtendedLength {
		l := make([]byte, 2)
		binary.BigEndian.PutUint16(l, uint16(len(nodeAttrs)))
		b = append(b, l...)
	} else {
		b = append(b, uint8(len(nodeAttrs)))
	}
	b = append(b, nodeAttrs...)

	return b, nil
}

// 2 octet type and 2 octet length
func serializeBgpLsStringTLV(l uint16, s string) []byte {
	val := reverseByteOrder([]byte(s))
	b := make([]byte, 4)
	binary.BigEndian.PutUint16(b[:2], l)
	binary.BigEndian.PutUint16(b[2:], uint16(len(val)))
	b = append(b, val...)
	return b
}

// 2 octet type and 2 octet length
func serializeBgpLsIPv4TLV(l uint16, a net.IP) ([]byte, error) {
	b := make([]byte, 4)
	binary.BigEndian.PutUint16(b[:2], l)
	binary.BigEndian.PutUint16(b[2:], uint16(4))
	addr := a.To4()
	if addr == nil {
		return nil, errors.New("invalid ipv4 address")
	}
	b = append(b, addr...)
	return b, nil
}

// 2 octet type and 2 octet length
func serializeBgpLsIPv6TLV(l uint16, a net.IP) ([]byte, error) {
	b := make([]byte, 4)
	binary.BigEndian.PutUint16(b[:2], l)
	binary.BigEndian.PutUint16(b[2:], uint16(16))
	addr := a.To16()
	if addr == nil {
		return nil, errors.New("invalid ipv4 address")
	}
	b = append(b, addr...)
	return b, nil
}

func deserializeIPv4Addr(b []byte) (net.IP, error) {
	if len(b) != 4 {
		return nil, errors.New("invalid length for ipv4 address")
	}

	addr, err := bytesToIPAddress(b)
	if err != nil {
		return nil, fmt.Errorf("error deserializing ipv4 address: %v", err)
	}

	return addr, err
}

func deserializeIPv6Addr(b []byte) (net.IP, error) {
	if len(b) != 16 {
		return nil, errors.New("invalid length for ipv6 address")
	}

	addr, err := bytesToIPAddress(b)
	if err != nil {
		return nil, fmt.Errorf("error deserializing ipv6 address: %v", err)
	}

	return addr, err
}

// NodeAttrCode describes the type of node attribute contained in a bgp-ls attribute
//
// https://tools.ietf.org/html/rfc7752#section-3.3.1
type NodeAttrCode uint16

// NodeAttrCode values
const (
	NodeAttrCodeMultiTopologyID   NodeAttrCode = 263
	NodeAttrCodeNodeFlagBits      NodeAttrCode = 1024
	NodeAttrCodeOpaqueNodeAttr    NodeAttrCode = 1025
	NodeAttrCodeNodeName          NodeAttrCode = 1026
	NodeAttrCodeIsIsAreaID        NodeAttrCode = 1027
	NodeAttrCodeLocalIPv4RouterID NodeAttrCode = 1028
	NodeAttrCodeLocalIPv6RouterID NodeAttrCode = 1029
)

// NodeAttr is a node attribute contained in a bgp-ls attribute.
type NodeAttr interface {
	Code() NodeAttrCode
	serialize() ([]byte, error)
	deserialize(b []byte) error
}

// NodeAttrMultiTopologyID is a node attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/rfc7752#section-3.2.1.5
type NodeAttrMultiTopologyID struct {
	IDs []uint16
}

// Code returns the appropriate NodeAttrCode for NodeAttrMultiTopologyID.
func (n *NodeAttrMultiTopologyID) Code() NodeAttrCode {
	return NodeAttrCodeMultiTopologyID
}

func (n *NodeAttrMultiTopologyID) deserialize(b []byte) error {
	ids, err := deserializeMultiTopologyIDs(b)
	if err != nil {
		return err
	}

	n.IDs = ids
	return nil
}

func (n *NodeAttrMultiTopologyID) serialize() ([]byte, error) {
	return serializeMultiTopologyIDs(uint16(n.Code()), n.IDs)
}

// NodeAttrNodeFlagBits is a node attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/rfc7752#section-3.3.1.1
type NodeAttrNodeFlagBits struct {
	Overload bool
	Attached bool
	External bool
	ABR      bool
	Router   bool
	V6       bool
}

// Code returns the appropriate NodeAttrCode for NodeAttrNodeFlagBits.
func (n *NodeAttrNodeFlagBits) Code() NodeAttrCode {
	return NodeAttrCodeNodeFlagBits
}

func (n *NodeAttrNodeFlagBits) deserialize(b []byte) error {
	if len(b) != 1 {
		return &errWithNotification{
			error:   errors.New("invalid length for node flag bits link state node attribute"),
			code:    NotifErrCodeUpdateMessage,
			subcode: NotifErrSubcodeMalformedAttr,
		}
	}

	n.Overload = (128 & b[0]) != 0
	n.Attached = (64 & b[0]) != 0
	n.External = (32 & b[0]) != 0
	n.ABR = (16 & b[0]) != 0
	n.Router = (8 & b[0]) != 0
	n.V6 = (4 & b[0]) != 0

	return nil
}

func (n *NodeAttrNodeFlagBits) serialize() ([]byte, error) {
	b := make([]byte, 5)
	binary.BigEndian.PutUint16(b[:2], uint16(n.Code()))
	binary.BigEndian.PutUint16(b[2:], uint16(1))

	var val uint8
	if n.Overload {
		val += 128
	}
	if n.Attached {
		val += 64
	}
	if n.External {
		val += 32
	}
	if n.ABR {
		val += 16
	}
	if n.Router {
		val += 8
	}
	if n.V6 {
		val += 4
	}

	b[4] = val
	return b, nil
}

// NodeAttrOpaqueNodeAttr is a node attribute contained a bgp-ls attribute.
//
// https://tools.ietf.org/html/rfc7752#section-3.3.1.5
type NodeAttrOpaqueNodeAttr struct {
	Data []byte
}

// Code returns the appropriate NodeAttrCode for NodeAttrOpaqueNodeAttr.
func (n *NodeAttrOpaqueNodeAttr) Code() NodeAttrCode {
	return NodeAttrCodeOpaqueNodeAttr
}

func (n *NodeAttrOpaqueNodeAttr) deserialize(b []byte) error {
	n.Data = b
	return nil
}

func (n *NodeAttrOpaqueNodeAttr) serialize() ([]byte, error) {
	b := make([]byte, 4, len(n.Data)+4)
	binary.BigEndian.PutUint16(b[:2], uint16(n.Code()))
	binary.BigEndian.PutUint16(b[2:], uint16(len(n.Data)))
	b = append(b, n.Data...)
	return b, nil
}

// NodeAttrNodeName is a node attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/rfc7752#section-3.3.1.3
type NodeAttrNodeName struct {
	Name string
}

// Code returns the appropriate NodeAttrCode for NodeAttrNodeName.
func (n *NodeAttrNodeName) Code() NodeAttrCode {
	return NodeAttrCodeNodeName
}

func (n *NodeAttrNodeName) deserialize(b []byte) error {
	if len(b) < 1 {
		return nil
	}
	b = reverseByteOrder(b)
	n.Name = string(b)
	return nil
}

func (n *NodeAttrNodeName) serialize() ([]byte, error) {
	return serializeBgpLsStringTLV(uint16(n.Code()), n.Name), nil
}

// NodeAttrIsIsAreaID is a node attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/rfc7752#section-3.3.1.2
type NodeAttrIsIsAreaID struct {
	AreaID uint32
}

// Code returns the appropriate NodeAttrCode for NodeAttrIsIsAreaID.
func (n *NodeAttrIsIsAreaID) Code() NodeAttrCode {
	return NodeAttrCodeIsIsAreaID
}

func (n *NodeAttrIsIsAreaID) deserialize(b []byte) error {
	if len(b) != 4 {
		return &errWithNotification{
			error:   errors.New("invalid length for is-is area ID node attribute"),
			code:    NotifErrCodeUpdateMessage,
			subcode: NotifErrSubcodeMalformedAttr,
		}
	}

	n.AreaID = binary.BigEndian.Uint32(b)
	return nil
}

func (n *NodeAttrIsIsAreaID) serialize() ([]byte, error) {
	b := make([]byte, 8)
	binary.BigEndian.PutUint16(b[:2], uint16(n.Code()))
	binary.BigEndian.PutUint16(b[2:], 4)
	binary.BigEndian.PutUint32(b[4:], n.AreaID)
	return b, nil
}

// NodeAttrLocalIPv4RouterID is a node attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/rfc5305#section-4.3
type NodeAttrLocalIPv4RouterID struct {
	Address net.IP
}

// Code returns the appropriate NodeAttrCode for NodeAttrLocalIPv4RouterID.
func (n *NodeAttrLocalIPv4RouterID) Code() NodeAttrCode {
	return NodeAttrCodeLocalIPv4RouterID
}

func (n *NodeAttrLocalIPv4RouterID) deserialize(b []byte) error {
	addr, err := deserializeIPv4Addr(b)
	if err != nil {
		return err
	}
	n.Address = addr
	return nil
}

func (n *NodeAttrLocalIPv4RouterID) serialize() ([]byte, error) {
	return serializeBgpLsIPv4TLV(uint16(n.Code()), n.Address)
}

// NodeAttrLocalIPv6RouterID is a node attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/rfc5305#section-4.1
type NodeAttrLocalIPv6RouterID struct {
	Address net.IP
}

// Code returns the appropriate NodeAttrCode for NodeAttrLocalIPv6RouterID.
func (n *NodeAttrLocalIPv6RouterID) Code() NodeAttrCode {
	return NodeAttrCodeLocalIPv6RouterID
}

func (n *NodeAttrLocalIPv6RouterID) deserialize(b []byte) error {
	addr, err := deserializeIPv6Addr(b)
	if err != nil {
		return &errWithNotification{
			error:   fmt.Errorf("invalid ipv6 router ID node attribute: %v", err),
			code:    NotifErrCodeUpdateMessage,
			subcode: NotifErrSubcodeMalformedAttr,
		}
	}
	n.Address = addr
	return nil
}

func (n *NodeAttrLocalIPv6RouterID) serialize() ([]byte, error) {
	return serializeBgpLsIPv6TLV(uint16(n.Code()), n.Address)
}

// LinkAttr is a link attribute contained in a bgp-ls attribute.
type LinkAttr interface {
	Code() LinkAttrCode
	serialize() ([]byte, error)
	deserialize(b []byte) error
}

// LinkAttrCode describes the type of node attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/rfc7752#section-3.3.2
type LinkAttrCode uint16

// LinkAttrCode values
const (
	LinkAttrCodeRemoteIPv4RouterID         LinkAttrCode = 1030
	LinkAttrCodeRemoteIPv6RouterID         LinkAttrCode = 1031
	LinkAttrCodeAdminGroup                 LinkAttrCode = 1088
	LinkAttrCodeMaxLinkBandwidth           LinkAttrCode = 1089
	LinkAttrCodeMaxReservableLinkBandwidth LinkAttrCode = 1090
	LinkAttrCodeUnreservedBandwidth        LinkAttrCode = 1091
	LinkAttrCodeTEDefaultMetric            LinkAttrCode = 1092
	LinkAttrCodeLinkProtectionType         LinkAttrCode = 1093
	LinkAttrCodeMplsProtocolMask           LinkAttrCode = 1094
	LinkAttrCodeIgpMetric                  LinkAttrCode = 1095
	LinkAttrCodeSharedRiskLinkGroup        LinkAttrCode = 1096
	LinkAttrCodeOpaqueLinkAttr             LinkAttrCode = 1097
	LinkAttrCodeLinkName                   LinkAttrCode = 1098
)

// LinkAttrRemoteIPv4RouterID is a link attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/rfc5305#section-4.3
type LinkAttrRemoteIPv4RouterID struct {
	Address net.IP
}

// Code returns the appropriate LinkAttrCode for LinkAttrRemoteIPv4RouterID.
func (l *LinkAttrRemoteIPv4RouterID) Code() LinkAttrCode {
	return LinkAttrCodeRemoteIPv4RouterID
}

func (l *LinkAttrRemoteIPv4RouterID) deserialize(b []byte) error {
	addr, err := deserializeIPv4Addr(b)
	if err != nil {
		return &errWithNotification{
			error:   fmt.Errorf("invalid ipv4 router ID link attribute: %v", err),
			code:    NotifErrCodeUpdateMessage,
			subcode: NotifErrSubcodeMalformedAttr,
		}
	}
	l.Address = addr
	return nil
}

func (l *LinkAttrRemoteIPv4RouterID) serialize() ([]byte, error) {
	return serializeBgpLsIPv4TLV(uint16(l.Code()), l.Address)
}

// LinkAttrRemoteIPv6RouterID is a link attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/rfc6119#section-4.1
type LinkAttrRemoteIPv6RouterID struct {
	Address net.IP
}

// Code returns the appropriate LinkAttrCode for LinkAttrRemoteIPv6RouterID.
func (l *LinkAttrRemoteIPv6RouterID) Code() LinkAttrCode {
	return LinkAttrCodeRemoteIPv6RouterID
}

func (l *LinkAttrRemoteIPv6RouterID) deserialize(b []byte) error {
	addr, err := deserializeIPv6Addr(b)
	if err != nil {
		return &errWithNotification{
			error:   fmt.Errorf("invalid ipv6 remote router ID link attribute: %v", err),
			code:    NotifErrCodeUpdateMessage,
			subcode: NotifErrSubcodeMalformedAttr,
		}
	}
	l.Address = addr
	return nil
}

func (l *LinkAttrRemoteIPv6RouterID) serialize() ([]byte, error) {
	return serializeBgpLsIPv6TLV(uint16(l.Code()), l.Address)
}

// LinkAttrAdminGroup is a link attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/rfc5305#section-3.1
type LinkAttrAdminGroup struct {
	Group [32]bool
}

// Code returns the appropriate LinkAttrCode for LinkAttrAdminGroup.
func (l *LinkAttrAdminGroup) Code() LinkAttrCode {
	return LinkAttrCodeAdminGroup
}

/*
	The administrative group sub-TLV contains a 4-octet bit mask assigned
	by the network administrator.  Each set bit corresponds to one
	administrative group assigned to the interface.

	By convention, the least significant bit is referred to as 'group 0',
	and the most significant bit is referred to as 'group 31'.
*/
func (l *LinkAttrAdminGroup) deserialize(b []byte) error {
	if len(b) != 4 {
		return &errWithNotification{
			error:   errors.New("invalid length for admin group link attribute"),
			code:    NotifErrCodeUpdateMessage,
			subcode: NotifErrSubcodeMalformedAttr,
		}
	}

	b = reverseByteOrder(b)
	for i := 0; i < 4; i++ {
		for j, k := 1, 0; j < 256; j, k = j*2, k+1 {
			l.Group[i*8+k] = (b[i] & byte(j)) != 0
		}
	}

	return nil
}

func (l *LinkAttrAdminGroup) serialize() ([]byte, error) {
	b := make([]byte, 4)
	binary.BigEndian.PutUint16(b[:2], uint16(l.Code()))
	binary.BigEndian.PutUint16(b[2:], 4)
	c := make([]byte, 4)
	for i := 0; i < 4; i++ {
		for j, k := 1, 0; j < 256; j, k = j*2, k+1 {
			if l.Group[i*8+k] {
				c[i] += uint8(j)
			}
		}
	}
	c = reverseByteOrder(c)
	b = append(b, c...)
	return b, nil
}

// LinkAttrMaxLinkBandwidth is a link attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/rfc5305#section-3.4
type LinkAttrMaxLinkBandwidth struct {
	BytesPerSecond float32
}

// Code returns the appropriate LinkAttrCode for LinkAttrMaxLinkBandwidth.
func (l *LinkAttrMaxLinkBandwidth) Code() LinkAttrCode {
	return LinkAttrCodeMaxLinkBandwidth
}

func (l *LinkAttrMaxLinkBandwidth) deserialize(b []byte) error {
	if len(b) != 4 {
		return &errWithNotification{
			error:   errors.New("invalid length for max link bandwidth attribute"),
			code:    NotifErrCodeUpdateMessage,
			subcode: NotifErrSubcodeMalformedAttr,
		}
	}

	var f float32
	buff := bytes.NewReader(b)
	err := binary.Read(buff, binary.BigEndian, &f)
	if err != nil {
		return &errWithNotification{
			error:   errors.New("invalid value for max link bandwidth attribute"),
			code:    NotifErrCodeUpdateMessage,
			subcode: NotifErrSubcodeMalformedAttr,
		}
	}
	l.BytesPerSecond = f
	return nil
}

func (l *LinkAttrMaxLinkBandwidth) serialize() ([]byte, error) {
	b := make([]byte, 4)
	binary.BigEndian.PutUint16(b[:2], uint16(l.Code()))
	binary.BigEndian.PutUint16(b[2:], 4)
	f := new(bytes.Buffer)
	err := binary.Write(f, binary.BigEndian, l.BytesPerSecond)
	if err != nil {
		return nil, err
	}

	b = append(b, f.Bytes()...)
	return b, nil
}

// LinkAttrMaxReservableLinkBandwidth is a link attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/rfc5305#section-3.5
type LinkAttrMaxReservableLinkBandwidth struct {
	BytesPerSecond float32
}

// Code returns the appropriate LinkAttrCode for LinkAttrMaxReservableLinkBandwidth.
func (l *LinkAttrMaxReservableLinkBandwidth) Code() LinkAttrCode {
	return LinkAttrCodeMaxReservableLinkBandwidth
}

func (l *LinkAttrMaxReservableLinkBandwidth) deserialize(b []byte) error {
	if len(b) != 4 {
		return &errWithNotification{
			error:   errors.New("invalid length for max reservable link bandwidth attribute"),
			code:    NotifErrCodeUpdateMessage,
			subcode: NotifErrSubcodeMalformedAttr,
		}
	}

	var f float32
	buff := bytes.NewReader(b)
	err := binary.Read(buff, binary.BigEndian, &f)
	if err != nil {
		return &errWithNotification{
			error:   errors.New("invalid value for max reservable link bandwidth attribute"),
			code:    NotifErrCodeUpdateMessage,
			subcode: NotifErrSubcodeMalformedAttr,
		}
	}
	l.BytesPerSecond = f
	return nil
}

func (l *LinkAttrMaxReservableLinkBandwidth) serialize() ([]byte, error) {
	b := make([]byte, 4)
	binary.BigEndian.PutUint16(b[:2], uint16(l.Code()))
	binary.BigEndian.PutUint16(b[2:], 4)
	f := new(bytes.Buffer)
	err := binary.Write(f, binary.BigEndian, l.BytesPerSecond)
	if err != nil {
		return nil, err
	}

	b = append(b, f.Bytes()...)
	return b, nil
}

// LinkAttrUnreservedBandwidth is a link attribute contained in a bgp-ls attribute.
// The index number represents the priority level.
//
// https://tools.ietf.org/html/rfc5305#section-3.6
type LinkAttrUnreservedBandwidth struct {
	BytesPerSecond [8]float32
}

// Code returns the appropriate LinkAttrCode for LinkAttrUnreservedBandwidth.
func (l *LinkAttrUnreservedBandwidth) Code() LinkAttrCode {
	return LinkAttrCodeUnreservedBandwidth
}

func (l *LinkAttrUnreservedBandwidth) deserialize(b []byte) error {
	if len(b) != 32 {
		return &errWithNotification{
			error:   errors.New("invalid length for unreserved bandwidth attribute"),
			code:    NotifErrCodeUpdateMessage,
			subcode: NotifErrSubcodeMalformedAttr,
		}
	}

	for i := 0; i < 32; i = i + 4 {
		var f float32
		buff := bytes.NewReader(b[i : i+4])
		err := binary.Read(buff, binary.BigEndian, &f)
		if err != nil {
			return &errWithNotification{
				error:   errors.New("invalid value for unreserved bandwidth attribute"),
				code:    NotifErrCodeUpdateMessage,
				subcode: NotifErrSubcodeMalformedAttr,
			}
		}
		l.BytesPerSecond[i/4] = f
	}

	return nil
}

func (l *LinkAttrUnreservedBandwidth) serialize() ([]byte, error) {
	b := make([]byte, 4, 36)
	binary.BigEndian.PutUint16(b[:2], uint16(l.Code()))
	binary.BigEndian.PutUint16(b[2:], uint16(32))

	for i := 0; i < 8; i++ {
		f := new(bytes.Buffer)
		err := binary.Write(f, binary.BigEndian, l.BytesPerSecond[i])
		if err != nil {
			return nil, err
		}
		b = append(b, f.Bytes()...)
	}
	return b, nil
}

// LinkAttrTEDefaultMetric is a link attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/rfc5305#section-3.7
type LinkAttrTEDefaultMetric struct {
	Metric uint32
}

// Code returns the appropriate LinkAttrCode for LinkAttrTEDefaultMetric.
func (l *LinkAttrTEDefaultMetric) Code() LinkAttrCode {
	return LinkAttrCodeTEDefaultMetric
}

func (l *LinkAttrTEDefaultMetric) deserialize(b []byte) error {
	if len(b) != 4 {
		return &errWithNotification{
			error:   errors.New("invalid length for te default metric attribute"),
			code:    NotifErrCodeUpdateMessage,
			subcode: NotifErrSubcodeMalformedAttr,
		}
	}

	l.Metric = binary.BigEndian.Uint32(b)
	return nil
}

func (l *LinkAttrTEDefaultMetric) serialize() ([]byte, error) {
	b := make([]byte, 8)
	binary.BigEndian.PutUint16(b[:2], uint16(l.Code()))
	binary.BigEndian.PutUint16(b[2:], uint16(4))
	binary.BigEndian.PutUint32(b[4:], l.Metric)
	return b, nil
}

// LinkAttrLinkProtectionType is a link attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/rfc5307#section-1.2
type LinkAttrLinkProtectionType struct {
	ExtraTraffic        bool
	Unprotected         bool
	Shared              bool
	DedicatedOneToOne   bool
	DedicatedOnePlusOne bool
	Enhanced            bool
}

// Code returns the appropriate LinkAttrCode for LinkAttrLinkProtectionType.
func (l *LinkAttrLinkProtectionType) Code() LinkAttrCode {
	return LinkAttrCodeLinkProtectionType
}

func (l *LinkAttrLinkProtectionType) deserialize(b []byte) error {
	if len(b) != 2 {
		return &errWithNotification{
			error:   errors.New("invalid length for link protection type link attribute"),
			code:    NotifErrCodeUpdateMessage,
			subcode: NotifErrSubcodeMalformedAttr,
		}
	}

	l.ExtraTraffic = (b[0] & 1) != 0
	l.Unprotected = (b[0] & 2) != 0
	l.Shared = (b[0] & 4) != 0
	l.DedicatedOneToOne = (b[0] & 8) != 0
	l.DedicatedOnePlusOne = (b[0] & 16) != 0
	l.Enhanced = (b[0] & 32) != 0

	return nil
}

func (l *LinkAttrLinkProtectionType) serialize() ([]byte, error) {
	b := make([]byte, 6)
	binary.BigEndian.PutUint16(b[:2], uint16(l.Code()))
	binary.BigEndian.PutUint16(b[2:], uint16(2))

	if l.ExtraTraffic {
		b[4]++
	}
	if l.Unprotected {
		b[4] += 2
	}
	if l.Shared {
		b[4] += 4
	}
	if l.DedicatedOneToOne {
		b[4] += 8
	}
	if l.DedicatedOnePlusOne {
		b[4] += 16
	}
	if l.Enhanced {
		b[4] += 32
	}

	return b, nil
}

// LinkAttrMplsProtocolMask is a link attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/rfc7752#section-3.3.2.2
type LinkAttrMplsProtocolMask struct {
	LDP    bool
	RsvpTE bool
}

// Code returns the appropriate LinkAttrCode for LinkAttrMplsProtocolMask.
func (l *LinkAttrMplsProtocolMask) Code() LinkAttrCode {
	return LinkAttrCodeMplsProtocolMask
}

func (l *LinkAttrMplsProtocolMask) deserialize(b []byte) error {
	if len(b) != 1 {
		return &errWithNotification{
			error:   errors.New("invalid length for mpls protocol mask link attribute"),
			code:    NotifErrCodeUpdateMessage,
			subcode: NotifErrSubcodeMalformedAttr,
		}
	}

	l.LDP = (b[0] & 128) != 0
	l.RsvpTE = (b[0] & 64) != 0
	return nil
}

func (l *LinkAttrMplsProtocolMask) serialize() ([]byte, error) {
	b := make([]byte, 5)
	binary.BigEndian.PutUint16(b[:2], uint16(l.Code()))
	binary.BigEndian.PutUint16(b[2:], uint16(1))
	if l.LDP {
		b[4] += 128
	}
	if l.RsvpTE {
		b[4] += 64
	}
	return b, nil
}

// LinkAttrIgpMetric is a link attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/rfc7752#section-3.3.2.4
type LinkAttrIgpMetric struct {
	Metric uint32
	Type   LinkAttrIgpMetricType
}

// LinkAttrIgpMetricType describes the type of igp metric contained in a LinkAttrIgpMetric
//
// https://tools.ietf.org/html/rfc7752#section-3.3.2.4
type LinkAttrIgpMetricType uint8

// LinkAttrIgpMetricType values
const (
	LinkAttrIgpMetricIsIsSmallType LinkAttrIgpMetricType = iota
	LinkAttrIgpMetricOspfType
	LinkAttrIgpMetricIsIsWideType
)

func (l LinkAttrIgpMetricType) String() string {
	switch l {
	case LinkAttrIgpMetricIsIsSmallType:
		return "is-is small"
	case LinkAttrIgpMetricOspfType:
		return "ospf"
	case LinkAttrIgpMetricIsIsWideType:
		return "is-is wide"
	default:
		return "unknown igp metric type"
	}
}

// Code returns the appropriate LinkAttrCode for LinkAttrIgpMetric.
func (l *LinkAttrIgpMetric) Code() LinkAttrCode {
	return LinkAttrCodeIgpMetric
}

/*
	The IGP Metric TLV carries the metric for this link.  The length of
	this TLV is variable, depending on the metric width of the underlying
	protocol.  IS-IS small metrics have a length of 1 octet (the two most
	significant bits are ignored).  OSPF link metrics have a length of 2
	octets.  IS-IS wide metrics have a length of 3 octets.

	 0                   1                   2                   3
	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|              Type             |             Length            |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//      IGP Link Metric (variable length)      //
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
func (l *LinkAttrIgpMetric) deserialize(b []byte) error {
	switch len(b) {
	case 1:
		l.Type = LinkAttrIgpMetricIsIsSmallType
		b = append([]byte{0, 0, 0}, b...)
	case 2:
		l.Type = LinkAttrIgpMetricOspfType
		b = append([]byte{0, 0}, b...)
	case 3:
		l.Type = LinkAttrIgpMetricIsIsWideType
		b = append([]byte{0}, b...)
	default:
		return &errWithNotification{
			error:   errors.New("invalid length for igp metric link attribute"),
			code:    NotifErrCodeUpdateMessage,
			subcode: NotifErrSubcodeMalformedAttr,
		}
	}

	l.Metric = binary.BigEndian.Uint32(b)
	return nil
}

func (l *LinkAttrIgpMetric) serialize() ([]byte, error) {
	b := make([]byte, 4)
	binary.BigEndian.PutUint16(b[:2], uint16(l.Code()))

	c := make([]byte, 4)
	binary.BigEndian.PutUint32(c, l.Metric)
	switch l.Type {
	case LinkAttrIgpMetricIsIsSmallType:
		c = c[3:]
	case LinkAttrIgpMetricOspfType:
		c = c[2:]
	case LinkAttrIgpMetricIsIsWideType:
		c = c[1:]
	}

	binary.BigEndian.PutUint16(b[2:], uint16(len(c)))
	b = append(b, c...)

	return b, nil
}

// LinkAttrSharedRiskLinkGroup is a link attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/rfc7752#section-3.3.2.5
type LinkAttrSharedRiskLinkGroup struct {
	Groups []uint32
}

// Code returns the appropriate LinkAttrCode for LinkAttrSharedRiskLinkGroups.
func (l *LinkAttrSharedRiskLinkGroup) Code() LinkAttrCode {
	return LinkAttrCodeSharedRiskLinkGroup
}

func (l *LinkAttrSharedRiskLinkGroup) deserialize(b []byte) error {
	if len(b)%4 != 0 || len(b) < 4 {
		return &errWithNotification{
			error:   errors.New("invalid length for shared risk link group link attribute"),
			code:    NotifErrCodeUpdateMessage,
			subcode: NotifErrSubcodeMalformedAttr,
		}
	}

	for {
		l.Groups = append(l.Groups, binary.BigEndian.Uint32(b[:4]))
		b = b[4:]
		if len(b) == 0 {
			break
		}
	}

	return nil
}

func (l *LinkAttrSharedRiskLinkGroup) serialize() ([]byte, error) {
	b := make([]byte, 4)
	binary.BigEndian.PutUint16(b[:2], uint16(l.Code()))
	binary.BigEndian.PutUint16(b[2:], uint16(len(l.Groups)*4))
	for _, g := range l.Groups {
		c := make([]byte, 4)
		binary.BigEndian.PutUint32(c, g)
		b = append(b, c...)
	}
	return b, nil
}

// LinkAttrOpaqueLinkAttr is a link attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/rfc7752#section-3.3.2.6
type LinkAttrOpaqueLinkAttr struct {
	Data []byte
}

// Code returns the appropriate LinkAttrCode for LinkAttrOpaqueLinkAttr.
func (l *LinkAttrOpaqueLinkAttr) Code() LinkAttrCode {
	return LinkAttrCodeOpaqueLinkAttr
}

func (l *LinkAttrOpaqueLinkAttr) deserialize(b []byte) error {
	l.Data = b
	return nil
}

func (l *LinkAttrOpaqueLinkAttr) serialize() ([]byte, error) {
	b := make([]byte, 4)
	binary.BigEndian.PutUint16(b[:2], uint16(l.Code()))
	binary.BigEndian.PutUint16(b[2:], uint16(len(l.Data)))
	b = append(b, l.Data...)
	return b, nil
}

// LinkAttrLinkName is a link attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/rfc7752#section-3.3.2.7
type LinkAttrLinkName struct {
	Name string
}

// Code returns the appropriate LinkAttrCode for LinkAttrLinkName.
func (l *LinkAttrLinkName) Code() LinkAttrCode {
	return LinkAttrCodeLinkName
}

func (l *LinkAttrLinkName) deserialize(b []byte) error {
	b = reverseByteOrder(b)
	l.Name = string(b)
	return nil
}

func (l *LinkAttrLinkName) serialize() ([]byte, error) {
	return serializeBgpLsStringTLV(uint16(l.Code()), l.Name), nil
}

// PrefixAttr is a prefix attribute contained in a bgp-ls attribute.
type PrefixAttr interface {
	Code() PrefixAttrCode
	serialize() ([]byte, error)
	deserialize(b []byte) error
}

// PrefixAttrCode describes the type of prefix attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/rfc7752#section-3.3.3
type PrefixAttrCode uint16

// PrefixAttrCode values
const (
	PrefixAttrCodeIgpFlags              PrefixAttrCode = 1152
	PrefixAttrCodeIgpRouteTag           PrefixAttrCode = 1153
	PrefixAttrCodeIgpExtendedRouteTag   PrefixAttrCode = 1154
	PrefixAttrCodePrefixMetric          PrefixAttrCode = 1155
	PrefixAttrCodeOspfForwardingAddress PrefixAttrCode = 1156
	PrefixAttrCodeOpaquePrefixAttribute PrefixAttrCode = 1157
)

// PrefixAttrIgpFlags is a prefix attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/rfc7752#section-3.3.3.1
type PrefixAttrIgpFlags struct {
	IsIsDown          bool
	OspfNoUnicast     bool
	OspfLocalAddress  bool
	OspfPropagateNssa bool
}

// Code returns the appropriate PrefixAttrCode for PrefixAttrIgpFlags.
func (p *PrefixAttrIgpFlags) Code() PrefixAttrCode {
	return PrefixAttrCodeIgpFlags
}

/*
	The IGP Flags TLV contains IS-IS and OSPF flags and bits originally
	assigned to the prefix.  The IGP Flags TLV is encoded as follows:

	  0                   1                   2                   3
	  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 |              Type             |             Length            |
	 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 |D|N|L|P| Resvd.|
	 +-+-+-+-+-+-+-+-+
*/
func (p *PrefixAttrIgpFlags) deserialize(b []byte) error {
	if len(b) != 1 {
		return &errWithNotification{
			error:   errors.New("invalid length for igp flags prefix attribute"),
			code:    NotifErrCodeUpdateMessage,
			subcode: NotifErrSubcodeMalformedAttr,
		}
	}

	p.IsIsDown = (b[0] & 128) != 0
	p.OspfNoUnicast = (b[0] & 64) != 0
	p.OspfLocalAddress = (b[0] & 32) != 0
	p.OspfPropagateNssa = (b[0] & 16) != 0
	return nil
}

func (p *PrefixAttrIgpFlags) serialize() ([]byte, error) {
	b := make([]byte, 5)
	binary.BigEndian.PutUint16(b[:2], uint16(p.Code()))
	binary.BigEndian.PutUint16(b[2:], uint16(1))
	if p.IsIsDown {
		b[4] += 128
	}
	if p.OspfNoUnicast {
		b[4] += 64
	}
	if p.OspfLocalAddress {
		b[4] += 32
	}
	if p.OspfPropagateNssa {
		b[4] += 16
	}
	return b, nil
}

// PrefixAttrIgpRouteTag is a prefix attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/rfc7752#section-3.3.3.2
type PrefixAttrIgpRouteTag struct {
	Tags []uint32
}

// Code returns the appropriate PrefixAttrCode for PrefixAttrIgpRouteTag.
func (p *PrefixAttrIgpRouteTag) Code() PrefixAttrCode {
	return PrefixAttrCodeIgpRouteTag
}

func (p *PrefixAttrIgpRouteTag) deserialize(b []byte) error {
	if len(b)%4 != 0 || len(b) == 0 {
		return &errWithNotification{
			error:   errors.New("invalid length for igp route tag attribute"),
			code:    NotifErrCodeUpdateMessage,
			subcode: NotifErrSubcodeMalformedAttr,
		}
	}

	for {
		p.Tags = append(p.Tags, binary.BigEndian.Uint32(b[:4]))
		b = b[4:]
		if len(b) == 0 {
			break
		}
	}
	return nil
}

func (p *PrefixAttrIgpRouteTag) serialize() ([]byte, error) {
	b := make([]byte, 4)
	binary.BigEndian.PutUint16(b[:2], uint16(p.Code()))
	binary.BigEndian.PutUint16(b[2:], uint16(len(p.Tags)*4))
	for _, t := range p.Tags {
		tag := make([]byte, 4)
		binary.BigEndian.PutUint32(tag, t)
		b = append(b, tag...)
	}

	return b, nil
}

// PrefixAttrIgpExtendedRouteTag is a prefix attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/rfc7752#section-3.3.3.3
type PrefixAttrIgpExtendedRouteTag struct {
	Tags []uint64
}

// Code returns the appropriate PrefixAttrCode for PrefixAttrIgpExtendedRouteTag.
func (p *PrefixAttrIgpExtendedRouteTag) Code() PrefixAttrCode {
	return PrefixAttrCodeIgpExtendedRouteTag
}

func (p *PrefixAttrIgpExtendedRouteTag) deserialize(b []byte) error {
	if len(b)%8 != 0 || len(b) == 0 {
		return &errWithNotification{
			error:   errors.New("invalid length for extended igp route tag prefix attribute"),
			code:    NotifErrCodeUpdateMessage,
			subcode: NotifErrSubcodeMalformedAttr,
		}
	}

	for {
		p.Tags = append(p.Tags, binary.BigEndian.Uint64(b[:8]))
		b = b[8:]
		if len(b) == 0 {
			break
		}
	}
	return nil
}

func (p *PrefixAttrIgpExtendedRouteTag) serialize() ([]byte, error) {
	b := make([]byte, 4)
	binary.BigEndian.PutUint16(b[:2], uint16(p.Code()))
	binary.BigEndian.PutUint16(b[2:], uint16(len(p.Tags)*8))
	for _, t := range p.Tags {
		tag := make([]byte, 8)
		binary.BigEndian.PutUint64(tag, t)
		b = append(b, tag...)
	}

	return b, nil
}

// PrefixAttrPrefixMetric is a prefix attributed contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/rfc7752#section-3.3.3.4
type PrefixAttrPrefixMetric struct {
	Metric uint32
}

// Code returns the appropriate PrefixAttrCode for PrefixAttrPrefixMetric.
func (p *PrefixAttrPrefixMetric) Code() PrefixAttrCode {
	return PrefixAttrCodePrefixMetric
}

func (p *PrefixAttrPrefixMetric) deserialize(b []byte) error {
	if len(b) != 4 {
		return &errWithNotification{
			error:   errors.New("invalid length for prefix metric prefix attribute"),
			code:    NotifErrCodeUpdateMessage,
			subcode: NotifErrSubcodeMalformedAttr,
		}
	}

	p.Metric = binary.BigEndian.Uint32(b)
	return nil
}

func (p *PrefixAttrPrefixMetric) serialize() ([]byte, error) {
	b := make([]byte, 8)
	binary.BigEndian.PutUint16(b[:2], uint16(p.Code()))
	binary.BigEndian.PutUint16(b[2:], uint16(4))
	binary.BigEndian.PutUint32(b[4:], p.Metric)
	return b, nil
}

// PrefixAttrOspfForwardingAddress is a prefix attribute contained in a bgp-ls attribute.
//
// https://tools.ietf.org/html/rfc7752#section-3.3.3.5
type PrefixAttrOspfForwardingAddress struct {
	Address net.IP
}

// Code returns the appropriate PrefixAttrCode for PrefixAttrOspfForwardingAddress.
func (p *PrefixAttrOspfForwardingAddress) Code() PrefixAttrCode {
	return PrefixAttrCodeOspfForwardingAddress
}

func (p *PrefixAttrOspfForwardingAddress) deserialize(b []byte) error {
	if len(b) != 4 && len(b) != 16 {
		return &errWithNotification{
			error:   errors.New("invalid length for ospf forwarding address attribute"),
			code:    NotifErrCodeUpdateMessage,
			subcode: NotifErrSubcodeMalformedAttr,
		}
	}

	addr, err := bytesToIPAddress(b)
	if err != nil {
		return err
	}
	p.Address = addr
	return nil
}

func (p *PrefixAttrOspfForwardingAddress) serialize() ([]byte, error) {
	if p.Address.To4() == nil {
		if p.Address.To16() == nil {
			return nil, errors.New("invalid ip address in ospf forwarding address prefix attribute")
		}
		return serializeBgpLsIPv6TLV(uint16(p.Code()), p.Address)
	}
	return serializeBgpLsIPv4TLV(uint16(p.Code()), p.Address)
}

// PrefixAttrOpaquePrefixAttribute is a prefix attribute contained in a bgp-ls attribute.
type PrefixAttrOpaquePrefixAttribute struct {
	Data []byte
}

// Code returns the appropriate PrefixAttrCode for PrefixAttrOpaquePrefixAttribute.
func (p *PrefixAttrOpaquePrefixAttribute) Code() PrefixAttrCode {
	return PrefixAttrCodeOpaquePrefixAttribute
}

func (p *PrefixAttrOpaquePrefixAttribute) deserialize(b []byte) error {
	p.Data = b
	return nil
}

func (p *PrefixAttrOpaquePrefixAttribute) serialize() ([]byte, error) {
	b := make([]byte, 4)
	binary.BigEndian.PutUint16(b[:2], uint16(p.Code()))
	binary.BigEndian.PutUint16(b[2:], uint16(len(p.Data)))
	b = append(b, p.Data...)
	return b, nil
}

// PathAttrMpReach is a path attribute.
//
// https://tools.ietf.org/html/rfc4760#section-3
type PathAttrMpReach struct {
	f    PathAttrFlags
	Afi  MultiprotoAfi
	Safi MultiprotoSafi
	Nlri []LinkStateNlri
}

/*
	+---------------------------------------------------------+
	| Address Family Identifier (2 octets)                    |
	+---------------------------------------------------------+
	| Subsequent Address Family Identifier (1 octet)          |
	+---------------------------------------------------------+
	| Length of Next Hop Network Address (1 octet)            |
	+---------------------------------------------------------+
	| Network Address of Next Hop (variable)                  |
	+---------------------------------------------------------+
	| Reserved (1 octet)                                      |
	+---------------------------------------------------------+
	| Network Layer Reachability Information (variable)       |
	+---------------------------------------------------------+
*/
func (p *PathAttrMpReach) deserialize(f PathAttrFlags, b []byte) error {
	p.f = f

	tooShortErr := &errWithNotification{
		error:   errors.New("mp reach path attribute too short"),
		code:    NotifErrCodeUpdateMessage,
		subcode: NotifErrSubcodeMalformedAttr,
	}

	if len(b) < 5 {
		return tooShortErr
	}

	p.Afi = MultiprotoAfi(binary.BigEndian.Uint16(b[:2]))
	p.Safi = MultiprotoSafi(b[2])
	nhLen := int(b[3])
	b = b[4:]
	if len(b) < nhLen+1 {
		return tooShortErr
	}
	b = b[nhLen+1:]

	nlri, err := deserializeLinkStateNlri(p.Afi, p.Safi, b)
	if err != nil {
		return err
	}
	for _, n := range nlri {
		p.Nlri = append(p.Nlri, n)
	}

	return nil
}

func deserializeLinkStateNlri(afi MultiprotoAfi, safi MultiprotoSafi, b []byte) ([]LinkStateNlri, error) {
	if afi == BgpLsAfi || safi == BgpLsSafi {
		return nil, &errWithNotification{
			error:   errors.New("non bgp-ls afi/safi"),
			code:    NotifErrCodeUpdateMessage,
			subcode: NotifErrSubcodeMalformedAttr,
		}
	}

	if len(b) == 0 {
		return nil, nil
	}

	tooShortErr := &errWithNotification{
		error:   errors.New("link state nlri attribute too short"),
		code:    NotifErrCodeUpdateMessage,
		subcode: NotifErrSubcodeMalformedAttr,
	}

	if len(b) < 4 {
		return nil, tooShortErr
	}

	nlri := make([]LinkStateNlri, 0)

	for {
		lsNlriType := binary.BigEndian.Uint16(b[:2])
		lsNlriLen := int(binary.BigEndian.Uint16(b[2:4]))
		b = b[4:]

		if len(b) < lsNlriLen {
			return nil, tooShortErr
		}

		NlriToDecode := b[:lsNlriLen]
		b = b[lsNlriLen:]

		switch lsNlriType {
		case uint16(LinkStateNlriNodeType):
			node := &LinkStateNlriNode{}
			err := node.deserialize(NlriToDecode)
			if err != nil {
				return nil, err
			}
			nlri = append(nlri, node)
		case uint16(LinkStateNlriLinkType):
			link := &LinkStateNlriLink{}
			err := link.deserialize(NlriToDecode)
			if err != nil {
				return nil, err
			}
			nlri = append(nlri, link)
		case uint16(LinkStateNlriIPv4PrefixType):
			prefix := &LinkStateNlriIPv4Prefix{}
			err := prefix.deserialize(NlriToDecode)
			if err != nil {
				return nil, err
			}
			nlri = append(nlri, prefix)
		case uint16(LinkStateNlriIPv6PrefixType):
			prefix := &LinkStateNlriIPv6Prefix{}
			err := prefix.deserialize(NlriToDecode)
			if err != nil {
				return nil, err
			}
			nlri = append(nlri, prefix)
		default:
			return nil, &errWithNotification{
				error:   errors.New("unknown link state nlri type"),
				code:    NotifErrCodeUpdateMessage,
				subcode: NotifErrSubcodeMalformedAttr,
			}
		}

		if len(b) == 0 {
			break
		}
	}

	return nlri, nil
}

func (p *PathAttrMpReach) serialize() ([]byte, error) {
	p.f = PathAttrFlags{
		Optional: true,
	}

	b := make([]byte, 0, 512)
	for _, n := range p.Nlri {
		nlri, err := n.serialize()
		if err != nil {
			return nil, err
		}
		b = append(b, nlri...)
	}

	// prepend reserved byte, nh len, safi, afi
	b = append([]byte{0}, b...)
	b = append([]byte{0}, b...)
	b = append([]byte{byte(p.Safi)}, b...)
	afi := make([]byte, 2)
	binary.BigEndian.PutUint16(afi, uint16(p.Afi))
	b = append(afi, b...)

	if len(b) > math.MaxUint8 {
		p.f.ExtendedLength = true
	}
	flags, err := p.f.serialize()
	if err != nil {
		return nil, err
	}

	c := make([]byte, 2)
	c[0] = flags
	c[1] = byte(PathAttrMpReachType)

	if p.f.ExtendedLength {
		attrLen := make([]byte, 2)
		binary.BigEndian.PutUint16(attrLen, uint16(len(b)))
		c = append(c, attrLen...)
	} else {
		c = append(c, []byte{uint8(len(b))}...)
	}

	c = append(c, b...)

	return c, nil
}

// Flags returns the PathAttrFlags for PathAttrMpReach.
func (p *PathAttrMpReach) Flags() PathAttrFlags {
	return p.f
}

// Type returns the appropriate PathAttrType for PathAttrMpReach.
func (p *PathAttrMpReach) Type() PathAttrType {
	return PathAttrMpReachType
}

// PathAttrMpUnreach is a path attribute.
//
// https://tools.ietf.org/html/rfc4760#section-4
type PathAttrMpUnreach struct {
	f    PathAttrFlags
	Afi  MultiprotoAfi
	Safi MultiprotoSafi
	Nlri []LinkStateNlri
}

/*
	+---------------------------------------------------------+
	| Address Family Identifier (2 octets)                    |
	+---------------------------------------------------------+
	| Subsequent Address Family Identifier (1 octet)          |
	+---------------------------------------------------------+
	| Withdrawn Routes (variable)                             |
	+---------------------------------------------------------+
*/
func (p *PathAttrMpUnreach) deserialize(f PathAttrFlags, b []byte) error {
	p.f = f

	tooShortErr := &errWithNotification{
		error:   errors.New("mp unreach path attribute too short"),
		code:    NotifErrCodeUpdateMessage,
		subcode: NotifErrSubcodeMalformedAttr,
	}

	if len(b) < 3 {
		return tooShortErr
	}

	p.Afi = MultiprotoAfi(binary.BigEndian.Uint16(b[:2]))
	p.Safi = MultiprotoSafi(b[2])
	b = b[3:]

	nlri, err := deserializeLinkStateNlri(p.Afi, p.Safi, b)
	if err != nil {
		return err
	}
	for _, n := range nlri {
		p.Nlri = append(p.Nlri, n)
	}

	return nil
}

func (p *PathAttrMpUnreach) serialize() ([]byte, error) {
	p.f = PathAttrFlags{
		Optional: true,
	}

	b := make([]byte, 0, 512)
	for _, n := range p.Nlri {
		nlri, err := n.serialize()
		if err != nil {
			return nil, err
		}
		b = append(b, nlri...)
	}

	// prepend safi and afi
	b = append([]byte{byte(p.Safi)}, b...)
	afi := make([]byte, 2)
	binary.BigEndian.PutUint16(afi, uint16(p.Afi))
	b = append(afi, b...)

	if len(b) > math.MaxUint8 {
		p.f.ExtendedLength = true
	}
	flags, err := p.f.serialize()
	if err != nil {
		return nil, err
	}

	c := make([]byte, 2)
	c[0] = flags
	c[1] = byte(PathAttrMpUnreachType)

	if p.f.ExtendedLength {
		attrLen := make([]byte, 2)
		binary.BigEndian.PutUint16(attrLen, uint16(len(b)))
		c = append(c, attrLen...)
	} else {
		c = append(c, []byte{uint8(len(b))}...)
	}

	c = append(c, b...)

	return c, nil
}

// Flags returns the PathAttrFlags for PathAttrMpUnreach.
func (p *PathAttrMpUnreach) Flags() PathAttrFlags {
	return p.f
}

// Type returns the appropriate PathAttrType for PathAttrMpUnreach.
func (p *PathAttrMpUnreach) Type() PathAttrType {
	return PathAttrMpUnreachType
}

// LinkStateNlri contains nlri of link-state type.
type LinkStateNlri interface {
	Type() LinkStateNlriType
	Afi() MultiprotoAfi
	Safi() MultiprotoSafi
	serialize() ([]byte, error)
	deserialize(b []byte) error
}

// LinkStateNlriType describes the type of bgp-ls nlri.
//
// https://tools.ietf.org/html/rfc7752#section-3.2 figure 6
type LinkStateNlriType uint16

// LinkStateNlriType values
const (
	_ LinkStateNlriType = iota
	LinkStateNlriNodeType
	LinkStateNlriLinkType
	LinkStateNlriIPv4PrefixType
	LinkStateNlriIPv6PrefixType
)

// LinkStateNlriProtocolID describes the protocol of the link state nlri.
//
// https://tools.ietf.org/html/rfc7752#section-3.2 table 2
type LinkStateNlriProtocolID uint8

// LinkStateNlriProtocolID values
const (
	_ LinkStateNlriProtocolID = iota
	LinkStateNlriIsIsL1ProtocolID
	LinkStateNlriIsIsL2ProtocolID
	LinkStateNlriOSPFv2ProtocolID
	LinkStateNlriDirectProtocolID
	LinkStateNlriStaticProtocolID
	LinkStateNlriOSPFv3ProtocolID
	// https://tools.ietf.org/html/draft-ietf-idr-bgpls-segment-routing-epe-14#section-8
	LinkStateNlriBgpProtocolID
)

// LinkStateNlriNode is a link state nlri.
//
// https://tools.ietf.org/html/rfc7752#section-3.2 figure 7
type LinkStateNlriNode struct {
	ProtocolID           LinkStateNlriProtocolID
	ID                   uint64
	LocalNodeDescriptors []NodeDescriptor
}

// Type returns the appropriate LinkStateNlriType for LinkStateNlriNode
func (n *LinkStateNlriNode) Type() LinkStateNlriType {
	return LinkStateNlriNodeType
}

// Afi returns the appropriate MultiprotoAfi for LinkStateNlriNode
func (n *LinkStateNlriNode) Afi() MultiprotoAfi {
	return BgpLsAfi
}

// Safi returns the appropriate MultiprotoAfi for LinkStateNlriNode
func (n *LinkStateNlriNode) Safi() MultiprotoSafi {
	return BgpLsSafi
}

// LinkStateNlriDescriptorCode describes the type of link state nlri.
type LinkStateNlriDescriptorCode uint16

// LinkStateNlriDescriptorCode values
const (
	LinkStateNlriLocalNodeDescriptorsDescriptorCode  LinkStateNlriDescriptorCode = 256
	LinkStateNlriRemoteNodeDescriptorsDescriptorCode LinkStateNlriDescriptorCode = 257
)

func deserializeNodeDescriptors(protocolID LinkStateNlriProtocolID, b []byte) ([]NodeDescriptor, error) {
	descriptors := make([]NodeDescriptor, 0)

	tooShortErr := &errWithNotification{
		error:   errors.New("link state node descriptors too short"),
		code:    NotifErrCodeUpdateMessage,
		subcode: NotifErrSubcodeMalformedAttr,
	}

	for {
		if len(b) < 4 {
			return nil, tooShortErr
		}

		descriptorType := binary.BigEndian.Uint16(b[:2])
		descriptorLen := int(binary.BigEndian.Uint16(b[2:4]))
		if len(b[4:]) < descriptorLen {
			return nil, tooShortErr
		}

		descriptorToDecode := b[4 : 4+descriptorLen]
		b = b[4+descriptorLen:]

		switch descriptorType {
		case uint16(NodeDescriptorCodeASN):
			descriptor := &NodeDescriptorASN{}
			err := descriptor.deserialize(descriptorToDecode)
			if err != nil {
				return nil, err
			}
			descriptors = append(descriptors, descriptor)
		case uint16(NodeDescriptorCodeBgpLsID):
			descriptor := &NodeDescriptorBgpLsID{}
			err := descriptor.deserialize(descriptorToDecode)
			if err != nil {
				return nil, err
			}
			descriptors = append(descriptors, descriptor)
		case uint16(NodeDescriptorCodeOspfAreaID):
			descriptor := &NodeDescriptorOspfAreaID{}
			err := descriptor.deserialize(descriptorToDecode)
			if err != nil {
				return nil, err
			}
			descriptors = append(descriptors, descriptor)
		case uint16(NodeDescriptorCodeIgpRouterID):
			/*
				IGP Router-ID:  Opaque value.  This is a mandatory TLV.  For an IS-IS
				non-pseudonode, this contains a 6-octet ISO Node-ID (ISO system-
				ID).  For an IS-IS pseudonode corresponding to a LAN, this
				contains the 6-octet ISO Node-ID of the Designated Intermediate
				System (DIS) followed by a 1-octet, nonzero PSN identifier (7
				octets in total).  For an OSPFv2 or OSPFv3 non-pseudonode, this
				contains the 4-octet Router-ID.  For an OSPFv2 pseudonode
				representing a LAN, this contains the 4-octet Router-ID of the
				Designated Router (DR) followed by the 4-octet IPv4 address of the
				DR's interface to the LAN (8 octets in total).  Similarly, for an
				OSPFv3 pseudonode, this contains the 4-octet Router-ID of the DR
				followed by the 4-octet interface identifier of the DR's interface
				to the LAN (8 octets in total).  The TLV size in combination with
				the protocol identifier enables the decoder to determine the type
				of the node.
			*/
			if protocolID == LinkStateNlriIsIsL1ProtocolID || protocolID == LinkStateNlriIsIsL2ProtocolID {
				switch len(descriptorToDecode) {
				case 6:
					descriptor := &NodeDescriptorIgpRouterIDIsIsNonPseudo{}
					err := descriptor.deserialize(descriptorToDecode)
					if err != nil {
						return nil, err
					}
					descriptors = append(descriptors, descriptor)
				case 7:
					descriptor := &NodeDescriptorIgpRouterIDIsIsPseudo{}
					err := descriptor.deserialize(descriptorToDecode)
					if err != nil {
						return nil, err
					}
					descriptors = append(descriptors, descriptor)
				default:
					return nil, &errWithNotification{
						error:   errors.New("link state node igp router id node descriptor has protocol is-is but invalid length"),
						code:    NotifErrCodeUpdateMessage,
						subcode: NotifErrSubcodeMalformedAttr,
					}
				}
			} else if protocolID == LinkStateNlriOSPFv2ProtocolID || protocolID == LinkStateNlriOSPFv3ProtocolID {
				switch len(descriptorToDecode) {
				case 4:
					descriptor := &NodeDescriptorIgpRouterIDOspfNonPseudo{}
					err := descriptor.deserialize(descriptorToDecode)
					if err != nil {
						return nil, err
					}
					descriptors = append(descriptors, descriptor)
				case 8:
					descriptor := &NodeDescriptorIgpRouterIDOspfPseudo{}
					err := descriptor.deserialize(descriptorToDecode)
					if err != nil {
						return nil, err
					}
					descriptors = append(descriptors, descriptor)
				default:
					return nil, &errWithNotification{
						error:   errors.New("link state node igp router id node descriptor has protocol OSPF but invalid length"),
						code:    NotifErrCodeUpdateMessage,
						subcode: NotifErrSubcodeMalformedAttr,
					}
				}
			} else {
				return nil, &errWithNotification{
					error:   errors.New("link state node igp router id should not be present with static or direct protocol"),
					code:    NotifErrCodeUpdateMessage,
					subcode: NotifErrSubcodeMalformedAttr,
				}
			}
		case uint16(NodeDescriptorCodeBgpRouterID):
			descriptor := &NodeDescriptorBgpRouterID{}
			err := descriptor.deserialize(descriptorToDecode)
			if err != nil {
				return nil, err
			}
			descriptors = append(descriptors, descriptor)
		case uint16(NodeDescriptorCodeMemberASN):
			descriptor := &NodeDescriptorMemberASN{}
			err := descriptor.deserialize(descriptorToDecode)
			if err != nil {
				return nil, err
			}
			descriptors = append(descriptors, descriptor)
		default:
			return nil, &errWithNotification{
				error:   errors.New("unknown link state node descriptor code"),
				code:    NotifErrCodeUpdateMessage,
				subcode: NotifErrSubcodeMalformedAttr,
			}
		}

		if len(b) == 0 {
			break
		}
	}

	return descriptors, nil
}

/*
	0                   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+
	|  Protocol-ID  |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                           Identifier                          |
	|                            (64 bits)                          |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//                Local Node Descriptors (variable)            //
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
func (n *LinkStateNlriNode) deserialize(b []byte) error {
	tooShortErr := &errWithNotification{
		error:   errors.New("link state node nlri too short"),
		code:    NotifErrCodeUpdateMessage,
		subcode: NotifErrSubcodeMalformedAttr,
	}

	if len(b) < 13 {
		return tooShortErr
	}

	n.ProtocolID = LinkStateNlriProtocolID(b[0])
	n.ID = binary.BigEndian.Uint64(b[1:9])
	b = b[9:]

	// local node descriptors TLV
	if binary.BigEndian.Uint16(b[:2]) != uint16(LinkStateNlriLocalNodeDescriptorsDescriptorCode) {
		return &errWithNotification{
			error:   errors.New("link state node nlri local node descriptors tlv type invalid"),
			code:    NotifErrCodeUpdateMessage,
			subcode: NotifErrSubcodeMalformedAttr,
		}
	}
	// len of local node descriptors, no other descriptors should follow
	if int(binary.BigEndian.Uint16(b[2:4])) != len(b[4:]) {
		return &errWithNotification{
			error:   errors.New("link state node nlri local node descriptors tlv length invalid"),
			code:    NotifErrCodeUpdateMessage,
			subcode: NotifErrSubcodeMalformedAttr,
		}
	}
	b = b[4:]

	descriptors, err := deserializeNodeDescriptors(n.ProtocolID, b)
	if err != nil {
		return err
	}
	n.LocalNodeDescriptors = descriptors

	return nil
}

func (n *LinkStateNlriNode) serialize() ([]byte, error) {
	nodes := make([]byte, 0, 512)
	for _, d := range n.LocalNodeDescriptors {
		e, err := d.serialize()
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, e...)
	}

	b := make([]byte, 17)
	binary.BigEndian.PutUint16(b[:2], uint16(LinkStateNlriNodeType))
	binary.BigEndian.PutUint16(b[2:], uint16(len(nodes)+13))
	b[4] = uint8(n.ProtocolID)
	binary.BigEndian.PutUint64(b[5:], n.ID)
	binary.BigEndian.PutUint16(b[13:], uint16(LinkStateNlriLocalNodeDescriptorsDescriptorCode))
	binary.BigEndian.PutUint16(b[15:], uint16(len(nodes)))
	b = append(b, nodes...)

	return b, nil
}

// NodeDescriptor is a bgp-ls nlri node descriptor.
//
// https://tools.ietf.org/html/rfc7752#section-3.2.1
type NodeDescriptor interface {
	Code() NodeDescriptorCode
	serialize() ([]byte, error)
	deserialize(b []byte) error
}

// NodeDescriptorCode describes the type of node descriptor.
//
// https://tools.ietf.org/html/rfc7752#section-3.2.1.4
type NodeDescriptorCode uint16

// NodeDescriptorCode values
const (
	NodeDescriptorCodeASN         NodeDescriptorCode = 512
	NodeDescriptorCodeBgpLsID     NodeDescriptorCode = 513
	NodeDescriptorCodeOspfAreaID  NodeDescriptorCode = 514
	NodeDescriptorCodeIgpRouterID NodeDescriptorCode = 515
	// https://tools.ietf.org/html/draft-ietf-idr-bgpls-segment-routing-epe-14#section-4.1
	NodeDescriptorCodeBgpRouterID NodeDescriptorCode = 516
	NodeDescriptorCodeMemberASN   NodeDescriptorCode = 517
)

// NodeDescriptorASN is a node descriptor contained in a bgp-ls node nlri.
//
// https://tools.ietf.org/html/rfc7752#section-3.2.1.4
type NodeDescriptorASN struct {
	ASN uint32
}

// Code returns the appropriate NodeDescriptorCode for NodeDescriptorASN.
func (n *NodeDescriptorASN) Code() NodeDescriptorCode {
	return NodeDescriptorCodeASN
}

func (n *NodeDescriptorASN) deserialize(b []byte) error {
	if len(b) != 4 {
		return &errWithNotification{
			error:   errors.New("invalid ASN node descriptor length"),
			code:    NotifErrCodeUpdateMessage,
			subcode: NotifErrSubcodeOptionalAttrError,
		}
	}

	n.ASN = binary.BigEndian.Uint32(b)
	return nil
}

func (n *NodeDescriptorASN) serialize() ([]byte, error) {
	b := make([]byte, 8)
	binary.BigEndian.PutUint16(b[:2], uint16(n.Code()))
	binary.BigEndian.PutUint16(b[2:], uint16(4))
	binary.BigEndian.PutUint32(b[4:], n.ASN)
	return b, nil
}

// NodeDescriptorBgpLsID is a node descriptor contained in a bgp-ls node nlri.
//
// https://tools.ietf.org/html/rfc7752#section-3.2.1.4
type NodeDescriptorBgpLsID struct {
	ID uint32
}

// Code returns the appropriate NodeDescriptorCode for NodeDescriptorBgpLsID.
func (n *NodeDescriptorBgpLsID) Code() NodeDescriptorCode {
	return NodeDescriptorCodeBgpLsID
}

func (n *NodeDescriptorBgpLsID) deserialize(b []byte) error {
	if len(b) != 4 {
		return &errWithNotification{
			error:   errors.New("invalid BGP LS ID node descriptor length"),
			code:    NotifErrCodeUpdateMessage,
			subcode: NotifErrSubcodeOptionalAttrError,
		}
	}

	n.ID = binary.BigEndian.Uint32(b)
	return nil
}

func (n *NodeDescriptorBgpLsID) serialize() ([]byte, error) {
	b := make([]byte, 8)
	binary.BigEndian.PutUint16(b[:2], uint16(n.Code()))
	binary.BigEndian.PutUint16(b[2:], uint16(4))
	binary.BigEndian.PutUint32(b[4:], n.ID)
	return b, nil
}

// NodeDescriptorOspfAreaID is a node descriptor contained in a bgp-ls node nlri.
//
// https://tools.ietf.org/html/rfc7752#section-3.2.1.4
type NodeDescriptorOspfAreaID struct {
	ID uint32
}

// Code returns the appropriate NodeDescriptorCode for NodeDescriptorOspfAreaID.
func (n *NodeDescriptorOspfAreaID) Code() NodeDescriptorCode {
	return NodeDescriptorCodeOspfAreaID
}

func (n *NodeDescriptorOspfAreaID) deserialize(b []byte) error {
	if len(b) != 4 {
		return &errWithNotification{
			error:   errors.New("invalid OSPF Area ID node descriptor length"),
			code:    NotifErrCodeUpdateMessage,
			subcode: NotifErrSubcodeOptionalAttrError,
		}
	}

	n.ID = binary.BigEndian.Uint32(b)
	return nil
}

func (n *NodeDescriptorOspfAreaID) serialize() ([]byte, error) {
	b := make([]byte, 8)
	binary.BigEndian.PutUint16(b[:2], uint16(n.Code()))
	binary.BigEndian.PutUint16(b[2:], uint16(4))
	binary.BigEndian.PutUint32(b[4:], n.ID)
	return b, nil
}

// NodeDescriptorIgpRouterIDType describes the type of igp router id.
//
// https://tools.ietf.org/html/rfc7752#section-3.2.1.4
type NodeDescriptorIgpRouterIDType uint8

// NodeDescriptorIgRouterIDType values
const (
	NodeDescriptorIgpRouterIDIsIsNonPseudoType NodeDescriptorIgpRouterIDType = iota
	NodeDescriptorIgpRouterIDIsIsPseudoType
	NodeDescriptorIgpRouterIDOspfNonPseudoType
	NodeDescriptorIgpRouterIDOspfPseudoType
)

// NodeDescriptorIgpRouterIDIsIsNonPseudo is a node descriptor contained in a bgp-ls node nlri.
//
// https://tools.ietf.org/html/rfc7752#section-3.2.1.4
type NodeDescriptorIgpRouterIDIsIsNonPseudo struct {
	IsoNodeID uint64
}

// Code returns the appropriate NodeDescriptorCode for NodeDescriptorIgpRouterIDIsIsNonPseudo.
func (n *NodeDescriptorIgpRouterIDIsIsNonPseudo) Code() NodeDescriptorCode {
	return NodeDescriptorCodeIgpRouterID
}

func (n *NodeDescriptorIgpRouterIDIsIsNonPseudo) deserialize(b []byte) error {
	if len(b) != 6 {
		return &errWithNotification{
			error:   errors.New("node descriptor igp router ID is-is non-pseudo invalid length"),
			code:    NotifErrCodeUpdateMessage,
			subcode: NotifErrSubcodeMalformedAttr,
		}
	}

	b = append([]byte{0, 0}, b...)
	n.IsoNodeID = binary.BigEndian.Uint64(b)
	return nil
}

func (n *NodeDescriptorIgpRouterIDIsIsNonPseudo) serialize() ([]byte, error) {
	b := make([]byte, 4)
	binary.BigEndian.PutUint16(b[:2], uint16(n.Code()))
	binary.BigEndian.PutUint16(b[2:], uint16(6))
	c := make([]byte, 8)
	binary.BigEndian.PutUint64(c, n.IsoNodeID)
	// 2 bytes are padded 0s
	b = append(b, c[2:]...)
	return b, nil
}

// NodeDescriptorIgpRouterIDIsIsPseudo is a node descriptor contained in a bgp-ls node nlri.
//
// https://tools.ietf.org/html/rfc7752#section-3.2.1.4
type NodeDescriptorIgpRouterIDIsIsPseudo struct {
	IsoNodeID uint64
	PsnID     uint8
}

// Code returns the appropriate NodeDescriptorCode for NodeDescriptorIgpRouterIDIsIsPseudo.
func (n *NodeDescriptorIgpRouterIDIsIsPseudo) Code() NodeDescriptorCode {
	return NodeDescriptorCodeIgpRouterID
}

func (n *NodeDescriptorIgpRouterIDIsIsPseudo) deserialize(b []byte) error {
	if len(b) != 7 {
		return &errWithNotification{
			error:   errors.New("node descriptor igp router ID is-is pseudo invalid length"),
			code:    NotifErrCodeUpdateMessage,
			subcode: NotifErrSubcodeMalformedAttr,
		}
	}

	b = append([]byte{0, 0}, b...)
	n.IsoNodeID = binary.BigEndian.Uint64(b[:8])
	n.PsnID = b[8]
	return nil
}

func (n *NodeDescriptorIgpRouterIDIsIsPseudo) serialize() ([]byte, error) {
	b := make([]byte, 4)
	binary.BigEndian.PutUint16(b[:2], uint16(n.Code()))
	binary.BigEndian.PutUint16(b[2:], uint16(7))
	c := make([]byte, 8)
	binary.BigEndian.PutUint64(c, n.IsoNodeID)
	// 2 bytes are padded 0s
	b = append(b, c[2:]...)
	b = append(b, uint8(n.PsnID))
	return b, nil
}

// NodeDescriptorIgpRouterIDOspfNonPseudo is a node descriptor contained in a bgp-ls node nlri.
//
// https://tools.ietf.org/html/rfc7752#section-3.2.1.4
type NodeDescriptorIgpRouterIDOspfNonPseudo struct {
	RouterID net.IP
}

// Code returns the appropriate NodeDescriptorCode for NodeDescriptorIgpRouterIDOspfNonPseudo.
func (n *NodeDescriptorIgpRouterIDOspfNonPseudo) Code() NodeDescriptorCode {
	return NodeDescriptorCodeIgpRouterID
}

func (n *NodeDescriptorIgpRouterIDOspfNonPseudo) deserialize(b []byte) error {
	addr, err := deserializeIPv4Addr(b)
	if err != nil {
		return err
	}
	n.RouterID = addr
	return nil
}

func (n *NodeDescriptorIgpRouterIDOspfNonPseudo) serialize() ([]byte, error) {
	return serializeBgpLsIPv4TLV(uint16(n.Code()), n.RouterID)
}

// NodeDescriptorIgpRouterIDOspfPseudo is a node descriptor contained in a bgp-ls node nlri.
//
// https://tools.ietf.org/html/rfc7752#section-3.2.1.4
type NodeDescriptorIgpRouterIDOspfPseudo struct {
	DrRouterID       net.IP
	DrInterfaceToLAN net.IP
}

// Code returns the appropriate NodeDescriptorCode for NodeDescriptorIgpRouterIDOspfPseudo.
func (n *NodeDescriptorIgpRouterIDOspfPseudo) Code() NodeDescriptorCode {
	return NodeDescriptorCodeIgpRouterID
}

func (n *NodeDescriptorIgpRouterIDOspfPseudo) deserialize(b []byte) error {
	if len(b) != 8 {
		return &errWithNotification{
			error:   errors.New("node descriptor igp router ID OSPF pseudo invalid length"),
			code:    NotifErrCodeUpdateMessage,
			subcode: NotifErrSubcodeMalformedAttr,
		}
	}

	drRouterID, err := bytesToIPAddress(b[:4])
	if err != nil {
		return &errWithNotification{
			error:   fmt.Errorf("error deserializing drRouterID in igp router ID node descriptor: %v", err),
			code:    NotifErrCodeUpdateMessage,
			subcode: NotifErrSubcodeMalformedAttr,
		}
	}
	n.DrRouterID = drRouterID

	drInterfaceToLAN, err := bytesToIPAddress(b[4:])
	if err != nil {
		return &errWithNotification{
			error:   fmt.Errorf("error deserializing drInterfaceToLan in igp router ID node descriptor: %v", err),
			code:    NotifErrCodeUpdateMessage,
			subcode: NotifErrSubcodeMalformedAttr,
		}
	}
	n.DrInterfaceToLAN = drInterfaceToLAN

	return nil
}

func (n *NodeDescriptorIgpRouterIDOspfPseudo) serialize() ([]byte, error) {
	b := make([]byte, 4)
	binary.BigEndian.PutUint16(b[:2], uint16(n.Code()))
	binary.BigEndian.PutUint16(b[2:], uint16(8))

	routerID := n.DrRouterID.To4()
	if routerID == nil {
		return nil, errors.New("invalid dr router ID")
	}
	b = append(b, routerID...)
	lan := n.DrInterfaceToLAN.To4()
	if lan == nil {
		return nil, errors.New("invalid dr interface to lan")
	}

	b = append(b, lan...)
	return b, nil
}

// NodeDescriptorBgpRouterID is a node descriptor contained in a bgp-ls node nlri
//
// https://tools.ietf.org/html/draft-ietf-idr-bgpls-segment-routing-epe-14#section-4.1
type NodeDescriptorBgpRouterID struct {
	RouterID net.IP
}

// Code returns the appropriate NodeDescriptorCode for NodeDescriptorBgpRouterID
func (n *NodeDescriptorBgpRouterID) Code() NodeDescriptorCode {
	return NodeDescriptorCodeBgpRouterID
}

func (n *NodeDescriptorBgpRouterID) deserialize(b []byte) error {
	addr, err := deserializeIPv4Addr(b)
	if err != nil {
		return err
	}
	n.RouterID = addr
	return nil
}

func (n *NodeDescriptorBgpRouterID) serialize() ([]byte, error) {
	return serializeBgpLsIPv4TLV(uint16(n.Code()), n.RouterID)
}

// NodeDescriptorMemberASN is a node descriptor contained in a bgp-ls node nlri
//
// https://tools.ietf.org/html/draft-ietf-idr-bgpls-segment-routing-epe-14#section-4.1
type NodeDescriptorMemberASN struct {
	ASN uint32
}

// Code returns the appropriate NodeDescriptorCode for NodeDescriptorMemberASN
func (n *NodeDescriptorMemberASN) Code() NodeDescriptorCode {
	return NodeDescriptorCodeMemberASN
}

func (n *NodeDescriptorMemberASN) deserialize(b []byte) error {
	if len(b) != 4 {
		return &errWithNotification{
			error:   errors.New("invalid length for node descriptor member asn"),
			code:    NotifErrCodeUpdateMessage,
			subcode: NotifErrSubcodeMalformedAttr,
		}
	}
	n.ASN = binary.BigEndian.Uint32(b)
	return nil
}

func (n *NodeDescriptorMemberASN) serialize() ([]byte, error) {
	b := make([]byte, 8)
	binary.BigEndian.PutUint16(b[:2], uint16(n.Code()))
	binary.BigEndian.PutUint16(b[2:], uint16(4))
	binary.BigEndian.PutUint32(b[4:], n.ASN)
	return b, nil
}

func deserializeLinkDescriptors(id LinkStateNlriProtocolID, b []byte) ([]LinkDescriptor, error) {
	descriptors := make([]LinkDescriptor, 0)

	tooShortErr := &errWithNotification{
		error:   errors.New("link state link descriptors too short"),
		code:    NotifErrCodeUpdateMessage,
		subcode: NotifErrSubcodeMalformedAttr,
	}

	for {
		if len(b) < 4 {
			return nil, tooShortErr
		}

		descriptorType := binary.BigEndian.Uint16(b[:2])
		descriptorLen := int(binary.BigEndian.Uint16(b[2:4]))
		if len(b[4:]) < descriptorLen {
			return nil, tooShortErr
		}

		descriptorToDecode := b[4 : 4+descriptorLen]
		b = b[4+descriptorLen:]

		switch descriptorType {
		case uint16(LinkDescriptorCodeLinkIDs):
			descriptor := &LinkDescriptorLinkIDs{}
			err := descriptor.deserialize(descriptorToDecode)
			if err != nil {
				return nil, err
			}
			descriptors = append(descriptors, descriptor)
		case uint16(LinkDescriptorCodeIPv4InterfaceAddress):
			descriptor := &LinkDescriptorIPv4InterfaceAddress{}
			err := descriptor.deserialize(descriptorToDecode)
			if err != nil {
				return nil, err
			}
			descriptors = append(descriptors, descriptor)
		case uint16(LinkDescriptorCodeIPv4NeighborAddress):
			descriptor := &LinkDescriptorIPv4NeighborAddress{}
			err := descriptor.deserialize(descriptorToDecode)
			if err != nil {
				return nil, err
			}
			descriptors = append(descriptors, descriptor)
		case uint16(LinkDescriptorCodeIPv6InterfaceAddress):
			descriptor := &LinkDescriptorIPv6InterfaceAddress{}
			err := descriptor.deserialize(descriptorToDecode)
			if err != nil {
				return nil, err
			}
			descriptors = append(descriptors, descriptor)
		case uint16(LinkDescriptorCodeIPv6NeighborAddress):
			descriptor := &LinkDescriptorIPv6NeighborAddress{}
			err := descriptor.deserialize(descriptorToDecode)
			if err != nil {
				return nil, err
			}
			descriptors = append(descriptors, descriptor)
		case uint16(LinkDescriptorCodeMultiTopologyID):
			descriptor := &LinkDescriptorMultiTopologyID{}
			err := descriptor.deserialize(descriptorToDecode)
			if err != nil {
				return nil, err
			}
			descriptors = append(descriptors, descriptor)
		default:
			return nil, &errWithNotification{
				error:   errors.New("unknown link state link descriptor code"),
				code:    NotifErrCodeUpdateMessage,
				subcode: NotifErrSubcodeMalformedAttr,
			}
		}

		if len(b) == 0 {
			break
		}
	}

	return descriptors, nil
}

// LinkDescriptor is a bgp-ls nlri.
type LinkDescriptor interface {
	Code() LinkDescriptorCode
	serialize() ([]byte, error)
	deserialize(b []byte) error
}

// LinkDescriptorCode describes the type of link descriptor.
//
// https://tools.ietf.org/html/rfc7752#section-3.2.2 table 5
type LinkDescriptorCode uint16

// LinkDescriptorCode values
const (
	LinkDescriptorCodeLinkIDs              LinkDescriptorCode = 258
	LinkDescriptorCodeIPv4InterfaceAddress LinkDescriptorCode = 259
	LinkDescriptorCodeIPv4NeighborAddress  LinkDescriptorCode = 260
	LinkDescriptorCodeIPv6InterfaceAddress LinkDescriptorCode = 261
	LinkDescriptorCodeIPv6NeighborAddress  LinkDescriptorCode = 262
	LinkDescriptorCodeMultiTopologyID      LinkDescriptorCode = 263
)

// LinkDescriptorLinkIDs is a link descriptor contained in a bgp-ls link nlri.
//
// https://tools.ietf.org/html/rfc5307#section-1.1
type LinkDescriptorLinkIDs struct {
	LocalID  uint32
	RemoteID uint32
}

// Code returns the appropriate LinkDescriptorCode for LinkDescriptorLinkIDs.
func (l *LinkDescriptorLinkIDs) Code() LinkDescriptorCode {
	return LinkDescriptorCodeLinkIDs
}

func (l *LinkDescriptorLinkIDs) deserialize(b []byte) error {
	if len(b) != 8 {
		return &errWithNotification{
			error:   errors.New("link descriptor link ID invalid length"),
			code:    NotifErrCodeUpdateMessage,
			subcode: NotifErrSubcodeMalformedAttr,
		}
	}

	l.LocalID = binary.BigEndian.Uint32(b[:4])
	l.RemoteID = binary.BigEndian.Uint32(b[4:])
	return nil
}

func (l *LinkDescriptorLinkIDs) serialize() ([]byte, error) {
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b[:2], uint16(l.Code()))
	binary.BigEndian.PutUint16(b[2:], uint16(8))
	binary.BigEndian.PutUint32(b[4:], l.LocalID)
	binary.BigEndian.PutUint32(b[8:], l.RemoteID)
	return b, nil
}

// LinkDescriptorIPv4InterfaceAddress is a link descriptor contained in a bgp-ls link nlri.
//
// https://tools.ietf.org/html/rfc5305#section-3.2
type LinkDescriptorIPv4InterfaceAddress struct {
	Address net.IP
}

// Code returns the appropriate LinkDescriptorCode for LinkDescriptorIPv4InterfaceAddress.
func (l *LinkDescriptorIPv4InterfaceAddress) Code() LinkDescriptorCode {
	return LinkDescriptorCodeIPv4InterfaceAddress
}

func (l *LinkDescriptorIPv4InterfaceAddress) deserialize(b []byte) error {
	addr, err := deserializeIPv4Addr(b)
	if err != nil {
		return err
	}
	l.Address = addr
	return nil
}

func (l *LinkDescriptorIPv4InterfaceAddress) serialize() ([]byte, error) {
	return serializeBgpLsIPv4TLV(uint16(l.Code()), l.Address)
}

// LinkDescriptorIPv4NeighborAddress is a link descriptor contained in a bgp-ls link nlri.
//
// https://tools.ietf.org/html/rfc5305#section-3.3
type LinkDescriptorIPv4NeighborAddress struct {
	Address net.IP
}

// Code returns the appropriate LinkDescriptorCode for LinkDescriptorIPv4NeighborAddress.
func (l *LinkDescriptorIPv4NeighborAddress) Code() LinkDescriptorCode {
	return LinkDescriptorCodeIPv4NeighborAddress
}

func (l *LinkDescriptorIPv4NeighborAddress) deserialize(b []byte) error {
	addr, err := deserializeIPv4Addr(b)
	if err != nil {
		return err
	}
	l.Address = addr
	return nil
}

func (l *LinkDescriptorIPv4NeighborAddress) serialize() ([]byte, error) {
	return serializeBgpLsIPv4TLV(uint16(l.Code()), l.Address)
}

// LinkDescriptorIPv6InterfaceAddress is a link descriptor contained in a bgp-ls link nlri.
//
// https://tools.ietf.org/html/rfc6119#section-4.2
type LinkDescriptorIPv6InterfaceAddress struct {
	Address net.IP
}

// Code returns the appropriate LinkDescriptorCode for LinkDescriptorIPv6InterfaceAddress.
func (l *LinkDescriptorIPv6InterfaceAddress) Code() LinkDescriptorCode {
	return LinkDescriptorCodeIPv6InterfaceAddress
}

func (l *LinkDescriptorIPv6InterfaceAddress) deserialize(b []byte) error {
	addr, err := deserializeIPv6Addr(b)
	if err != nil {
		return err
	}
	l.Address = addr
	return nil
}

func (l *LinkDescriptorIPv6InterfaceAddress) serialize() ([]byte, error) {
	return serializeBgpLsIPv6TLV(uint16(l.Code()), l.Address)
}

// LinkDescriptorIPv6NeighborAddress is a link descriptor contained in a bgp-ls link nlri.
//
// https://tools.ietf.org/html/rfc6119#section-4.3
type LinkDescriptorIPv6NeighborAddress struct {
	Address net.IP
}

// Code returns the appropriate LinkDescriptorCode for LinkDescriptorIPv6NeighborAddress.
func (l *LinkDescriptorIPv6NeighborAddress) Code() LinkDescriptorCode {
	return LinkDescriptorCodeIPv6NeighborAddress
}

func (l *LinkDescriptorIPv6NeighborAddress) deserialize(b []byte) error {
	addr, err := deserializeIPv6Addr(b)
	if err != nil {
		return err
	}
	l.Address = addr
	return nil
}

func (l *LinkDescriptorIPv6NeighborAddress) serialize() ([]byte, error) {
	return serializeBgpLsIPv6TLV(uint16(l.Code()), l.Address)
}

func serializeMultiTopologyIDs(t uint16, ids []uint16) ([]byte, error) {
	b := make([]byte, 4)
	binary.BigEndian.PutUint16(b[:2], t)
	binary.BigEndian.PutUint16(b[2:], uint16(len(ids)*2))
	for _, id := range ids {
		c := make([]byte, 2)
		binary.BigEndian.PutUint16(c, id)
		b = append(b, c...)
	}
	return b, nil
}

/*
	0                   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|              Type             |          Length=2*n           |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|R R R R|  Multi-Topology ID 1  |             ....             //
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//             ....             |R R R R|  Multi-Topology ID n  |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
func deserializeMultiTopologyIDs(b []byte) ([]uint16, error) {
	ids := make([]uint16, 0)

	if len(b) == 0 {
		return ids, nil
	}

	if len(b)%2 != 0 {
		return nil, &errWithNotification{
			error:   errors.New("invalid length for multi topology ID link state tlv"),
			code:    NotifErrCodeUpdateMessage,
			subcode: NotifErrSubcodeMalformedAttr,
		}
	}

	for {
		ids = append(ids, binary.BigEndian.Uint16(b[:2]))
		b = b[2:]

		if len(b) == 0 {
			break
		}
	}

	return ids, nil
}

// LinkDescriptorMultiTopologyID is a link descriptor contained in a bgp-ls link nlri.
//
// https://tools.ietf.org/html/rfc7752#section-3.2.1.5
type LinkDescriptorMultiTopologyID struct {
	IDs []uint16
}

// Code returns the appropriate LinkDescriptorCode for LinkDescriptorMultiTopologyID.
func (l *LinkDescriptorMultiTopologyID) Code() LinkDescriptorCode {
	return LinkDescriptorCodeMultiTopologyID
}

func (l *LinkDescriptorMultiTopologyID) deserialize(b []byte) error {
	ids, err := deserializeMultiTopologyIDs(b)
	if err != nil {
		return err
	}

	l.IDs = ids
	return nil
}

func (l *LinkDescriptorMultiTopologyID) serialize() ([]byte, error) {
	return serializeMultiTopologyIDs(uint16(l.Code()), l.IDs)
}

// LinkStateNlriLink is a link state nlri.
//
// https://tools.ietf.org/html/rfc7752#section-3.2 figure 8
type LinkStateNlriLink struct {
	ProtocolID            LinkStateNlriProtocolID
	ID                    uint64
	LocalNodeDescriptors  []NodeDescriptor
	RemoteNodeDescriptors []NodeDescriptor
	LinkDescriptors       []LinkDescriptor
}

// Type returns the appropriate LinkStateNlriType for LinkStateNlriLink
func (l *LinkStateNlriLink) Type() LinkStateNlriType {
	return LinkStateNlriLinkType
}

// Afi returns the appropriate MultiprotoAfi for LinkStateNlriLink
func (l *LinkStateNlriLink) Afi() MultiprotoAfi {
	return BgpLsAfi
}

// Safi returns the appropriate MultiprotoAfi for LinkStateNlriLink
func (l *LinkStateNlriLink) Safi() MultiprotoSafi {
	return BgpLsSafi
}

/*
	0                   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+
	|  Protocol-ID  |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                           Identifier                          |
	|                            (64 bits)                          |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//               Local Node Descriptors (variable)             //
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//               Remote Node Descriptors (variable)            //
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//                  Link Descriptors (variable)                //
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
func (l *LinkStateNlriLink) deserialize(b []byte) error {
	tooShortErr := &errWithNotification{
		error:   errors.New("link state link nlri too short"),
		code:    NotifErrCodeUpdateMessage,
		subcode: NotifErrSubcodeMalformedAttr,
	}

	if len(b) < 17 {
		return tooShortErr
	}

	l.ProtocolID = LinkStateNlriProtocolID(b[0])
	l.ID = binary.BigEndian.Uint64(b[1:9])
	b = b[9:]

	// local node descriptors TLV, mandatory
	if binary.BigEndian.Uint16(b[:2]) != uint16(LinkStateNlriLocalNodeDescriptorsDescriptorCode) {
		return &errWithNotification{
			error:   errors.New("link state link nlri local node descriptors tlv type invalid"),
			code:    NotifErrCodeUpdateMessage,
			subcode: NotifErrSubcodeMalformedAttr,
		}
	}

	localNodeDescriptorsLen := int(binary.BigEndian.Uint16(b[2:4]))
	if len(b[4:]) < localNodeDescriptorsLen {
		return tooShortErr
	}
	b = b[4:]
	localNodeDescriptors, err := deserializeNodeDescriptors(l.ProtocolID, b[:localNodeDescriptorsLen])
	if err != nil {
		return err
	}
	l.LocalNodeDescriptors = localNodeDescriptors
	b = b[localNodeDescriptorsLen:]

	// remote node descriptors, mandatory
	if len(b) < 4 {
		return tooShortErr
	}
	if binary.BigEndian.Uint16(b[:2]) != uint16(LinkStateNlriRemoteNodeDescriptorsDescriptorCode) {
		return &errWithNotification{
			error:   errors.New("link state link nlri remote node descriptors tlv type invalid"),
			code:    NotifErrCodeUpdateMessage,
			subcode: NotifErrSubcodeMalformedAttr,
		}
	}

	remoteNodeDescriptorsLen := int(binary.BigEndian.Uint16(b[2:4]))
	if len(b[4:]) < remoteNodeDescriptorsLen {
		return tooShortErr
	}
	b = b[4:]
	remoteNodeDescriptors, err := deserializeNodeDescriptors(l.ProtocolID, b[:remoteNodeDescriptorsLen])
	if err != nil {
		return err
	}
	l.RemoteNodeDescriptors = remoteNodeDescriptors
	b = b[remoteNodeDescriptorsLen:]

	// link descriptors, optional
	if len(b) == 0 {
		return nil
	}
	if len(b) < 4 {
		return tooShortErr
	}
	LinkDescriptors, err := deserializeLinkDescriptors(l.ProtocolID, b)
	if err != nil {
		return err
	}
	l.LinkDescriptors = LinkDescriptors

	return nil
}

func (l *LinkStateNlriLink) serialize() ([]byte, error) {
	localNodes := make([]byte, 0, 512)
	for _, d := range l.LocalNodeDescriptors {
		e, err := d.serialize()
		if err != nil {
			return nil, err
		}
		localNodes = append(localNodes, e...)
	}
	remoteNodes := make([]byte, 0, 512)
	for _, d := range l.RemoteNodeDescriptors {
		e, err := d.serialize()
		if err != nil {
			return nil, err
		}
		remoteNodes = append(remoteNodes, e...)
	}
	links := make([]byte, 0, 512)
	for _, d := range l.LinkDescriptors {
		e, err := d.serialize()
		if err != nil {
			return nil, err
		}
		links = append(links, e...)
	}

	b := make([]byte, 17)
	binary.BigEndian.PutUint16(b[:2], uint16(LinkStateNlriLinkType))
	binary.BigEndian.PutUint16(b[2:], uint16(len(localNodes)+len(remoteNodes)+len(links)+17))
	b[4] = uint8(l.ProtocolID)
	binary.BigEndian.PutUint64(b[5:], l.ID)

	// local nodes
	binary.BigEndian.PutUint16(b[13:], uint16(LinkStateNlriLocalNodeDescriptorsDescriptorCode))
	binary.BigEndian.PutUint16(b[15:], uint16(len(localNodes)))
	b = append(b, localNodes...)

	// remote nodes
	r := make([]byte, 4)
	binary.BigEndian.PutUint16(r[:2], uint16(LinkStateNlriRemoteNodeDescriptorsDescriptorCode))
	binary.BigEndian.PutUint16(r[2:], uint16(len(remoteNodes)))
	b = append(b, r...)
	b = append(b, remoteNodes...)

	// links
	b = append(b, links...)

	return b, nil
}

// LinkStateNlriIPv4Prefix is a link state nlri.
//
// https://tools.ietf.org/html/rfc7752#section-3.2 figure 9
type LinkStateNlriIPv4Prefix struct {
	LinkStateNlriPrefix
}

// Type returns the appropriate LinkStateNlriType for LinkStateNlriIPv4Prefix
func (l *LinkStateNlriIPv4Prefix) Type() LinkStateNlriType {
	return LinkStateNlriIPv4PrefixType
}

func (l *LinkStateNlriIPv4Prefix) serialize() ([]byte, error) {
	return l.LinkStateNlriPrefix.serialize(l.Type())
}

// LinkStateNlriIPv6Prefix is a link state nlri.
//
// https://tools.ietf.org/html/rfc7752#section-3.2 figure 9
type LinkStateNlriIPv6Prefix struct {
	LinkStateNlriPrefix
}

// Type returns the appropriate LinkStateNlriType for LinkStateNlriIPv6Prefix
func (l *LinkStateNlriIPv6Prefix) Type() LinkStateNlriType {
	return LinkStateNlriIPv6PrefixType
}

func (l *LinkStateNlriIPv6Prefix) serialize() ([]byte, error) {
	return l.LinkStateNlriPrefix.serialize(l.Type())
}

// LinkStateNlriPrefix is a link state nlri.
//
// https://tools.ietf.org/html/rfc7752#section-3.2 figure 9
type LinkStateNlriPrefix struct {
	ProtocolID           LinkStateNlriProtocolID
	ID                   uint64
	LocalNodeDescriptors []NodeDescriptor
	PrefixDescriptors    []PrefixDescriptor
}

// Afi returns the appropriate MultiprotoAfi for LinkStateNlriPrefix
func (l *LinkStateNlriPrefix) Afi() MultiprotoAfi {
	return BgpLsAfi
}

// Safi returns the appropriate MultiprotoAfi for LinkStateNlriPrefix
func (l *LinkStateNlriPrefix) Safi() MultiprotoSafi {
	return BgpLsSafi
}

/*
	0                   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+
	|  Protocol-ID  |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                           Identifier                          |
	|                            (64 bits)                          |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//              Local Node Descriptors (variable)              //
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//                Prefix Descriptors (variable)                //
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
func (l *LinkStateNlriPrefix) deserialize(b []byte) error {
	tooShortErr := &errWithNotification{
		error:   errors.New("link state prefix nlri too short"),
		code:    NotifErrCodeUpdateMessage,
		subcode: NotifErrSubcodeMalformedAttr,
	}

	if len(b) < 13 {
		return tooShortErr
	}

	l.ProtocolID = LinkStateNlriProtocolID(b[0])
	l.ID = binary.BigEndian.Uint64(b[1:9])
	b = b[9:]

	// local node descriptors TLV, mandatory
	if binary.BigEndian.Uint16(b[:2]) != uint16(LinkStateNlriLocalNodeDescriptorsDescriptorCode) {
		return &errWithNotification{
			error:   errors.New("link state prefix nlri local node descriptors tlv type invalid"),
			code:    NotifErrCodeUpdateMessage,
			subcode: NotifErrSubcodeMalformedAttr,
		}
	}

	localNodeDescriptorsLen := int(binary.BigEndian.Uint16(b[2:4]))
	if len(b[4:]) < localNodeDescriptorsLen {
		return tooShortErr
	}
	b = b[4:]
	localNodeDescriptors, err := deserializeNodeDescriptors(l.ProtocolID, b[:localNodeDescriptorsLen])
	if err != nil {
		return err
	}
	l.LocalNodeDescriptors = localNodeDescriptors
	b = b[localNodeDescriptorsLen:]

	// prefix descriptors, optional
	if len(b) == 0 {
		return nil
	}
	if len(b) < 4 {
		return tooShortErr
	}
	PrefixDescriptors, err := deserializePrefixDescriptors(l.ProtocolID, b)
	if err != nil {
		return err
	}
	l.PrefixDescriptors = PrefixDescriptors

	return nil
}

func (l *LinkStateNlriPrefix) serialize(t LinkStateNlriType) ([]byte, error) {
	localNodes := make([]byte, 0, 512)
	for _, d := range l.LocalNodeDescriptors {
		e, err := d.serialize()
		if err != nil {
			return nil, err
		}
		localNodes = append(localNodes, e...)
	}
	prefixes := make([]byte, 0, 512)
	for _, d := range l.PrefixDescriptors {
		e, err := d.serialize()
		if err != nil {
			return nil, err
		}
		prefixes = append(prefixes, e...)
	}

	b := make([]byte, 17)
	binary.BigEndian.PutUint16(b[:2], uint16(t))
	binary.BigEndian.PutUint16(b[2:], uint16(len(localNodes)+len(prefixes)+13))
	b[4] = uint8(l.ProtocolID)
	binary.BigEndian.PutUint64(b[5:], l.ID)

	// local nodes
	binary.BigEndian.PutUint16(b[13:], uint16(LinkStateNlriLocalNodeDescriptorsDescriptorCode))
	binary.BigEndian.PutUint16(b[15:], uint16(len(localNodes)))
	b = append(b, localNodes...)

	// prefixes
	b = append(b, prefixes...)

	return b, nil
}

// PrefixDescriptor is a bgp-ls prefix descriptor.
//
// https://tools.ietf.org/html/rfc7752#section-3.2.3
type PrefixDescriptor interface {
	Code() PrefixDescriptorCode
	serialize() ([]byte, error)
	deserialize(b []byte) error
}

// PrefixDescriptorCode describes the type of prefix descriptor.
//
// https://tools.ietf.org/html/rfc7752#section-3.2.3
type PrefixDescriptorCode uint16

// PrefixDescriptorCode values
const (
	PrefixDescriptorCodeMultiTopologyID    PrefixDescriptorCode = 263
	PrefixDescriptorCodeOspfRouteType      PrefixDescriptorCode = 264
	PrefixDescriptorCodeIPReachabilityInfo PrefixDescriptorCode = 265
)

func deserializePrefixDescriptors(id LinkStateNlriProtocolID, b []byte) ([]PrefixDescriptor, error) {
	descriptors := make([]PrefixDescriptor, 0)

	tooShortErr := &errWithNotification{
		error:   errors.New("link state prefix descriptors too short"),
		code:    NotifErrCodeUpdateMessage,
		subcode: NotifErrSubcodeMalformedAttr,
	}

	for {
		if len(b) < 4 {
			return nil, tooShortErr
		}

		descriptorType := binary.BigEndian.Uint16(b[:2])
		descriptorLen := int(binary.BigEndian.Uint16(b[2:4]))
		if len(b[4:]) < descriptorLen {
			return nil, tooShortErr
		}

		descriptorToDecode := b[4 : 4+descriptorLen]
		b = b[4+descriptorLen:]

		switch descriptorType {
		case uint16(PrefixDescriptorCodeMultiTopologyID):
			descriptor := &PrefixDescriptorMultiTopologyID{}
			err := descriptor.deserialize(descriptorToDecode)
			if err != nil {
				return nil, err
			}
			descriptors = append(descriptors, descriptor)
		case uint16(PrefixDescriptorCodeOspfRouteType):
			descriptor := &PrefixDescriptorOspfRouteType{}
			err := descriptor.deserialize(descriptorToDecode)
			if err != nil {
				return nil, err
			}
			descriptors = append(descriptors, descriptor)
		case uint16(PrefixDescriptorCodeIPReachabilityInfo):
			descriptor := &PrefixDescriptorIPReachabilityInfo{}
			err := descriptor.deserialize(descriptorToDecode)
			if err != nil {
				return nil, err
			}
			descriptors = append(descriptors, descriptor)
		default:
			return nil, &errWithNotification{
				error:   errors.New("unknown link state prefix descriptor code"),
				code:    NotifErrCodeUpdateMessage,
				subcode: NotifErrSubcodeMalformedAttr,
			}
		}

		if len(b) == 0 {
			break
		}
	}

	return descriptors, nil
}

// PrefixDescriptorMultiTopologyID is a prefix descriptor contained in a bgp-ls nlri.
//
// https://tools.ietf.org/html/rfc7752#section-3.2.1.5
type PrefixDescriptorMultiTopologyID struct {
	IDs []uint16
}

// Code returns the appropriate PrefixDescriptorCode for PrefixDescriptorMultiTopologyID.
func (p *PrefixDescriptorMultiTopologyID) Code() PrefixDescriptorCode {
	return PrefixDescriptorCodeMultiTopologyID
}

func (p *PrefixDescriptorMultiTopologyID) deserialize(b []byte) error {
	ids, err := deserializeMultiTopologyIDs(b)
	if err != nil {
		return err
	}

	p.IDs = ids
	return nil
}

func (p *PrefixDescriptorMultiTopologyID) serialize() ([]byte, error) {
	return serializeMultiTopologyIDs(uint16(p.Code()), p.IDs)
}

// PrefixDescriptorOspfRouteType is a prefix descriptor contained in a bgp-ls nlri.
//
// https://tools.ietf.org/html/rfc7752#section-3.2.3.1
type PrefixDescriptorOspfRouteType struct {
	RouteType OspfRouteType
}

// OspfRouteType describes the type of ospf route.
//
// https://tools.ietf.org/html/rfc7752#section-3.2.3.1
type OspfRouteType uint8

// OspfRouteType values
const (
	_ OspfRouteType = iota
	OspfRouteTypeIntraArea
	OspfRouteTypeInterArea
	OspfRouteTypeExternal1
	OspfRouteTypeExternal2
	OspfRouteTypeNSSA1
	OspfRouteTypeNSSA2
)

// Code returns the appropriate PrefixDescriptorCode for PrefixDescriptorOspfRouteType.
func (p *PrefixDescriptorOspfRouteType) Code() PrefixDescriptorCode {
	return PrefixDescriptorCodeOspfRouteType
}

func (p *PrefixDescriptorOspfRouteType) deserialize(b []byte) error {
	if len(b) != 1 {
		return &errWithNotification{
			error:   errors.New("invalid ospf route type prefix descriptor length"),
			code:    NotifErrCodeUpdateMessage,
			subcode: NotifErrSubcodeMalformedAttr,
		}
	}

	rt := int(b[0])
	if rt < 1 || rt > 6 {
		return &errWithNotification{
			error:   errors.New("invalid ospf route type prefix descriptor value"),
			code:    NotifErrCodeUpdateMessage,
			subcode: NotifErrSubcodeMalformedAttr,
		}
	}

	p.RouteType = OspfRouteType(rt)
	return nil
}

func (p *PrefixDescriptorOspfRouteType) serialize() ([]byte, error) {
	b := make([]byte, 5)
	binary.BigEndian.PutUint16(b[:2], uint16(p.Code()))
	binary.BigEndian.PutUint16(b[2:], uint16(1))
	b[4] = uint8(p.RouteType)
	return b, nil
}

// PrefixDescriptorIPReachabilityInfo is a prefix descriptor contained in a bgp-ls nlri.
//
// https://tools.ietf.org/html/rfc7752#section-3.2.3.2
type PrefixDescriptorIPReachabilityInfo struct {
	PrefixLength uint8
	Prefix       net.IP
}

// Code returns the appropriate PrefixDescriptorCode for PrefixDescriptorIPReachabilityInfo.
func (p *PrefixDescriptorIPReachabilityInfo) Code() PrefixDescriptorCode {
	return PrefixDescriptorCodeIPReachabilityInfo
}

func (p *PrefixDescriptorIPReachabilityInfo) deserialize(b []byte) error {
	if len(b) != 5 && len(b) != 17 {
		return &errWithNotification{
			error:   errors.New("invalid ip reachability info prefix descriptor"),
			code:    NotifErrCodeUpdateMessage,
			subcode: NotifErrSubcodeMalformedAttr,
		}
	}

	p.PrefixLength = b[0]
	b = b[1:]

	addr, err := bytesToIPAddress(b)
	if err != nil {
		return err
	}

	p.Prefix = addr
	return nil
}

func (p *PrefixDescriptorIPReachabilityInfo) serialize() ([]byte, error) {
	b := make([]byte, 5)
	binary.BigEndian.PutUint16(b[:2], uint16(p.Code()))
	b[4] = p.PrefixLength

	addr := p.Prefix.To4()
	if addr == nil {
		addr = p.Prefix.To16()
		if addr == nil {
			return nil, errors.New("invalid address")
		}
		binary.BigEndian.PutUint16(b[2:], uint16(17))
		b = append(b, addr...)
		return b, nil
	}
	binary.BigEndian.PutUint16(b[2:], uint16(5))
	b = append(b, addr...)

	return b, nil
}

// PathAttrOrigin is a path attribute.
//
// https://tools.ietf.org/html/rfc4271#section-5.1.1
type PathAttrOrigin struct {
	f      PathAttrFlags
	Origin OriginCode
}

// Flags returns the PathAttrFlags for PathAttrOrigin.
func (o *PathAttrOrigin) Flags() PathAttrFlags {
	return o.f
}

// Type returns the appropriate PathAttrType for PathAttrOrigin.
func (o *PathAttrOrigin) Type() PathAttrType {
	return PathAttrOriginType
}

func (o *PathAttrOrigin) serialize() ([]byte, error) {
	o.f = PathAttrFlags{
		Transitive: true,
	}

	flags, err := o.f.serialize()
	if err != nil {
		return nil, err
	}

	return []byte{flags, byte(PathAttrOriginType), byte(1), byte(o.Origin)}, nil
}

func (o *PathAttrOrigin) deserialize(flags PathAttrFlags, b []byte) error {
	if len(b) != 1 {
		return &errWithNotification{
			error:   errors.New("origin attribute invalid length"),
			code:    NotifErrCodeUpdateMessage,
			subcode: NotifErrSubcodeMalformedAttr,
		}
	}

	o.f = flags
	if b[0] >= 0 && b[0] <= 3 {
		o.Origin = OriginCode(b[0])
	} else {
		return &errWithNotification{
			error:   errors.New("origin attribute invalid value"),
			code:    NotifErrCodeUpdateMessage,
			subcode: NotifErrSubcodeMalformedAttr,
		}
	}

	return nil
}

// OriginCode describes the type of origin in the origin attribute.
//
// https://tools.ietf.org/html/rfc4271#section-5.1.1
type OriginCode uint8

// OriginCode values
const (
	OriginCodeIGP OriginCode = iota
	OriginCodeEGP
	OriginCodeIncomplete
)

func (o OriginCode) String() string {
	switch o {
	case OriginCodeIGP:
		return "igp"
	case OriginCodeEGP:
		return "egp"
	case OriginCodeIncomplete:
		return "incomplete"
	default:
		return "unknown"
	}
}

// AsPathSegment is contained in an as-path path attribute
type AsPathSegment interface {
	Type() AsPathSegmentType
	serialize() ([]byte, error)
	deserialize(b []byte) error
}

// AsPathSegmentType describes the type of AsPathSegment
type AsPathSegmentType uint8

// AsPathSegmentType values
const (
	AsPathSegmentSetType      AsPathSegmentType = 1
	AsPathSegmentSequenceType AsPathSegmentType = 2
)

// AsPathSegmentSet is an unordered as-path segment
type AsPathSegmentSet struct {
	Set []uint16
}

// Type returns the appropriate AsPathSegmentType for AsPathSegmentSet
func (a *AsPathSegmentSet) Type() AsPathSegmentType {
	return AsPathSegmentSetType
}

func (a *AsPathSegmentSet) serialize() ([]byte, error) {
	b := make([]byte, 2)
	b[0] = byte(AsPathSegmentSetType)
	b[1] = byte(len(a.Set))

	for _, s := range a.Set {
		asn := make([]byte, 2)
		binary.BigEndian.PutUint16(asn, s)
		b = append(b, asn...)
	}

	return b, nil
}

func (a *AsPathSegmentSet) deserialize(b []byte) error {
	asns, err := deserializeAsPathSegment(b)
	if err != nil {
		return err
	}

	a.Set = asns
	return nil
}

// AsPathSegmentSequence is an ordered as-path segment
type AsPathSegmentSequence struct {
	Sequence []uint16
}

// Type returns the appropriate AsPathSegmentType for AsPathSegmentSequence
func (a *AsPathSegmentSequence) Type() AsPathSegmentType {
	return AsPathSegmentSequenceType
}

func (a *AsPathSegmentSequence) serialize() ([]byte, error) {
	b := make([]byte, 2)
	b[0] = byte(AsPathSegmentSequenceType)
	b[1] = byte(len(a.Sequence))

	for _, s := range a.Sequence {
		asn := make([]byte, 2)
		binary.BigEndian.PutUint16(asn, s)
		b = append(b, asn...)
	}

	return b, nil
}

func (a *AsPathSegmentSequence) deserialize(b []byte) error {
	asns, err := deserializeAsPathSegment(b)
	if err != nil {
		return err
	}

	a.Sequence = asns
	return nil
}

func deserializeAsPathSegment(b []byte) ([]uint16, error) {
	errTooShort := &errWithNotification{
		error:   errors.New("invalid length for as path segment"),
		code:    NotifErrCodeUpdateMessage,
		subcode: NotifErrSubcodeMalformedAttr,
	}

	if len(b) < 2 || len(b)%2 != 0 {
		return nil, errTooShort
	}

	asn := make([]uint16, 0, len(b)/2)
	for i := 0; i < len(b); i = i + 2 {
		asn = append(asn, binary.BigEndian.Uint16(b[i:i+2]))
	}

	return asn, nil
}

// PathAttrAsPath is a path attribute.
//
// https://tools.ietf.org/html/rfc4271#section-5.1.2
type PathAttrAsPath struct {
	f        PathAttrFlags
	Segments []AsPathSegment
}

// Flags returns the appropriate PathAttrFlags for PathAttrAsPath.
func (a *PathAttrAsPath) Flags() PathAttrFlags {
	return a.f
}

// Type returns the appropriate PathAttrType for PathAttrAsPath.
func (a *PathAttrAsPath) Type() PathAttrType {
	return PathAttrAsPathType
}

func (a *PathAttrAsPath) serialize() ([]byte, error) {
	a.f = PathAttrFlags{
		Transitive: true,
	}

	segments := make([]byte, 0, 512)
	for _, s := range a.Segments {
		b, err := s.serialize()
		if err != nil {
			return nil, err
		}
		segments = append(segments, b...)
	}

	if len(segments) > math.MaxUint8 {
		a.f.ExtendedLength = true
	}
	flags, err := a.f.serialize()
	if err != nil {
		return nil, err
	}

	b := make([]byte, 2)
	b[0] = flags
	b[1] = byte(PathAttrAsPathType)

	if a.f.ExtendedLength {
		attrLen := make([]byte, 2)
		binary.BigEndian.PutUint16(attrLen, uint16(len(segments)))
		b = append(b, attrLen...)
	} else {
		b = append(b, uint8(len(segments)))
	}

	b = append(b, segments...)

	return b, nil
}

func (a *PathAttrAsPath) deserialize(f PathAttrFlags, b []byte) error {
	a.f = f

	if len(b) == 0 {
		return nil
	}

	for {
		if len(b) < 4 {
			return &errWithNotification{
				error:   errors.New("invalid as path length"),
				code:    NotifErrCodeUpdateMessage,
				subcode: NotifErrSubcodeMalformedAttr,
			}
		}

		segmentType := b[0]
		segmentLen := int(b[1]) * 2
		b = b[2:]
		if len(b) < segmentLen {
			return &errWithNotification{
				error:   errors.New("invalid as path length"),
				code:    NotifErrCodeUpdateMessage,
				subcode: NotifErrSubcodeMalformedAttr,
			}
		}
		segmentToDecode := b[:segmentLen]

		switch segmentType {
		case uint8(AsPathSegmentSequenceType):
			segment := &AsPathSegmentSequence{}
			err := segment.deserialize(segmentToDecode)
			if err != nil {
				return err
			}
			a.Segments = append(a.Segments, segment)
		case uint8(AsPathSegmentSetType):
			segment := &AsPathSegmentSet{}
			err := segment.deserialize(segmentToDecode)
			if err != nil {
				return err
			}
			a.Segments = append(a.Segments, segment)
		default:
			return &errWithNotification{
				error:   errors.New("invalid as path segment type"),
				code:    NotifErrCodeUpdateMessage,
				subcode: NotifErrSubcodeMalformedAttr,
			}
		}

		b = b[segmentLen:]

		if len(b) == 0 {
			break
		}
	}

	return nil
}

// PathAttrLocalPref is a path attribute.
//
// https://tools.ietf.org/html/rfc4271#section-5.1.5
type PathAttrLocalPref struct {
	f          PathAttrFlags
	Preference uint32
}

// Flags returns the PathAttrFlags for PathAttrLocalPref.
func (p *PathAttrLocalPref) Flags() PathAttrFlags {
	return p.f
}

// Type returns the appropriate PathAttrType for PathAttrLocalPref.
func (p *PathAttrLocalPref) Type() PathAttrType {
	return PathAttrLocalPrefType
}

func (p *PathAttrLocalPref) serialize() ([]byte, error) {
	p.f = PathAttrFlags{
		Transitive: true,
	}

	flags, err := p.f.serialize()
	if err != nil {
		return nil, err
	}

	b := make([]byte, 7)
	b[0] = flags
	b[1] = byte(PathAttrLocalPrefType)
	b[2] = byte(4)
	binary.BigEndian.PutUint32(b[3:7], p.Preference)
	return b, nil
}

func (p *PathAttrLocalPref) deserialize(f PathAttrFlags, b []byte) error {
	p.f = f
	if len(b) != 4 {
		return &errWithNotification{
			error:   errors.New("local preference invalid length"),
			code:    NotifErrCodeUpdateMessage,
			subcode: NotifErrSubcodeMalformedAttr,
		}
	}

	p.Preference = binary.BigEndian.Uint32(b)

	return nil
}
