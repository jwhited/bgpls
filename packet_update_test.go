package bgpls

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPathAttrOrigin(t *testing.T) {
	cases := []struct {
		c OriginCode
		s string
	}{
		{OriginCodeIGP, "igp"},
		{OriginCodeEGP, "egp"},
		{OriginCodeIncomplete, "incomplete"},
		{OriginCode(3), "unknown"},
	}

	for _, c := range cases {
		assert.Equal(t, c.c.String(), c.s)
	}

	o := &PathAttrOrigin{}
	assert.Equal(t, o.Type(), PathAttrOriginType)
	assert.Equal(t, o.Flags(), PathAttrFlags{})

	// empty attr
	err := o.deserialize(PathAttrFlags{}, []byte{})
	assert.NotNil(t, err)
}

func TestPathAttrAsPath(t *testing.T) {
	asp := &PathAttrAsPath{}
	assert.Equal(t, asp.Type(), PathAttrAsPathType)
	assert.Equal(t, asp.Flags(), PathAttrFlags{})

	// extended len
	segments := make([]AsPathSegment, 0)
	for i := 1; i < 256; i++ {
		segments = append(segments, &AsPathSegmentSet{Set: []uint16{1}})
	}
	asp.Segments = segments
	_, err := asp.serialize()
	assert.Nil(t, err)

	// empty attr
	err = asp.deserialize(PathAttrFlags{}, []byte{})
	assert.Nil(t, err)

	// < 2 bytes
	err = asp.deserialize(PathAttrFlags{}, []byte{1})
	assert.NotNil(t, err)

	// invalid segment len
	err = asp.deserialize(PathAttrFlags{}, []byte{0, 100, 0, 0})
	assert.NotNil(t, err)

	// invalid segment type
	err = asp.deserialize(PathAttrFlags{}, []byte{0, 2, 0, 0, 0, 0})
	assert.NotNil(t, err)

	// err deserialize sequence type
	err = asp.deserialize(PathAttrFlags{}, []byte{2, 0})
	assert.NotNil(t, err)

	// err deserialize set type
	err = asp.deserialize(PathAttrFlags{}, []byte{1, 0})
	assert.NotNil(t, err)

	// error serializing segments
	asp = &PathAttrAsPath{
		Segments: []AsPathSegment{
			&AsPathSegmentSet{},
			&AsPathSegmentSequence{},
		},
	}
	_, err = asp.serialize()
	assert.NotNil(t, err)

	// segment tests
	seq := &AsPathSegmentSequence{}
	assert.Equal(t, seq.Type(), AsPathSegmentSequenceType)
	_, err = seq.serialize()
	assert.NotNil(t, err)
	set := &AsPathSegmentSet{}
	assert.Equal(t, set.Type(), AsPathSegmentSetType)
	_, err = seq.serialize()
	assert.NotNil(t, err)
}

func TestPathAttrLocalPref(t *testing.T) {
	lp := &PathAttrLocalPref{}
	assert.Equal(t, lp.Type(), PathAttrLocalPrefType)
	assert.Equal(t, lp.Flags(), PathAttrFlags{})
}

func TestIPTlvSerialization(t *testing.T) {
	b, err := serializeBgpLsIPv4TLV(1, []byte{1, 1, 1, 1})
	assert.Nil(t, err)
	assert.Equal(t, b, []byte{0, 1, 0, 4, 1, 1, 1, 1})
	_, err = serializeBgpLsIPv4TLV(1, []byte{1, 1, 1, 1, 1})
	assert.NotNil(t, err)

	b, err = serializeBgpLsIPv6TLV(1, []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1})
	assert.Nil(t, err)
	assert.Equal(t, b, []byte{0, 1, 0, 16, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1})
	_, err = serializeBgpLsIPv6TLV(1, []byte{1, 1, 1, 1, 1})
	assert.NotNil(t, err)

	_, err = deserializeIPv4Addr([]byte{1, 1, 1, 1})
	assert.Nil(t, err)
	_, err = deserializeIPv4Addr([]byte{1, 1, 1, 1, 1})
	assert.NotNil(t, err)

	_, err = deserializeIPv6Addr([]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1})
	assert.Nil(t, err)
	_, err = deserializeIPv6Addr([]byte{1, 1, 1, 1, 1})
	assert.NotNil(t, err)
}

func TestPathAttrLinkState(t *testing.T) {
	ls := &PathAttrLinkState{}
	assert.Equal(t, ls.Flags(), PathAttrFlags{})
	assert.Equal(t, ls.Type(), PathAttrLinkStateType)
	err := ls.deserialize(PathAttrFlags{}, []byte{})
	assert.Nil(t, err)

	// 0 > len < 4
	err = ls.deserialize(PathAttrFlags{}, []byte{0})
	assert.NotNil(t, err)

	// invalid attr len
	err = ls.deserialize(PathAttrFlags{}, []byte{0, 0, 0, 100, 0})
	assert.NotNil(t, err)

	// err on attr deserialization
	cases := []struct {
		a uint16
		b []byte
	}{
		{
			uint16(NodeAttrCodeIsIsAreaID),
			[]byte{0},
		},
		{
			uint16(NodeAttrCodeLocalIPv4RouterID),
			[]byte{0},
		},
		{
			uint16(NodeAttrCodeLocalIPv6RouterID),
			[]byte{0},
		},
		{
			uint16(NodeAttrCodeMultiTopologyID),
			[]byte{0},
		},
		{
			uint16(NodeAttrCodeNodeFlagBits),
			[]byte{0, 0},
		},
		{
			uint16(NodeAttrCodeNodeName),
			[]byte{},
		},
		{
			uint16(NodeAttrCodeOpaqueNodeAttr),
			[]byte{},
		},
		{
			uint16(LinkAttrCodeAdminGroup),
			[]byte{0, 0},
		},
		{
			uint16(LinkAttrCodeIgpMetric),
			[]byte{0, 0, 0, 0},
		},
		{
			uint16(LinkAttrCodeLinkName),
			[]byte{},
		},
		{
			uint16(LinkAttrCodeLinkProtectionType),
			[]byte{0, 0, 0, 0},
		},
		{
			uint16(LinkAttrCodeMaxLinkBandwidth),
			[]byte{0, 0, 0},
		},
		{
			uint16(LinkAttrCodeMaxReservableLinkBandwidth),
			[]byte{0, 0, 0},
		},
		{
			uint16(LinkAttrCodeMplsProtocolMask),
			[]byte{0, 0, 0},
		},
		{
			uint16(LinkAttrCodeRemoteIPv4RouterID),
			[]byte{0, 0, 0},
		},
		{
			uint16(LinkAttrCodeRemoteIPv6RouterID),
			[]byte{0, 0, 0},
		},
		{
			uint16(LinkAttrCodeSharedRiskLinkGroup),
			[]byte{0, 0, 0},
		},
		{
			uint16(LinkAttrCodeOpaqueLinkAttr),
			[]byte{},
		},
		{
			uint16(LinkAttrCodeTEDefaultMetric),
			[]byte{0, 0, 0},
		},
		{
			uint16(LinkAttrCodeUnreservedBandwidth),
			[]byte{0, 0, 0},
		},
		{
			uint16(LinkAttrCodePeerNodeSID),
			[]byte{0, 0, 0},
		},
		{
			uint16(LinkAttrCodePeerAdjSID),
			[]byte{0, 0, 0},
		},
		{
			uint16(LinkAttrCodePeerSetSID),
			[]byte{0, 0, 0},
		},
		{
			uint16(PrefixAttrCodeIgpExtendedRouteTag),
			[]byte{0, 0, 0},
		},
		{
			uint16(PrefixAttrCodeIgpFlags),
			[]byte{0, 0, 0},
		},
		{
			uint16(PrefixAttrCodeIgpRouteTag),
			[]byte{0, 0, 0},
		},
		{
			uint16(PrefixAttrCodeOpaquePrefixAttribute),
			[]byte{},
		},
		{
			uint16(PrefixAttrCodeOspfForwardingAddress),
			[]byte{0, 0, 0},
		},
		{
			uint16(PrefixAttrCodePrefixMetric),
			[]byte{0, 0, 0},
		},
		{
			uint16(0),
			[]byte{0, 0, 0},
		},
	}

	for _, c := range cases {
		b := make([]byte, 4)
		binary.BigEndian.PutUint16(b[:2], uint16(c.a))
		binary.BigEndian.PutUint16(b[2:], uint16(len(c.b)))
		b = append(b, c.b...)
		err = ls.deserialize(PathAttrFlags{}, b)
		assert.NotNil(t, err)
	}

	// node attrs err on serialization
	ls = &PathAttrLinkState{
		NodeAttrs: []NodeAttr{
			&NodeAttrLocalIPv4RouterID{
				Address: []byte{0},
			},
		},
	}
	_, err = ls.serialize()
	assert.NotNil(t, err)

	// link attrs err on serialization
	ls = &PathAttrLinkState{
		LinkAttrs: []LinkAttr{
			&LinkAttrRemoteIPv4RouterID{
				Address: []byte{0},
			},
		},
	}
	_, err = ls.serialize()
	assert.NotNil(t, err)

	// prefix attrs err on serialization
	ls = &PathAttrLinkState{
		PrefixAttrs: []PrefixAttr{
			&PrefixAttrOspfForwardingAddress{
				Address: []byte{0},
			},
		},
	}
	_, err = ls.serialize()
	assert.NotNil(t, err)
}

func TestPathAttrFlags(t *testing.T) {
	cases := []struct {
		f   PathAttrFlags
		val uint8
	}{
		{
			PathAttrFlags{
				Optional: true,
			},
			128,
		},
		{
			PathAttrFlags{
				Transitive: true,
			},
			64,
		},
		{
			PathAttrFlags{
				Partial: true,
			},
			32,
		},
		{
			PathAttrFlags{
				ExtendedLength: true,
			},
			16,
		},
	}

	for _, c := range cases {
		f := pathAttrFlagsFromByte(c.val)
		assert.Equal(t, f, c.f)
		b := c.f.serialize()
		assert.Equal(t, b, c.val)
	}
}

func TestValidatePathAttrFlags(t *testing.T) {
	cases := []struct {
		f   PathAttrFlags
		cat pathAttrCategory
		err bool
	}{
		{
			PathAttrFlags{
				Transitive: true,
			},
			pathAttrCatWellKnownMandatory,
			false,
		},
		{
			PathAttrFlags{},
			pathAttrCatWellKnownDiscretionary,
			false,
		},
		{
			PathAttrFlags{
				Optional:   true,
				Transitive: true,
			},
			pathAttrCatOptionalTransitive,
			false,
		},
	}

	for _, c := range cases {
		err := validatePathAttrFlags(c.f, c.cat)
		if c.err {
			assert.NotNil(t, err)
		} else {
			assert.Nil(t, err)
		}
	}
}

func TestDeserializePathAttrs(t *testing.T) {
	// bytes < attrLen
	b := make([]byte, 4)
	b[2] = uint8(100)
	_, err := deserializePathAttrs(b)
	assert.NotNil(t, err)

	// origin errors
	o := &PathAttrOrigin{
		Origin: OriginCodeEGP,
	}
	b, err = o.serialize()
	if err != nil {
		t.Fatal(err)
	}
	// bad origin code
	b[3] = 3
	_, err = deserializePathAttrs(b)
	assert.NotNil(t, err)
	// set to valid origin code
	b[3] = 2
	// set flags to invalid value
	b[0] = 0
	_, err = deserializePathAttrs(b)
	assert.NotNil(t, err)

	cases := []struct {
		a             PathAttr
		invalidFlags  uint8
		bytesToRemove int
	}{
		{
			&PathAttrAsPath{
				Segments: []AsPathSegment{
					&AsPathSegmentSequence{
						Sequence: []uint16{1},
					},
				},
			},
			0, 1,
		},
		{
			&PathAttrLocalPref{
				Preference: 100,
			},
			128, 1,
		},
		{
			&PathAttrMpReach{},
			0,
			3,
		},
		{
			&PathAttrMpUnreach{},
			0,
			3,
		},
	}

	for _, c := range cases {
		b, err = c.a.serialize()
		if err != nil {
			t.Fatal(err)
		}
		b = b[:len(b)-c.bytesToRemove]
		b[2] = uint8(len(b) - 3)
		_, err = deserializePathAttrs(b)
		assert.NotNil(t, err)
		b[0] = c.invalidFlags
		_, err = deserializePathAttrs(b)
		assert.NotNil(t, err)
	}

	// link state errors
	ls := &PathAttrLinkState{}
	b, err = ls.serialize()
	if err != nil {
		t.Fatal(err)
	}
	b = append(b, 0)
	b[2] = 1
	_, err = deserializePathAttrs(b)
	assert.NotNil(t, err)
	b[0] = 0
	_, err = deserializePathAttrs(b)
	assert.NotNil(t, err)
}

func TestUpdateSerialization(t *testing.T) {
	// path attr serialization error
	u := &UpdateMessage{
		PathAttrs: []PathAttr{
			&PathAttrOrigin{
				Origin: OriginCode(3),
			},
		},
	}
	_, err := u.serialize()
	assert.NotNil(t, err)

	// len < 4
	err = u.deserialize([]byte{0})
	assert.NotNil(t, err)

	// withdrawn routes invalid len
	u = &UpdateMessage{}
	b, err := u.serialize()
	if err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint16(b[0:2], uint16(100))
	err = u.deserialize(b)
	assert.NotNil(t, err)

	// path attr invalid len
	binary.BigEndian.PutUint16(b[0:2], uint16(0))
	binary.BigEndian.PutUint16(b[2:4], uint16(200))
	err = u.deserialize(b)
	assert.NotNil(t, err)
}

func TestPrefixAttrs(t *testing.T) {
	attrs := []PrefixAttr{
		&PrefixAttrIgpFlags{
			IsIsDown: true,
		},
		&PrefixAttrIgpRouteTag{
			Tags: []uint32{1, 2, 3},
		},
		&PrefixAttrIgpExtendedRouteTag{
			Tags: []uint64{1, 2, 3},
		},
		&PrefixAttrPrefixMetric{
			Metric: 1,
		},
		&PrefixAttrOspfForwardingAddress{
			Address: net.ParseIP("1.1.1.1").To4(),
		},
	}

	for _, a := range attrs {
		b, err := a.serialize()
		assert.Nil(t, err)
		b = append(b, uint8(0))
		err = a.deserialize(b)
		assert.NotNil(t, err)
	}

	p := &PrefixAttrOpaquePrefixAttribute{}
	_, err := p.serialize()
	assert.NotNil(t, err)
}

func TestLinkAttrs(t *testing.T) {
	var adminGroup [32]bool
	adminGroup[31] = true

	attrs := []LinkAttr{
		&LinkAttrRemoteIPv4RouterID{
			Address: net.ParseIP("1.1.1.1").To4(),
		},
		&LinkAttrRemoteIPv6RouterID{
			Address: net.ParseIP("2601::").To16(),
		},
		&LinkAttrAdminGroup{
			Group: adminGroup,
		},
		&LinkAttrMaxLinkBandwidth{
			BytesPerSecond: 10000.00,
		},
		&LinkAttrMaxReservableLinkBandwidth{
			BytesPerSecond: 20000.00,
		},
		&LinkAttrUnreservedBandwidth{
			BytesPerSecond: [8]float32{0, 0, 1000.00, 0, 0, 0, 0, 0},
		},
		&LinkAttrTEDefaultMetric{
			Metric: uint32(5),
		},
		&LinkAttrLinkProtectionType{
			ExtraTraffic: true,
		},
		&LinkAttrPeerNodeSID{
			BaseSID: BaseSID{
				Value:  true,
				Local:  true,
				Weight: 1,
				Variable: &SIDLabel{
					Label: 50,
				},
			},
		},
		&LinkAttrPeerNodeSID{
			BaseSID: BaseSID{
				Value:  true,
				Local:  true,
				Weight: 1,
				Variable: &SRGBOffset{
					Offset: 50,
				},
			},
		},
		&LinkAttrPeerNodeSID{
			BaseSID: BaseSID{
				Value:  true,
				Local:  true,
				Weight: 1,
				Variable: &IPv6SID{
					Address: net.ParseIP("2601::"),
				},
			},
		},
		&LinkAttrPeerAdjSID{
			BaseSID: BaseSID{
				Value:  true,
				Local:  true,
				Weight: 1,
				Variable: &SIDLabel{
					Label: 50,
				},
			},
		},
		&LinkAttrPeerAdjSID{
			BaseSID: BaseSID{
				Value:  true,
				Local:  true,
				Weight: 1,
				Variable: &SRGBOffset{
					Offset: 50,
				},
			},
		},
		&LinkAttrPeerAdjSID{
			BaseSID: BaseSID{
				Value:  true,
				Local:  true,
				Weight: 1,
				Variable: &IPv6SID{
					Address: net.ParseIP("2601::"),
				},
			},
		},
		&LinkAttrPeerSetSID{
			BaseSID: BaseSID{
				Value:  true,
				Local:  true,
				Weight: 1,
				Variable: &SIDLabel{
					Label: 50,
				},
			},
		},
		&LinkAttrPeerSetSID{
			BaseSID: BaseSID{
				Value:  true,
				Local:  true,
				Weight: 1,
				Variable: &SRGBOffset{
					Offset: 50,
				},
			},
		},
		&LinkAttrPeerSetSID{
			BaseSID: BaseSID{
				Value:  true,
				Local:  true,
				Weight: 1,
				Variable: &IPv6SID{
					Address: net.ParseIP("2601::"),
				},
			},
		},
	}

	for _, a := range attrs {
		b, err := a.serialize()
		assert.Nil(t, err)
		b = append(b, uint8(0))
		err = a.deserialize(b)
		assert.NotNil(t, err)
	}

	l := &LinkAttrOpaqueLinkAttr{}
	_, err := l.serialize()
	assert.NotNil(t, err)
}

func TestNodeAttrs(t *testing.T) {
	attrs := []NodeAttr{
		&NodeAttrMultiTopologyID{
			IDs: []uint16{1, 2, 3},
		},
		&NodeAttrNodeFlagBits{
			Overload: true,
		},
		&NodeAttrIsIsAreaID{
			AreaID: uint32(1),
		},
		&NodeAttrLocalIPv4RouterID{
			Address: net.ParseIP("1.1.1.1").To4(),
		},
		&NodeAttrLocalIPv6RouterID{
			Address: net.ParseIP("2601::").To16(),
		},
	}

	for _, a := range attrs {
		b, err := a.serialize()
		assert.Nil(t, err)
		b = append(b, uint8(0))
		err = a.deserialize(b)
		assert.NotNil(t, err)
	}

	n := &NodeAttrOpaqueNodeAttr{}
	_, err := n.serialize()
	assert.NotNil(t, err)
}

func TestDeserializeLinkDescriptors(t *testing.T) {
	// len < 4
	_, err := deserializeLinkDescriptors(0, []byte{})
	assert.NotNil(t, err)

	// invalid descriptor len
	_, err = deserializeLinkDescriptors(0, []byte{0, 0, 0, 10, 0})
	assert.NotNil(t, err)

	// err deserializing link ids
	_, err = deserializeLinkDescriptors(0, []byte{1, 2, 0, 0})
	assert.NotNil(t, err)

	// err deserializing ipv4 int address
	_, err = deserializeLinkDescriptors(0, []byte{1, 3, 0, 0})
	assert.NotNil(t, err)

	// err deserializing ipv4 neighbor address
	_, err = deserializeLinkDescriptors(0, []byte{1, 4, 0, 0})
	assert.NotNil(t, err)

	// err deserializing ipv6 int address
	_, err = deserializeLinkDescriptors(0, []byte{1, 5, 0, 0})
	assert.NotNil(t, err)

	// err deserializing ipv6 neighbor address
	_, err = deserializeLinkDescriptors(0, []byte{1, 6, 0, 0})
	assert.NotNil(t, err)

	// err deserializing multi topo ids
	_, err = deserializeLinkDescriptors(0, []byte{1, 7, 0, 0})
	assert.NotNil(t, err)

	// invalid link descriptor code
	_, err = deserializeLinkDescriptors(0, []byte{0, 0, 0, 0})
	assert.NotNil(t, err)
}

func TestDeserializePrefixDescriptors(t *testing.T) {
	// len < 4
	_, err := deserializePrefixDescriptors(0, []byte{})
	assert.NotNil(t, err)

	// invalid descriptor len
	_, err = deserializePrefixDescriptors(0, []byte{0, 0, 0, 10, 0})
	assert.NotNil(t, err)

	// err deserializing multi topo id
	_, err = deserializePrefixDescriptors(0, []byte{1, 7, 0, 0})
	assert.NotNil(t, err)

	// err deserializing ospf route type
	_, err = deserializePrefixDescriptors(0, []byte{1, 8, 0, 0})
	assert.NotNil(t, err)

	// err deserializing ip reachability info
	_, err = deserializePrefixDescriptors(0, []byte{1, 9, 0, 0})
	assert.NotNil(t, err)

	// invalid prefix descriptor code
	_, err = deserializePrefixDescriptors(0, []byte{0, 0, 0, 0})
	assert.NotNil(t, err)
}

func TestPrefixDescriptors(t *testing.T) {
	descriptors := []PrefixDescriptor{
		&PrefixDescriptorIPReachabilityInfo{
			PrefixLength: uint8(32),
			Prefix:       net.ParseIP("1.2.3.4").To4(),
		},
		&PrefixDescriptorIPReachabilityInfo{
			PrefixLength: uint8(128),
			Prefix:       net.ParseIP("2601::").To16(),
		},
		&PrefixDescriptorMultiTopologyID{
			IDs: []uint16{0, 1, 2},
		},
		&PrefixDescriptorOspfRouteType{
			RouteType: OspfRouteTypeExternal1,
		},
	}

	for _, d := range descriptors {
		b, err := d.serialize()
		assert.Nil(t, err)
		b = append(b, uint8(0))
		err = d.deserialize(b)
		assert.NotNil(t, err)
	}

	// invalid addr
	r := &PrefixDescriptorIPReachabilityInfo{}
	_, err := r.serialize()
	assert.NotNil(t, err)

	// invalid route type
	o := &PrefixDescriptorOspfRouteType{}
	err = o.deserialize([]byte{0})
	assert.NotNil(t, err)
}

func TestLinkDescriptors(t *testing.T) {
	descriptors := []LinkDescriptor{
		&LinkDescriptorLinkIDs{
			LocalID:  uint32(2),
			RemoteID: uint32(3),
		},
		&LinkDescriptorIPv4InterfaceAddress{
			Address: net.ParseIP("1.1.1.1").To4(),
		},
		&LinkDescriptorIPv4NeighborAddress{
			Address: net.ParseIP("2.2.2.2").To4(),
		},
		&LinkDescriptorIPv6InterfaceAddress{
			Address: net.ParseIP("2601::").To16(),
		},
		&LinkDescriptorIPv6NeighborAddress{
			Address: net.ParseIP("2601::").To16(),
		},
		&LinkDescriptorMultiTopologyID{
			IDs: []uint16{0, 1, 2},
		},
	}

	for _, d := range descriptors {
		b, err := d.serialize()
		assert.Nil(t, err)
		b = append(b, uint8(0))
		err = d.deserialize(b)
		assert.NotNil(t, err)
	}
}

func TestNodeDescriptors(t *testing.T) {
	descriptors := []NodeDescriptor{
		&NodeDescriptorASN{
			ASN: uint32(64512),
		},
		&NodeDescriptorBgpLsID{
			ID: uint32(1),
		},
		&NodeDescriptorOspfAreaID{
			ID: uint32(1),
		},
		&NodeDescriptorIgpRouterIDIsIsNonPseudo{
			IsoNodeID: uint64(1),
		},
		&NodeDescriptorIgpRouterIDIsIsPseudo{
			IsoNodeID: uint64(1),
			PsnID:     uint8(1),
		},
		&NodeDescriptorIgpRouterIDOspfNonPseudo{
			RouterID: net.ParseIP("1.1.1.1").To4(),
		},
		&NodeDescriptorIgpRouterIDOspfPseudo{
			DrRouterID:       net.ParseIP("1.1.1.1").To4(),
			DrInterfaceToLAN: net.ParseIP("2.2.2.2").To4(),
		},
		&NodeDescriptorBgpRouterID{
			RouterID: net.ParseIP("1.1.1.1").To4(),
		},
		&NodeDescriptorMemberASN{
			ASN: uint32(64512),
		},
	}

	for _, d := range descriptors {
		b, err := d.serialize()
		assert.Nil(t, err)
		b = append(b, uint8(0))
		err = d.deserialize(b)
		assert.NotNil(t, err)
	}
}

func TestUpdateMessage(t *testing.T) {
	var adminGroup [32]bool
	adminGroup[31] = true
	var unreservedBW [8]float32
	unreservedBW[0] = 10000

	attrs := []PathAttr{
		&PathAttrMpUnreach{
			Nlri: []LinkStateNlri{
				&LinkStateNlriNode{
					ProtocolID: LinkStateNlriOSPFv2ProtocolID,
					ID:         uint64(56),
					LocalNodeDescriptors: []NodeDescriptor{
						&NodeDescriptorASN{
							ASN: uint32(64512),
						},
					},
				},
			},
		},
		&PathAttrMpReach{
			Nlri: []LinkStateNlri{
				&LinkStateNlriNode{
					ProtocolID: LinkStateNlriIsIsL1ProtocolID,
					ID:         uint64(55),
					LocalNodeDescriptors: []NodeDescriptor{
						&NodeDescriptorASN{
							ASN: uint32(64512),
						},
						&NodeDescriptorBgpLsID{
							ID: uint32(64512),
						},
						&NodeDescriptorOspfAreaID{
							ID: uint32(1),
						},
						&NodeDescriptorIgpRouterIDIsIsNonPseudo{
							IsoNodeID: uint64(2),
						},
						&NodeDescriptorIgpRouterIDIsIsPseudo{
							IsoNodeID: uint64(3),
							PsnID:     uint8(4),
						},
						&NodeDescriptorBgpRouterID{
							RouterID: net.ParseIP("172.16.1.1").To4(),
						},
						&NodeDescriptorMemberASN{
							ASN: uint32(64512),
						},
					},
				},
				&LinkStateNlriNode{
					ProtocolID: LinkStateNlriOSPFv2ProtocolID,
					ID:         uint64(56),
					LocalNodeDescriptors: []NodeDescriptor{
						&NodeDescriptorIgpRouterIDOspfNonPseudo{
							RouterID: net.ParseIP("172.16.1.201").To4(),
						},
						&NodeDescriptorIgpRouterIDOspfPseudo{
							DrRouterID:       net.ParseIP("172.16.1.202").To4(),
							DrInterfaceToLAN: net.ParseIP("172.16.1.203").To4(),
						},
					},
				},
				&LinkStateNlriLink{
					ProtocolID: LinkStateNlriOSPFv2ProtocolID,
					ID:         uint64(57),
					LocalNodeDescriptors: []NodeDescriptor{
						&NodeDescriptorASN{
							ASN: uint32(64512),
						},
					},
					RemoteNodeDescriptors: []NodeDescriptor{
						&NodeDescriptorASN{
							ASN: uint32(64512),
						},
					},
					LinkDescriptors: []LinkDescriptor{
						&LinkDescriptorLinkIDs{
							LocalID:  uint32(5),
							RemoteID: uint32(6),
						},
						&LinkDescriptorIPv4InterfaceAddress{
							Address: net.ParseIP("172.16.1.1").To4(),
						},
						&LinkDescriptorIPv4NeighborAddress{
							Address: net.ParseIP("172.16.1.2").To4(),
						},
						&LinkDescriptorIPv6InterfaceAddress{
							Address: net.ParseIP("2601::1").To16(),
						},
						&LinkDescriptorIPv6NeighborAddress{
							Address: net.ParseIP("2601::2").To16(),
						},
						&LinkDescriptorMultiTopologyID{
							IDs: []uint16{1, 2, 3, 4},
						},
					},
				},
				&LinkStateNlriIPv4Prefix{
					LinkStateNlriPrefix: LinkStateNlriPrefix{
						ProtocolID: LinkStateNlriOSPFv2ProtocolID,
						ID:         uint64(58),
						LocalNodeDescriptors: []NodeDescriptor{
							&NodeDescriptorASN{
								ASN: uint32(64512),
							},
						},
						PrefixDescriptors: []PrefixDescriptor{
							&PrefixDescriptorIPReachabilityInfo{
								Prefix:       net.ParseIP("172.16.1.4").To4(),
								PrefixLength: uint8(32),
							},
							&PrefixDescriptorMultiTopologyID{
								IDs: []uint16{10, 11, 12, 13},
							},
							&PrefixDescriptorOspfRouteType{
								RouteType: OspfRouteTypeExternal1,
							},
						},
					},
				},
			},
		},
		&PathAttrOrigin{
			Origin: OriginCodeIGP,
		},
		&PathAttrAsPath{
			Segments: []AsPathSegment{
				&AsPathSegmentSequence{
					Sequence: []uint16{64512},
				},
				&AsPathSegmentSet{
					Set: []uint16{64512},
				},
			}},
		&PathAttrLocalPref{
			Preference: uint32(200),
		},
		&PathAttrLinkState{
			NodeAttrs: []NodeAttr{
				&NodeAttrNodeFlagBits{
					Overload: true,
					Attached: true,
					External: true,
					ABR:      true,
					Router:   true,
					V6:       true,
				},
				&NodeAttrOpaqueNodeAttr{
					Data: []byte{0, 1, 2, 3},
				},
				&NodeAttrNodeName{
					Name: "test",
				},
				&NodeAttrIsIsAreaID{
					AreaID: uint32(64512),
				},
				&NodeAttrLocalIPv4RouterID{
					Address: net.ParseIP("172.16.1.201").To4(),
				},
				&NodeAttrLocalIPv6RouterID{
					Address: net.ParseIP("2601::1"),
				},
				&NodeAttrMultiTopologyID{
					IDs: []uint16{1, 2, 3, 4},
				},
			},
			LinkAttrs: []LinkAttr{
				&LinkAttrRemoteIPv4RouterID{
					Address: net.ParseIP("172.16.1.202").To4(),
				},
				&LinkAttrRemoteIPv6RouterID{
					Address: net.ParseIP("2601::2"),
				},
				&LinkAttrAdminGroup{
					Group: adminGroup,
				},
				&LinkAttrMaxLinkBandwidth{
					BytesPerSecond: 10000,
				},
				&LinkAttrMaxReservableLinkBandwidth{
					BytesPerSecond: 20000,
				},
				&LinkAttrUnreservedBandwidth{
					BytesPerSecond: unreservedBW,
				},
				&LinkAttrTEDefaultMetric{
					Metric: uint32(50),
				},
				&LinkAttrLinkProtectionType{
					ExtraTraffic:        true,
					Unprotected:         true,
					Shared:              true,
					DedicatedOneToOne:   true,
					DedicatedOnePlusOne: true,
					Enhanced:            true,
				},
				&LinkAttrMplsProtocolMask{
					LDP:    true,
					RsvpTE: true,
				},
				&LinkAttrIgpMetric{
					Type:   LinkAttrIgpMetricIsIsSmallType,
					Metric: 42,
				},
				&LinkAttrIgpMetric{
					Type:   LinkAttrIgpMetricOspfType,
					Metric: 42,
				},
				&LinkAttrIgpMetric{
					Type:   LinkAttrIgpMetricIsIsWideType,
					Metric: 42,
				},
				&LinkAttrSharedRiskLinkGroup{
					Groups: []uint32{24, 15, 16},
				},
				&LinkAttrOpaqueLinkAttr{
					Data: []byte{1, 2, 3, 4},
				},
				&LinkAttrLinkName{
					Name: "test",
				},
				&LinkAttrPeerNodeSID{
					BaseSID: BaseSID{
						Value:  true,
						Local:  true,
						Weight: 1,
						Variable: &SIDLabel{
							Label: 50,
						},
					},
				},
				&LinkAttrPeerNodeSID{
					BaseSID: BaseSID{
						Value:  true,
						Local:  true,
						Weight: 1,
						Variable: &SRGBOffset{
							Offset: 50,
						},
					},
				},
				&LinkAttrPeerNodeSID{
					BaseSID: BaseSID{
						Value:  true,
						Local:  true,
						Weight: 1,
						Variable: &IPv6SID{
							Address: net.ParseIP("2601::"),
						},
					},
				},
				&LinkAttrPeerAdjSID{
					BaseSID: BaseSID{
						Value:  true,
						Local:  true,
						Weight: 1,
						Variable: &SIDLabel{
							Label: 50,
						},
					},
				},
				&LinkAttrPeerAdjSID{
					BaseSID: BaseSID{
						Value:  true,
						Local:  true,
						Weight: 1,
						Variable: &SRGBOffset{
							Offset: 50,
						},
					},
				},
				&LinkAttrPeerAdjSID{
					BaseSID: BaseSID{
						Value:  true,
						Local:  true,
						Weight: 1,
						Variable: &IPv6SID{
							Address: net.ParseIP("2601::"),
						},
					},
				},
				&LinkAttrPeerAdjSID{
					BaseSID: BaseSID{
						Value:  true,
						Local:  true,
						Weight: 1,
						Variable: &SIDLabel{
							Label: 50,
						},
					},
				},
				&LinkAttrPeerAdjSID{
					BaseSID: BaseSID{
						Value:  true,
						Local:  true,
						Weight: 1,
						Variable: &SRGBOffset{
							Offset: 50,
						},
					},
				},
				&LinkAttrPeerAdjSID{
					BaseSID: BaseSID{
						Value:  true,
						Local:  true,
						Weight: 1,
						Variable: &IPv6SID{
							Address: net.ParseIP("2601::"),
						},
					},
				},
				&LinkAttrPeerSetSID{
					BaseSID: BaseSID{
						Value:  true,
						Local:  true,
						Weight: 1,
						Variable: &IPv6SID{
							Address: net.ParseIP("2601::"),
						},
					},
				},
			},
			PrefixAttrs: []PrefixAttr{
				&PrefixAttrIgpFlags{
					IsIsDown:          true,
					OspfNoUnicast:     true,
					OspfLocalAddress:  true,
					OspfPropagateNssa: true,
				},
				&PrefixAttrIgpRouteTag{
					Tags: []uint32{1, 2, 3, 4},
				},
				&PrefixAttrIgpExtendedRouteTag{
					Tags: []uint64{1, 2, 3, 4},
				},
				&PrefixAttrPrefixMetric{
					Metric: 35,
				},
				&PrefixAttrOspfForwardingAddress{
					Address: net.ParseIP("172.16.1.201").To4(),
				},
				&PrefixAttrOspfForwardingAddress{
					Address: net.ParseIP("2601::1"),
				},
				&PrefixAttrOpaquePrefixAttribute{
					Data: []byte{1, 2, 3, 4},
				},
			},
		},
	}

	u := &UpdateMessage{
		PathAttrs: attrs,
	}

	assert.Equal(t, u.MessageType(), UpdateMessageType)

	b, err := u.serialize()
	if err != nil {
		t.Fatal(err)
	}

	m, err := messagesFromBytes(b)
	if err != nil {
		t.Fatal(err)
	}

	if len(m) != 1 {
		t.Fatal("invalid length of messages deserialized")
	}

	um, ok := m[0].(*UpdateMessage)
	if !ok {
		t.Fatal("not an update message")
	}

	if !assert.Equal(t, len(um.PathAttrs), len(attrs)) {
		t.Fatal("attr len not equal")
	}

	for i, a := range attrs {
		assert.Equal(t, a, um.PathAttrs[i])
	}
}
