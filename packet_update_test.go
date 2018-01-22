package bgpls

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

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
}

func TestPrefixDescriptors(t *testing.T) {
	descriptors := []PrefixDescriptor{
		&PrefixDescriptorIPReachabilityInfo{
			PrefixLength: uint8(32),
			Prefix:       net.ParseIP("1.2.3.4").To4(),
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
			},
			PrefixAttrs: []PrefixAttr{
				&PrefixAttrIgpFlags{
					IsIsDown: true,
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
