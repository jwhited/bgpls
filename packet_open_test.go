package bgpls

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCapOptParam(t *testing.T) {
	c := &capabilityOptParam{}
	assert.Equal(t, c.optParamType(), capabilityOptParamType)

	// empty caps
	_, err := c.serialize()
	assert.NotNil(t, err)

	// error serializing cap

	// len < 2 deserializing
	err = c.deserialize([]byte{0})
	assert.NotNil(t, err)

	// invalid param len
	err = c.deserialize([]byte{0, 2, 0})
	assert.NotNil(t, err)

	// deserialize capUnknown
	u := &capUnknown{code: 100}
	b, err := u.serialize()
	if err != nil {
		t.Fatal(err)
	}

	err = c.deserialize(b)
	assert.Nil(t, err)
}

func TestCapUnknown(t *testing.T) {
	c := &capUnknown{}
	err := c.deserialize([]byte{0, 0, 0})
	assert.Nil(t, err)
	_, err = c.serialize()
	assert.Nil(t, err)
	assert.Equal(t, c.capabilityCode(), capabilityCode(0))
}

func TestCapMultiproto(t *testing.T) {
	c := &capMultiproto{}
	err := c.deserialize([]byte{0})
	assert.NotNil(t, err)
	assert.Equal(t, c.capabilityCode(), capCodeMultiproto)
}

func TestCapFourOctetAs(t *testing.T) {
	c := &capFourOctetAs{}
	err := c.deserialize([]byte{0})
	assert.NotNil(t, err)
	assert.Equal(t, c.capabilityCode(), capCodeFourOctetAs)
}

func TestValidateOpenMessage(t *testing.T) {
	// valid
	o, err := newOpenMessage(1, time.Second*3, net.ParseIP("172.16.1.1"))
	if err != nil {
		t.Fatal(err)
	}
	err = validateOpenMessage(o, 1)
	if err != nil {
		t.Fatal(err)
	}

	// asn mimatch
	err = validateOpenMessage(o, 2)
	assert.NotNil(t, err)

	// bad version
	o.version = 2
	err = validateOpenMessage(o, 1)
	assert.NotNil(t, err)

	// bad hold time
	o, err = newOpenMessage(1, time.Second*2, net.ParseIP("172.16.1.1"))
	if err != nil {
		t.Fatal(err)
	}
	err = validateOpenMessage(o, 1)
	assert.NotNil(t, err)

	// bad bgp id
	o, err = newOpenMessage(1, time.Second*3, []byte{0, 0, 0, 0})
	if err != nil {
		t.Fatal(err)
	}
	err = validateOpenMessage(o, 1)
	assert.NotNil(t, err)

	// bad opt params
	o.holdTime = 3
	o.bgpID = 1
	o.optParams = nil
	err = validateOpenMessage(o, 1)
	assert.NotNil(t, err)

	// test 4 octet asn
	o, err = newOpenMessage(523456, time.Second*3, net.ParseIP("172.16.1.1"))
	if err != nil {
		t.Fatal(err)
	}
	err = validateOpenMessage(o, 523456)
	assert.Nil(t, err)

	// 4 octet indicated but not found in cap
	o, err = newOpenMessage(uint32(asTrans), time.Second*3, net.ParseIP("172.16.1.1"))
	if err != nil {
		t.Fatal(err)
	}
	o.optParams = []optParam{
		&capabilityOptParam{
			caps: []capability{
				&capMultiproto{
					afi:  BgpLsAfi,
					safi: BgpLsSafi,
				},
			},
		},
	}
	err = validateOpenMessage(o, 5)
	assert.NotNil(t, err)

	// bad peer asn in 4 octet cap
	o, err = newOpenMessage(uint32(asTrans), time.Second*3, net.ParseIP("172.16.1.1"))
	if err != nil {
		t.Fatal(err)
	}
	o.optParams = []optParam{
		&capabilityOptParam{
			caps: []capability{
				&capFourOctetAs{
					asn: 6,
				},
				&capMultiproto{
					afi:  BgpLsAfi,
					safi: BgpLsSafi,
				},
			},
		},
	}
	err = validateOpenMessage(o, 5)
	assert.NotNil(t, err)
}

func TestOpenMessage(t *testing.T) {
	asn := uint16(64512)
	holdTime := time.Second * 30
	bgpID := net.ParseIP("172.16.0.1")

	o, err := newOpenMessage(uint32(asn), holdTime, bgpID)
	if err != nil {
		t.Fatal(err)
	}

	b, err := o.serialize()
	if err != nil {
		t.Fatal(err)
	}

	m, err := messagesFromBytes(b)
	if err != nil {
		t.Fatal(err)
	}

	if len(m) != 1 {
		t.Fatalf("invalid number of messages deserialized: %d", len(m))
	}

	f, ok := m[0].(*openMessage)
	if !ok {
		t.Fatal("not an open message")
	}

	assert.Equal(t, asn, f.asn)
	assert.Equal(t, uint16(holdTime/time.Second), f.holdTime)
	assert.Equal(t, binary.BigEndian.Uint32(bgpID[12:16]), f.bgpID)
	assert.Equal(t, f.MessageType(), OpenMessageType)
	assert.Equal(t, len(o.optParams), len(f.optParams))
	assert.Equal(t, f.version, uint8(4))

	if len(f.optParams) != 1 {
		t.Fatal("missing optional param")
	}

	p, ok := f.optParams[0].(*capabilityOptParam)
	if !ok {
		t.Fatal("not capability optional param")
	}

	if len(p.caps) != 2 {
		t.Fatal("missing capabilities")
	}

	q, ok := p.caps[0].(*capFourOctetAs)
	if !ok {
		t.Fatal("missing four octet ASN capability")
	}
	assert.Equal(t, q.asn, uint32(asn))

	r, ok := p.caps[1].(*capMultiproto)
	if !ok {
		t.Fatal("missing multiprotocol capability")
	}
	assert.Equal(t, r.capabilityCode(), capCodeMultiproto)
	assert.Equal(t, r.afi, BgpLsAfi)
	assert.Equal(t, r.safi, BgpLsSafi)
}
