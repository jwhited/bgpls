package bgpls

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUpdateMessage(t *testing.T) {
	attrs := []PathAttr{
		&PathAttrOrigin{
			Origin: OriginCodeIGP,
		},
		&PathAttrAsPath{
			Segments: []AsPathSegment{
				&AsPathSegmentSequence{
					Sequence: []uint16{64512},
				},
			}},
		&PathAttrLocalPref{
			Preference: uint32(200),
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

	assert.Equal(t, len(um.PathAttrs), len(attrs))

	for i, a := range attrs {
		assert.Equal(t, a, um.PathAttrs[i])
	}
}
