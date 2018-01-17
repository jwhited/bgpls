package bgpls

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCollector(t *testing.T) {
	collectorConfig := &CollectorConfig{
		ASN:             1234,
		RouterID:        net.ParseIP("172.16.1.106"),
		EventBufferSize: 1024,
	}

	c, err := NewCollector(collectorConfig)
	if err != nil {
		t.Fatal(err)
	}

	d := c.Config()
	assert.Equal(t, d, collectorConfig)

	neighborConfig := &NeighborConfig{
		Address:  net.ParseIP("127.0.0.1"),
		ASN:      1234,
		HoldTime: time.Second * 30,
	}

	err = c.AddNeighbor(neighborConfig)
	if err != nil {
		t.Fatal(err)
	}

	err = c.AddNeighbor(neighborConfig)
	assert.NotNil(t, err)

	_, err = c.Events()
	if err != nil {
		t.Fatal(err)
	}

	neighbors, err := c.Neighbors()
	if err != nil {
		t.Fatal(err)
	}
	assert.Len(t, neighbors, 1)
	assert.Equal(t, neighbors[0], neighborConfig)

	err = c.DeleteNeighbor(net.ParseIP("127.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}

	err = c.DeleteNeighbor(net.ParseIP("127.0.0.2"))
	assert.NotNil(t, err)

	c.Stop()

	_, err = c.Events()
	assert.Equal(t, err, ErrCollectorStopped)

	err = c.AddNeighbor(neighborConfig)
	assert.Equal(t, err, ErrCollectorStopped)

	_, err = c.Neighbors()
	assert.Equal(t, err, ErrCollectorStopped)

	c.Stop()
}
