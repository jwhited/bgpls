package bgpls

import (
	"net"
	"time"
)

// NeighborConfig is the configuration for a BGP-LS neighbor.
type NeighborConfig struct {
	Address  net.IP
	ASN      uint32
	HoldTime time.Duration
}

type neighbor interface {
	fsm
	config() *NeighborConfig
}

type standardNeighbor struct {
	fsm
	c *NeighborConfig
}

func newNeighbor(localASN uint32, config *NeighborConfig, events chan Event) (neighbor, error) {
	n := &standardNeighbor{
		c: config,
	}

	n.fsm = newFSM(n.config(), events, localASN, 179)

	return n, nil
}

func (n *standardNeighbor) config() *NeighborConfig {
	return n.c
}
