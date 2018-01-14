package bgpls

import (
	"errors"
	"net"
	"sync"
)

// ErrCollectorStopped is returned when an operation is not valid due to the collector being stopped
var ErrCollectorStopped = errors.New("collector is stopped")

// Collector is a BGP Link-State collector
type Collector interface {
	Events() (<-chan Event, error)
	Config() *CollectorConfig
	AddNeighbor(c *NeighborConfig) error
	DeleteNeighbor(address net.IP) error
	Neighbors() ([]*NeighborConfig, error)
	Stop()
}

type standardCollector struct {
	running   bool
	events    chan Event
	config    *CollectorConfig
	neighbors map[string]neighbor
	*sync.RWMutex
}

// CollectorConfig is the configuration for the Collector
// EventBufferSize is the size of the buffered Events channel
type CollectorConfig struct {
	ASN             uint32
	RouterID        net.IP
	EventBufferSize uint64
}

// NewCollector creates a Collector
func NewCollector(config *CollectorConfig) (Collector, error) {
	c := &standardCollector{
		running:   true,
		events:    make(chan Event, config.EventBufferSize),
		config:    config,
		neighbors: make(map[string]neighbor),
		RWMutex:   &sync.RWMutex{},
	}

	return c, nil
}

// Events returns the events channel or an error if the collector has been stopped
// The events channel is buffered, its size is configurable via CollectorConfig
func (c *standardCollector) Events() (<-chan Event, error) {
	c.RLock()
	defer c.RUnlock()
	if c.running {
		return c.events, nil
	}
	return nil, ErrCollectorStopped
}

// Config returns the configuration of the Collector
func (c *standardCollector) Config() *CollectorConfig {
	c.RLock()
	defer c.RUnlock()
	return c.config
}

// AddNeighbor initializes a new BGP-LS neighbor.
// An error is returned if the collector is stopped or the neighbor already exists
func (c *standardCollector) AddNeighbor(config *NeighborConfig) error {
	c.Lock()
	defer c.Unlock()

	if !c.running {
		return ErrCollectorStopped
	}

	_, exists := c.neighbors[config.Address.String()]
	if exists {
		return errors.New("neighbor exists")
	}

	n, err := newNeighbor(c.config.ASN, config, c.events)
	if err != nil {
		return err
	}

	c.neighbors[config.Address.String()] = n

	event := newEventNeighborAdded(config)
	c.events <- event

	return nil
}

// Neighbors returns the configuration of all neighbors
func (c *standardCollector) Neighbors() ([]*NeighborConfig, error) {
	c.RLock()
	defer c.RUnlock()

	if !c.running {
		return nil, ErrCollectorStopped
	}

	configs := make([]*NeighborConfig, 0)
	for _, n := range c.neighbors {
		configs = append(configs, n.config())
	}

	return configs, nil
}

// DeleteNeighbor shuts down and removes a neighbor from the collector.
// An error is returned if the collector is stopped or the neighbor does not exist
func (c *standardCollector) DeleteNeighbor(address net.IP) error {
	c.Lock()
	defer c.Unlock()

	if !c.running {
		return ErrCollectorStopped
	}

	n, exists := c.neighbors[address.String()]
	if !exists {
		return errors.New("neighbor does not exist")
	}

	n.shut()
	delete(c.neighbors, address.String())

	event := newEventNeighborRemoved(n.config())
	c.events <- event

	return nil
}

// Stop the collector and all neighbors
func (c *standardCollector) Stop() {
	c.Lock()
	defer c.Unlock()

	if !c.running {
		return
	}

	wg := &sync.WaitGroup{}
	for _, n := range c.neighbors {
		wg.Add(1)
		n := n
		go func() {
			n.shut()
			wg.Done()
		}()
	}
	wg.Wait()

	c.running = false
	close(c.events)
}
