package bgpls_test

import (
	"log"
	"net"
	"time"

	"github.com/jwhited/bgpls"
)

func ExampleCollector() {
	collectorConfig := &bgpls.CollectorConfig{
		ASN:             uint32(64512),
		RouterID:        net.ParseIP("1.2.3.4"),
		EventBufferSize: 1024,
	}

	collector, err := bgpls.NewCollector(collectorConfig)
	if err != nil {
		log.Fatal(err)
	}

	neighborConfig := &bgpls.NeighborConfig{
		Address:  net.ParseIP("172.16.1.201"),
		ASN:      uint32(64512),
		HoldTime: time.Second * 30,
	}

	err = collector.AddNeighbor(neighborConfig)
	if err != nil {
		log.Fatal(err)
	}

	eventsChan, err := collector.Events()
	if err != nil {
		log.Fatal(err)
	}

	for {
		event := <-eventsChan
		// all Event types can be found in event.go (EventNeighbor**)
		switch e := event.(type) {
		case *bgpls.EventNeighborErr:
			log.Printf("neighbor %s, err: %v", e.Neighbor().Address, e.Err)
		case *bgpls.EventNeighborStateTransition:
			log.Printf("neighbor %s, state transition: %v", e.Neighbor().Address, e.State)
		case *bgpls.EventNeighborNotificationReceived:
			log.Printf("neighbor %s notification message code: %v", e.Neighbor().Address, e.Message.Code)
		case *bgpls.EventNeighborUpdateReceived:
			log.Printf("neighbor %s update message", e.Neighbor().Address)
		}
	}
}
