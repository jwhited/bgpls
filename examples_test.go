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
		case *bgpls.EventNeighborUpdateReceived:
			var addr net.IP
			var maxLinkBW float32
			var maxReservableLinkBW float32
			var reservedBW float32

			log.Printf("neighbor %s update message", e.Neighbor().Address)
			// extracting link address and bandwidth reservation (assuming mpls-te links) attributes from the update message
			for _, a := range e.Message.PathAttrs {
				switch b := a.(type) {
				case *bgpls.PathAttrMpReach:
					switch e := b.NLRI.(type) {
					case *bgpls.NLRILinkState:
						for _, f := range e.Links {
							for _, g := range f.LinkDescriptors {
								switch h := g.(type) {
								case *bgpls.LinkDescriptorIPv4InterfaceAddress:
									addr = h.Address
									break
								}
							}
						}
					}
				case *bgpls.PathAttrLinkState:
					for _, c := range b.LinkAttrs {
						switch d := c.(type) {
						case *bgpls.LinkAttrMaxLinkBandwidth:
							maxLinkBW = d.BytesPerSecond
						case *bgpls.LinkAttrMaxReservableLinkBandwidth:
							maxReservableLinkBW = d.BytesPerSecond
						case *bgpls.LinkAttrUnreservedBandwidth:
							reservedBW = maxReservableLinkBW
							for i := 0; i < 8; i++ {
								reservedBW = reservedBW + (maxReservableLinkBW - d.BytesPerSecond[i])
							}
						}
					}
				}
			}

			if addr != nil {
				log.Printf("link: %s maxBW: %f maxReservableBW: %f unreservedBW: %f", addr, maxLinkBW, maxReservableLinkBW, reservedBW)
			}
		}
	}
}
