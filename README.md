# bgpls
A BGP Link-State collector library in Go. Note that the API is subject to change.

Documentation: [https://godoc.org/github.com/jwhited/bgpls](https://godoc.org/github.com/jwhited/bgpls)

## Supported RFCs
[RFC7752](https://tools.ietf.org/html/rfc7752)

## Example Usage
```golang
collectorConfig := bgpls.CollectorConfig{
  ASN:             uint32(64512),
  RouterID:        net.ParseIP("1.2.3.4"),
  EventBufferSize: 1024,
}

collector, err := bgpls.NewCollector(collectorConfig)
if err != nil {
  log.Fatal(err)
}

neighborConfig := bgpls.NeighborConfig{
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
  logger := logrus.WithFields(logrus.Fields{
    "neighbor": event.Neighbor().Address.String(),
    "event":    event.Type(),
  })

  switch e := event.(type) {
  case *bgpls.EventNeighborErr:
    logger.WithField("error", e.Err).Info()
  case *bgpls.EventNeighborStateTransition:
    logger.WithField("state", e.State).Info()
  case *bgpls.EventNeighborUpdateReceived:
    logger.Info()
  }
}
```
