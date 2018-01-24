package bgpls

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestEvent(t *testing.T) {
	conf := &NeighborConfig{
		ASN:      64512,
		HoldTime: time.Second * 30,
		Address:  net.ParseIP("172.16.0.1").To4(),
	}

	cases := []struct {
		event Event
		t     EventType
		s     string
	}{
		{newEventNeighborAdded(conf), EventTypeNeighborAdded, "neighbor added to collector"},
		{newEventNeighborErr(conf, errors.New("test")), EventTypeNeighborErr, "neighbor error"},
		{newEventNeighborHoldTimerExpired(conf), EventTypeNeighborHoldTimerExpired, "neighbor hold timer expired"},
		{newEventNeighborNotificationReceived(conf, &NotificationMessage{}), EventTypeNeighborNotificationReceived, "received notification message from neighbor"},
		{newEventNeighborRemoved(conf), EventTypeNeighborRemoved, "neighbor removed from collector"},
		{newEventNeighborStateTransition(conf, IdleState), EventTypeNeighborStateTransition, "neighbor state changed"},
		{newEventNeighborUpdateReceived(conf, &UpdateMessage{}), EventTypeNeighborUpdateReceived, "received update message from neighbor"},
	}

	for _, c := range cases {
		assert.Equal(t, c.event.Type(), c.t)
		assert.Equal(t, c.event.Type().String(), c.s)
		_ = c.event.Neighbor()
		_ = c.event.Timestamp()
	}
}
