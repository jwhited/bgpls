package bgpls

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"
)

// FSMState describes the state of a neighbor's fsm
type FSMState uint8

// FSMState values
const (
	DisabledState FSMState = iota
	IdleState
	ConnectState
	ActiveState
	OpenSentState
	OpenConfirmState
	EstablishedState
)

func (s FSMState) String() string {
	switch s {
	case DisabledState:
		return "disabled"
	case IdleState:
		return "idle"
	case ConnectState:
		return "connect"
	case ActiveState:
		return "active"
	case OpenSentState:
		return "openSent"
	case OpenConfirmState:
		return "openConfirm"
	case EstablishedState:
		return "established"
	default:
		return "unknown state"
	}
}

var (
	errInvalidStateTransition = errors.New("invalid state transition")
)

var (
	// A HoldTimer value of 4 minutes is suggested.
	longHoldTime = time.Minute * 4
)

const (
	// The exact value of the ConnectRetryTimer is a local matter, but it
	// SHOULD be sufficiently large to allow TCP initialization.
	connectRetryTime = time.Second * 5
)

type fsm interface {
	idle() FSMState
	connect() FSMState
	openSent() FSMState
	openConfirm() FSMState
	established() FSMState
	terminate()
}

type standardFSM struct {
	port               int
	events             chan Event
	disable            chan interface{}
	neighborConfig     *NeighborConfig
	localASN           uint32
	conn               net.Conn
	readerErr          chan error
	closeReader        chan struct{}
	readerClosed       chan struct{}
	msgCh              chan Message
	keepAliveTime      time.Duration
	keepAliveTimer     *time.Timer
	holdTime           time.Duration
	holdTimer          *time.Timer
	connectRetryTimer  *time.Timer
	running            bool
	outboundConnErr    chan error
	outboundConn       chan net.Conn
	cancelOutboundDial context.CancelFunc
	*sync.Mutex
}

func newFSM(c *NeighborConfig, events chan Event, localASN uint32, port int) fsm {
	f := &standardFSM{
		port:              port,
		events:            events,
		disable:           make(chan interface{}),
		neighborConfig:    c,
		localASN:          localASN,
		keepAliveTime:     time.Duration(int64(c.HoldTime) / 3).Truncate(time.Second),
		keepAliveTimer:    time.NewTimer(0),
		holdTime:          c.HoldTime,
		holdTimer:         time.NewTimer(0),
		connectRetryTimer: time.NewTimer(0),
		Mutex:             &sync.Mutex{},
	}

	// drain all timers so they can be reset
	drainTimers(f.keepAliveTimer, f.holdTimer, f.connectRetryTimer)

	f.running = true
	go f.loop()

	return f
}

func (f *standardFSM) terminate() {
	f.Lock()
	defer f.Unlock()
	if !f.running {
		return
	}

	f.disable <- nil
	<-f.disable
	f.running = false
}

func (f *standardFSM) dialNeighbor() {
	dialer := &net.Dialer{}
	ctx, cancel := context.WithCancel(context.Background())
	f.cancelOutboundDial = cancel

	go func() {
		conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(f.neighborConfig.Address.String(), strconv.Itoa(f.port)))
		if err != nil {
			f.outboundConnErr <- err
			return
		}

		f.outboundConn <- conn
	}()
}

func (f *standardFSM) idle() FSMState {
	// initializes all BGP resources for the peer connection
	f.readerErr = make(chan error)
	f.closeReader = make(chan struct{})
	f.readerClosed = make(chan struct{})
	f.msgCh = make(chan Message)
	f.outboundConnErr = make(chan error)
	f.outboundConn = make(chan net.Conn)

	// starts the ConnectRetryTimer with the initial value
	f.connectRetryTimer.Reset(connectRetryTime)

	// initiates a TCP connection to the other BGP peer
	f.dialNeighbor()

	// changes its state to Connect
	return ConnectState
}

// cleanupConnAndReader closes the connection,
// the reader close signal channel, and the messages channel
func (f *standardFSM) cleanupConnAndReader() {
	f.conn.Close()
	close(f.closeReader)
	<-f.readerClosed
	close(f.msgCh)
}

func (f *standardFSM) connect() FSMState {
Loop:
	for {
		select {
		case <-f.disable:
			drainTimers(f.connectRetryTimer)
			// drain the dialer and transition to DisabledState
			f.cancelOutboundDial()
			select {
			case <-f.outboundConn:
			case <-f.outboundConnErr:
			}
			return DisabledState
		case <-f.connectRetryTimer.C:
			/*
				In response to the ConnectRetryTimer_Expires event (Event 9), the
				local system:
				  - drops the TCP connection,
				  - restarts the ConnectRetryTimer,
				  - stops the DelayOpenTimer and resets the timer to zero,
				  - initiates a TCP connection to the other BGP peer,
				  - continues to listen for a connection that may be initiated by
				    the remote BGP peer, and
				  - stays in the Connect state.
			*/
			f.cancelOutboundDial()
			// canceling races with the dialer so it must be drained
			select {
			case conn := <-f.outboundConn:
				f.conn = conn
				go f.read()
				break Loop
			case <-f.outboundConnErr:
			}
			// timer already drained
			f.connectRetryTimer.Reset(connectRetryTime)
			f.dialNeighbor()
		case err := <-f.outboundConnErr:
			/*
				If the TCP connection fails (Event 18), the local system checks
				the DelayOpenTimer.  If the DelayOpenTimer is running, the local
				system:
				  - restarts the ConnectRetryTimer with the initial value,
				  - stops the DelayOpenTimer and resets its value to zero,
				  - continues to listen for a connection that may be initiated by
				    the remote BGP peer, and
				  - changes its state to Active.
			*/
			drainTimers(f.connectRetryTimer)
			next := f.handleErr(fmt.Errorf("error connecting to neighbor: %v", err), ActiveState)
			if next != DisabledState {
				f.connectRetryTimer.Reset(connectRetryTime)
			}
			return next
		case conn := <-f.outboundConn:
			/*
				If the TCP connection succeeds (Event 16 or Event 17), the local
				system checks the DelayOpen attribute prior to processing.
				...
				If the DelayOpen attribute is set to FALSE, the local system:
				  - stops the ConnectRetryTimer (if running) and sets the
				    ConnectRetryTimer to zero,
				  - completes BGP initialization
				  - sends an OPEN message to its peer,
				  - sets the HoldTimer to a large value, and
				  - changes its state to OpenSent.
			*/
			drainTimers(f.connectRetryTimer)
			f.conn = conn
			go f.read()
			break Loop
		}
	}

	o, err := newOpenMessage(f.localASN, f.holdTime, f.neighborConfig.Address)
	if err != nil {
		f.cleanupConnAndReader()
		return f.handleErr(fmt.Errorf("error creating open message: %v", err), IdleState)
	}
	b, err := o.serialize()
	if err != nil {
		panic("bug serializing open message")
	}

	_, err = f.conn.Write(b)
	if err != nil {
		f.cleanupConnAndReader()
		return f.handleErr(fmt.Errorf("error sending open message: %v", err), IdleState)
	}

	f.holdTimer.Reset(longHoldTime)

	return OpenSentState
}

func (f *standardFSM) active() FSMState {
	select {
	case <-f.disable:
		drainTimers(f.connectRetryTimer)
		return DisabledState
	case <-f.connectRetryTimer.C:
		/*
			In response to a ConnectRetryTimer_Expires event (Event 9), the
			local system:
				- restarts the ConnectRetryTimer (with initial value),
				- initiates a TCP connection to the other BGP peer,
				- continues to listen for a TCP connection that may be initiated
					by a remote BGP peer, and
				- changes its state to Connect.
		*/
		f.connectRetryTimer.Reset(connectRetryTime)
		f.dialNeighbor()
		return ConnectState
	}
}

// sendEvent sends the provided event on the events channel and
// returns the provided FSMState unless a disable signal is received
// in which case DisabledState is returned
func (f *standardFSM) sendEvent(e Event, nextState FSMState) FSMState {
	select {
	case f.events <- e:
		return nextState
	case <-f.disable:
		return DisabledState
	}
}

// handlerErr checks the provided err to see if a notification can be unwrapped
// and if so, sends it to the neighbor.
//
// The provided FSMState is returned unless a disable signal is received while
// trying to send on the events channel in which case DisabledState is returned.
func (f *standardFSM) handleErr(err error, nextState FSMState) FSMState {
	if err, ok := err.(*errWithNotification); ok {
		f.sendNotification(err.code, err.subcode, err.data)
	}

	return f.sendEvent(newEventNeighborErr(f.neighborConfig, err), nextState)
}

func (f *standardFSM) handleHoldTimerExpired() FSMState {
	/*
	   If the HoldTimer_Expires (Event 10), the local system:
	   	- sends a NOTIFICATION message with the error code Hold Timer
	   		Expired,
	   	- sets the ConnectRetryTimer to zero,
	   	- releases all BGP resources,
	   	- drops the TCP connection,
	   	- increments the ConnectRetryCounter,
	   	- (optionally) performs peer oscillation damping if the
	   		DampPeerOscillations attribute is set to TRUE, and
	   	- changes its state to Idle.
	*/
	f.sendHoldTimerExpired()
	f.cleanupConnAndReader()

	return f.sendEvent(newEventNeighborHoldTimerExpired(f.neighborConfig), IdleState)
}

func (f *standardFSM) read() {
	defer close(f.readerClosed)

	for {
		select {
		case <-f.closeReader:
			return
		default:
			buff := make([]byte, 4096)
			n, err := f.conn.Read(buff)
			if err != nil {
				select {
				case f.readerErr <- err:
				case <-f.closeReader:
				}
				return
			}
			buff = buff[:n]

			msgs, err := messagesFromBytes(buff)
			if err != nil {
				select {
				case f.readerErr <- err:
				case <-f.closeReader:
				}

				return
			}

			for _, m := range msgs {
				select {
				case f.msgCh <- m:
				case <-f.closeReader:
					return
				}
			}
		}
	}
}

func (f *standardFSM) sendHoldTimerExpired() error {
	return f.sendNotification(NotifErrCodeHoldTimerExpired, 0, nil)
}

// handleUnexpectedMessageType sends the appropriate notification message to the
// neighbor and generates an EventNeighborErr
func (f *standardFSM) handleUnexpectedMessageType(received MessageType, next FSMState) FSMState {
	b := make([]byte, 1)
	b[0] = uint8(received)
	f.sendNotification(NotifErrCodeMessageHeader, NotifErrSubcodeBadType, b)
	return f.sendEvent(newEventNeighborErr(f.neighborConfig, fmt.Errorf("unexpected message type: %s", received)), next)
}

func (f *standardFSM) openSent() FSMState {
	select {
	case <-f.disable:
		f.sendCease()
		drainTimers(f.holdTimer)
		f.cleanupConnAndReader()
		return DisabledState
	case err := <-f.readerErr:
		/*
			If a TcpConnectionFails event (Event 18) is received, the local
			system:
				- closes the BGP connection,
				- restarts the ConnectRetryTimer,
				- continues to listen for a connection that may be initiated by
					the remote BGP peer, and
				- changes its state to Active.
		*/
		var next FSMState
		// check if err is connection related or not - Active vs Idle
		_, isOpError := err.(*net.OpError)
		if isOpError {
			next = f.handleErr(err, ActiveState)
			if next != DisabledState {
				f.connectRetryTimer.Reset(connectRetryTime)
			}
		} else {
			next = f.handleErr(err, IdleState)
		}
		drainTimers(f.holdTimer)
		f.cleanupConnAndReader()
		return next
	case <-f.holdTimer.C:
		return f.handleHoldTimerExpired()
	case m := <-f.msgCh:
		open, isOpen := m.(*openMessage)
		if !isOpen {
			var next FSMState
			notif, isNotif := m.(*NotificationMessage)
			if isNotif {
				next = f.sendEvent(newEventNeighborNotificationReceived(f.neighborConfig, notif), IdleState)
			} else {
				next = f.handleUnexpectedMessageType(m.MessageType(), IdleState)
			}

			drainTimers(f.holdTimer)
			f.cleanupConnAndReader()
			return next
		}

		err := validateOpenMessage(open, f.neighborConfig.ASN)
		if err != nil {
			next := f.handleErr(err, IdleState)
			drainTimers(f.holdTimer)
			f.cleanupConnAndReader()
			return next
		}

		if float64(open.holdTime) < f.holdTime.Seconds() {
			f.holdTime = time.Duration(int64(open.holdTime) * int64(time.Second))
			f.keepAliveTime = (f.holdTime / 3).Truncate(time.Second)
		}

		err = f.sendKeepAlive()
		if err != nil {
			next := f.handleErr(err, IdleState)
			drainTimers(f.holdTimer)
			f.cleanupConnAndReader()
			return next
		}

		f.drainAndResetHoldTimer()
		return OpenConfirmState
	}
}

func (f *standardFSM) sendKeepAlive() error {
	ka := &keepAliveMessage{}
	b, err := ka.serialize()
	if err != nil {
		panic("bug serializing keepalive message")
	}
	_, err = f.conn.Write(b)
	return err
}

func (f *standardFSM) openConfirm() FSMState {
	for {
		select {
		case <-f.disable:
			f.sendCease()
			drainTimers(f.holdTimer)
			f.cleanupConnAndReader()
			return DisabledState
		case err := <-f.readerErr:
			next := f.handleErr(err, IdleState)
			drainTimers(f.holdTimer)
			f.cleanupConnAndReader()
			return next
		case <-f.holdTimer.C:
			return f.handleHoldTimerExpired()
		case m := <-f.msgCh:
			_, isKeepAlive := m.(*keepAliveMessage)
			if !isKeepAlive {
				next := f.handleErr(fmt.Errorf("message received in openConfirm state is not a keepalive, type: %s", m.MessageType()), IdleState)
				drainTimers(f.holdTimer)
				f.cleanupConnAndReader()
				return next
			}

			f.drainAndResetHoldTimer()
			// does not need to be drained
			f.keepAliveTimer.Reset(f.keepAliveTime)
			return EstablishedState
		}
	}
}

func (f *standardFSM) established() FSMState {
	for {
		select {
		case <-f.disable:
			f.sendCease()
			drainTimers(f.keepAliveTimer, f.holdTimer)
			f.cleanupConnAndReader()
			return DisabledState
		case err := <-f.readerErr:
			next := f.handleErr(err, IdleState)
			drainTimers(f.keepAliveTimer, f.holdTimer)
			f.cleanupConnAndReader()
			return next
		case <-f.holdTimer.C:
			drainTimers(f.keepAliveTimer)
			return f.handleHoldTimerExpired()
		case <-f.keepAliveTimer.C:
			err := f.sendKeepAlive()
			if err != nil {
				next := f.handleErr(err, IdleState)
				drainTimers(f.holdTimer)
				f.cleanupConnAndReader()
				return next
			}
			// does not need to be drained
			f.keepAliveTimer.Reset(f.keepAliveTime)
		case m := <-f.msgCh:
			switch m := m.(type) {
			case *keepAliveMessage:
				f.drainAndResetHoldTimer()
			case *UpdateMessage:
				f.drainAndResetHoldTimer()
				next := f.sendEvent(newEventNeighborUpdateReceived(f.neighborConfig, m), EstablishedState)
				if next == DisabledState {
					f.sendCease()
					drainTimers(f.keepAliveTimer, f.holdTimer)
					f.cleanupConnAndReader()
					return next
				}
			case *NotificationMessage:
				drainTimers(f.keepAliveTimer, f.holdTimer)
				f.cleanupConnAndReader()
				return f.sendEvent(newEventNeighborNotificationReceived(f.neighborConfig, m), IdleState)
			case *openMessage:
				next := f.handleUnexpectedMessageType(m.MessageType(), IdleState)
				drainTimers(f.holdTimer)
				f.cleanupConnAndReader()
				return next
			}
		}
	}
}

func (f *standardFSM) loop() {
	var current FSMState
	next := IdleState

	for {
		if next != DisabledState {
			next = f.sendEvent(newEventNeighborStateTransition(f.neighborConfig, next), next)
		}

		current = next

		switch current {
		case DisabledState:
			f.disable <- nil
			return
		case IdleState:
			next = f.idle()
		case ConnectState:
			next = f.connect()
		case ActiveState:
			next = f.active()
		case OpenSentState:
			next = f.openSent()
		case OpenConfirmState:
			next = f.openConfirm()
		case EstablishedState:
			next = f.established()
		}

		err := validTransition(current, next)
		if err != nil {
			panic(fmt.Sprintf("invalid state transition for neighbor:%s %s to %s", f.neighborConfig.Address, current, next))
		}
	}
}

func drainTimers(timers ...*time.Timer) {
	for _, t := range timers {
		if !t.Stop() {
			<-t.C
		}
	}
}

func (f *standardFSM) drainAndResetHoldTimer() {
	drainTimers(f.holdTimer)
	f.holdTimer.Reset(f.holdTime)
}

func (f *standardFSM) sendCease() error {
	return f.sendNotification(NotifErrCodeCease, 0, nil)
}

func (f *standardFSM) sendNotification(code NotifErrCode, subcode NotifErrSubcode, data []byte) error {
	n := &NotificationMessage{
		Code:    code,
		Subcode: subcode,
		Data:    data,
	}

	b, err := n.serialize()
	if err != nil {
		return err
	}

	_, err = f.conn.Write(b)
	return err
}

func validTransition(current, next FSMState) error {
	switch next {
	case DisabledState:
		return nil
	case IdleState:
		return nil
	case ConnectState:
		if current == IdleState || current == ActiveState {
			return nil
		}
	case ActiveState:
		if current == ConnectState || current == OpenSentState {
			return nil
		}
	case OpenSentState:
		if current == ConnectState || current == ActiveState {
			return nil
		}
	case OpenConfirmState:
		if current == OpenSentState {
			return nil
		}
	case EstablishedState:
		if current == OpenConfirmState {
			return nil
		}
	}

	return errors.New("invalid state transition")
}
