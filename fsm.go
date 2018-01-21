package bgpls

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
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

const (
	connectRetryTime = time.Second * 5
	loggerErrorField = "error"
)

type fsm interface {
	state() FSMState
	shut()
}

type standardFSM struct {
	port              int
	events            chan Event
	disable           chan interface{}
	neighborConfig    *NeighborConfig
	localASN          uint32
	logger            *logrus.Entry
	conn              net.Conn
	readerErr         chan error
	closeReader       chan struct{}
	readerClosed      chan struct{}
	msgCh             chan Message
	s                 FSMState
	keepAliveTime     time.Duration
	keepAliveTimer    *time.Timer
	holdTime          time.Duration
	holdTimer         *time.Timer
	connectRetryTimer *time.Timer
	*sync.RWMutex
}

func newFSM(c *NeighborConfig, events chan Event, localASN uint32, port int) fsm {
	f := &standardFSM{
		port:              port,
		events:            events,
		disable:           make(chan interface{}),
		neighborConfig:    c,
		localASN:          localASN,
		logger:            logrus.WithField("neighbor", c.Address.String()),
		s:                 IdleState,
		keepAliveTime:     time.Duration(int64(c.HoldTime) / 3).Truncate(time.Second),
		keepAliveTimer:    time.NewTimer(0),
		holdTime:          c.HoldTime,
		holdTimer:         time.NewTimer(0),
		connectRetryTimer: time.NewTimer(0),
		RWMutex:           &sync.RWMutex{},
	}

	<-f.keepAliveTimer.C
	<-f.holdTimer.C
	<-f.connectRetryTimer.C

	go f.loop()

	return f
}

func (f *standardFSM) shut() {
	f.RLock()
	if f.s == DisabledState {
		f.RUnlock()
		return
	}
	f.RUnlock()

	f.disable <- nil
	<-f.disable
}

func (f *standardFSM) transitionAndPanicOnErr(state FSMState) {
	err := f.transition(state)
	if err != nil {
		f.logger.WithField(loggerErrorField, err).Panic("bug in FSM state transition")
	}
}

func (f *standardFSM) idle() FSMState {
	return ConnectState
}

func (f *standardFSM) cleanupConn() {
	f.conn.Close()
	close(f.closeReader)
	<-f.readerClosed
	close(f.msgCh)
}

func (f *standardFSM) connect() FSMState {
	f.readerErr = make(chan error)
	f.closeReader = make(chan struct{})
	f.readerClosed = make(chan struct{})
	f.msgCh = make(chan Message)
	dialer := &net.Dialer{}
	ctx, cancel := context.WithCancel(context.Background())
	connectErrorChan := make(chan error)
	connChan := make(chan net.Conn)
	f.connectRetryTimer.Reset(connectRetryTime)

	go func() {
		conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(f.neighborConfig.Address.String(), strconv.Itoa(f.port)))
		if err != nil {
			connectErrorChan <- err
			return
		}

		connChan <- conn
	}()

	select {
	case <-f.disable:
		cancel()
		return DisabledState
	case <-f.connectRetryTimer.C:
		cancel()
		select {
		case conn := <-connChan:
			f.conn = conn
			go f.read()
		case <-connectErrorChan:
			return ConnectState
		}
	case err := <-connectErrorChan:
		cancel()

		event := newEventNeighborErr(f.neighborConfig, fmt.Errorf("error connecting to neighbor: %v", err))
		select {
		case f.events <- event:
		case <-f.disable:
			if !f.connectRetryTimer.Stop() {
				<-f.connectRetryTimer.C
			}
			return DisabledState
		}

		if !f.connectRetryTimer.Stop() {
			<-f.connectRetryTimer.C
		}
		return ActiveState
	case conn := <-connChan:
		cancel()
		if !f.connectRetryTimer.Stop() {
			<-f.connectRetryTimer.C
		}
		f.conn = conn
		go f.read()
	}

	o, err := newOpenMessage(f.localASN, f.holdTime, f.neighborConfig.Address)
	if err != nil {
		event := newEventNeighborErr(f.neighborConfig, fmt.Errorf("error creating open message: %v", err))
		select {
		case f.events <- event:
		case <-f.disable:
			f.cleanupConn()
			return DisabledState
		}

		f.cleanupConn()
		return IdleState
	}
	b, err := o.serialize()
	if err != nil {
		f.logger.WithField(loggerErrorField, err).Panic("bug serializing open message")
	}

	_, err = f.conn.Write(b)
	if err != nil {
		event := newEventNeighborErr(f.neighborConfig, fmt.Errorf("error sending open message: %v", err))
		select {
		case f.events <- event:
		case <-f.disable:
			f.cleanupConn()
			return DisabledState
		}

		f.cleanupConn()
		return ConnectState
	}

	return OpenSentState
}

func (f *standardFSM) active() FSMState {
	f.connectRetryTimer.Reset(connectRetryTime)

	select {
	case <-f.disable:
		return DisabledState
	case <-f.connectRetryTimer.C:
		return ConnectState
	}
}

func (f *standardFSM) handleErr(err error, nextState FSMState) FSMState {
	if err, ok := err.(*errWithNotification); ok {
		f.sendNotification(err.code, err.subcode, err.data)
	}

	event := newEventNeighborErr(f.neighborConfig, err)
	select {
	case f.events <- event:
	case <-f.disable:
		f.drainHoldTimer()
		f.cleanupConn()
		return DisabledState
	}

	f.drainHoldTimer()
	f.cleanupConn()
	return nextState
}

func (f *standardFSM) handleHoldTimerExpired(nextState FSMState) FSMState {
	f.sendHoldTimerExpired()

	event := newEventNeighborHoldTimerExpired(f.neighborConfig)
	select {
	case f.events <- event:
	case <-f.disable:
		f.cleanupConn()
		return DisabledState
	}

	f.cleanupConn()
	return nextState
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

func (f *standardFSM) openSent() FSMState {
	// should already be drained if previously set
	f.holdTimer.Reset(f.holdTime)

	select {
	case <-f.disable:
		f.sendCease()
		f.drainHoldTimer()
		f.cleanupConn()
		return DisabledState
	case err := <-f.readerErr:
		return f.handleErr(err, ActiveState)
	case <-f.holdTimer.C:
		return f.handleHoldTimerExpired(IdleState)
	case m := <-f.msgCh:
		open, isOpen := m.(*openMessage)
		if !isOpen {
			notif, isNotif := m.(*NotificationMessage)
			if isNotif {
				event := newEventNeighborNotificationReceived(f.neighborConfig, notif)
				select {
				case f.events <- event:
				case <-f.disable:
					f.drainHoldTimer()
					f.cleanupConn()
					return DisabledState
				}
			}

			f.drainHoldTimer()
			f.cleanupConn()
			return IdleState
		}

		err := validateOpenMessage(open, f.neighborConfig.ASN)
		if err != nil {
			return f.handleErr(err, IdleState)
		}

		if float64(open.holdTime) < f.holdTime.Seconds() {
			f.holdTime = time.Duration(int64(open.holdTime) * int64(time.Second))
			f.keepAliveTime = (f.holdTime / 3).Truncate(time.Second)
		}

		err = f.sendKeepAlive()
		if err != nil {
			return f.handleErr(err, IdleState)
		}

		f.drainAndResetHoldTimer()
		return OpenConfirmState
	}
}

func (f *standardFSM) sendKeepAlive() error {
	ka := &keepAliveMessage{}
	b, err := ka.serialize()
	if err != nil {
		f.logger.WithField(loggerErrorField, err).Panic("bug serializing keepalive message")
	}
	_, err = f.conn.Write(b)
	return err
}

func (f *standardFSM) openConfirm() FSMState {
	for {
		select {
		case <-f.disable:
			f.sendCease()
			f.drainHoldTimer()
			f.cleanupConn()
			return DisabledState
		case err := <-f.readerErr:
			return f.handleErr(err, IdleState)
		case <-f.holdTimer.C:
			return f.handleHoldTimerExpired(IdleState)
		case m := <-f.msgCh:
			_, isKeepAlive := m.(*keepAliveMessage)
			if !isKeepAlive {
				return f.handleErr(fmt.Errorf("message received in openConfirm state is not a keepalive, type: %s", m.MessageType()), IdleState)
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
			f.drainHoldTimer()
			f.cleanupConn()
			return DisabledState
		case err := <-f.readerErr:
			return f.handleErr(err, IdleState)
		case <-f.holdTimer.C:
			return f.handleHoldTimerExpired(IdleState)
		case <-f.keepAliveTimer.C:
			err := f.sendKeepAlive()
			if err != nil {
				return f.handleErr(err, IdleState)
			}
			// does not need to be drained
			f.keepAliveTimer.Reset(f.keepAliveTime)
		case m := <-f.msgCh:
			switch m := m.(type) {
			case *keepAliveMessage:
				f.drainAndResetHoldTimer()
			case *UpdateMessage:
				f.drainAndResetHoldTimer()
				event := newEventNeighborUpdateReceived(f.neighborConfig, m)

				select {
				case f.events <- event:
				case <-f.disable:
					f.sendCease()
					f.drainHoldTimer()
					f.cleanupConn()
					return DisabledState
				}
			case *NotificationMessage:
				event := newEventNeighborNotificationReceived(f.neighborConfig, m)
				select {
				case f.events <- event:
				case <-f.disable:
					f.drainHoldTimer()
					f.cleanupConn()
					return DisabledState
				}

				f.drainHoldTimer()
				f.cleanupConn()
				return IdleState
			case *openMessage:
				event := newEventNeighborErr(f.neighborConfig, errors.New("open message received while in established state"))
				select {
				case f.events <- event:
				case <-f.disable:
					f.drainHoldTimer()
					f.cleanupConn()
					return DisabledState
				}

				openType := make([]byte, 1)
				openType[0] = uint8(OpenMessageType)
				f.sendNotification(NotifErrCodeMessageHeader, NotifErrSubcodeBadType, openType)
				f.drainHoldTimer()
				f.cleanupConn()
				return IdleState
			}
		}
	}
}

func (f *standardFSM) loop() {
	for {
		state := f.state()

		if state != DisabledState {
			event := newEventNeighborStateTransition(f.neighborConfig, state)
			select {
			case f.events <- event:
			case <-f.disable:
				f.disable <- nil
				return
			}
		}

		switch state {
		case DisabledState:
			f.disable <- nil
			return
		case IdleState:
			f.transitionAndPanicOnErr(f.idle())
		case ConnectState:
			f.transitionAndPanicOnErr(f.connect())
		case ActiveState:
			f.transitionAndPanicOnErr(f.active())
		case OpenSentState:
			f.transitionAndPanicOnErr(f.openSent())
		case OpenConfirmState:
			f.transitionAndPanicOnErr(f.openConfirm())
		case EstablishedState:
			f.transitionAndPanicOnErr(f.established())
		}
	}
}

func (f *standardFSM) drainHoldTimer() {
	if !f.holdTimer.Stop() {
		<-f.holdTimer.C
	}
}

func (f *standardFSM) drainAndResetHoldTimer() {
	f.drainHoldTimer()
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

func (f *standardFSM) state() FSMState {
	f.RLock()
	defer f.RUnlock()
	return f.s
}

func (f *standardFSM) transition(state FSMState) error {
	f.Lock()
	defer f.Unlock()

	switch state {
	case DisabledState:
		f.s = DisabledState
		return nil
	case IdleState:
		f.s = IdleState
		return nil
	case ConnectState:
		if f.s == IdleState || f.s == ConnectState || f.s == ActiveState {
			f.s = ConnectState
			return nil
		}
	case ActiveState:
		if f.s == ConnectState || f.s == ActiveState || f.s == OpenSentState {
			f.s = ActiveState
			return nil
		}
	case OpenSentState:
		if f.s == ConnectState || f.s == ActiveState {
			f.s = OpenSentState
			return nil
		}
	case OpenConfirmState:
		if f.s == OpenSentState || f.s == OpenConfirmState {
			f.s = OpenConfirmState
			return nil
		}
	case EstablishedState:
		if f.s == OpenConfirmState || f.s == EstablishedState {
			f.s = EstablishedState
			return nil
		}
	default:
		return errors.New("invalid state")
	}

	return errInvalidStateTransition
}
