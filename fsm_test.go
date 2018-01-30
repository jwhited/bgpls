package bgpls

import (
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

func TestFSMString(t *testing.T) {
	cases := []struct {
		state FSMState
		str   string
	}{
		{DisabledState, "disabled"},
		{IdleState, "idle"},
		{ConnectState, "connect"},
		{ActiveState, "active"},
		{OpenSentState, "openSent"},
		{OpenConfirmState, "openConfirm"},
		{EstablishedState, "established"},
		{FSMState(10), "unknown state"},
	}

	for _, c := range cases {
		assert.Equal(t, c.state.String(), c.str)
	}
}

type fsmTestSuite struct {
	suite.Suite
	neighborConfig *NeighborConfig
	ln             net.Listener
	conn           net.Conn
	events         chan Event
	fsm            fsm
}

func (s *fsmTestSuite) BeforeTest(_, _ string) {

}

func (s *fsmTestSuite) AfterTest(_, _ string) {
	s.conn.Close()
	s.ln.Close()
	s.fsm.shut()
}

func (s *fsmTestSuite) readMessagesFromConn() ([]Message, error) {
	b := make([]byte, 4096)
	n, err := s.conn.Read(b)
	if err != nil {
		return nil, err
	}
	return messagesFromBytes(b[:n])
}

func (s *fsmTestSuite) sendKeepalive() error {
	k := &keepAliveMessage{}
	b, err := k.serialize()
	if err != nil {
		return err
	}
	_, err = s.conn.Write(b)
	return err
}

func (s *fsmTestSuite) sendOpen() error {
	o, err := newOpenMessage(s.neighborConfig.ASN, s.neighborConfig.HoldTime, net.ParseIP("127.0.0.1"))
	if err != nil {
		return err
	}

	b, err := o.serialize()
	if err != nil {
		return err
	}

	_, err = s.conn.Write(b)
	return err
}

func (s *fsmTestSuite) advanceToOpenSentState() {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		s.T().Fatal(err)
	}

	s.ln = ln

	split := strings.Split(s.ln.Addr().String(), ":")
	if len(split) != 2 {
		s.T().Fatal("unable to split listener address string")
	}

	i, err := strconv.Atoi(split[1])
	if err != nil {
		s.T().Fatal("unexpected split on listener address string")
	}

	s.neighborConfig = &NeighborConfig{
		Address:  net.ParseIP("127.0.0.1"),
		ASN:      64512,
		HoldTime: time.Second * 3,
	}

	s.events = make(chan Event, 1024)
	s.fsm = newFSM(s.neighborConfig, s.events, 64512, i)

	conn, err := ln.Accept()
	if err != nil {
		s.T().Fatal(err)
	}

	s.conn = conn

	m, err := s.readMessagesFromConn()
	if err != nil {
		s.T().Fatal(err)
	}
	if !assert.Equal(s.T(), len(m), 1) {
		s.T().Fatal("invalid number of messages from neighbor")
	}

	for i := 0; i < 3; i++ {
		evt := <-s.events
		e, ok := evt.(*EventNeighborStateTransition)
		if ok {
			switch i {
			case 0:
				assert.Equal(s.T(), e.State, IdleState)
			case 1:
				assert.Equal(s.T(), e.State, ConnectState)
			case 2:
				assert.Equal(s.T(), e.State, OpenSentState)
			}
		} else {
			s.T().Fatalf("not a state transition event: %s", evt.Type())
		}
	}
}

func (s *fsmTestSuite) advanceToOpenConfirmState() {
	s.advanceToOpenSentState()

	err := s.sendOpen()
	if err != nil {
		s.T().Fatal(err)
	}

	evt := <-s.events
	e, ok := evt.(*EventNeighborStateTransition)
	if ok {
		assert.Equal(s.T(), e.State, OpenConfirmState)
	} else {
		s.T().Fatalf("not a state transition event: %s", evt.Type())
	}
}

func (s *fsmTestSuite) advanceToEstablishedState() {
	s.advanceToOpenConfirmState()

	err := s.sendKeepalive()
	if err != nil {
		s.T().Fatal(err)
	}

	m, err := s.readMessagesFromConn()
	if err != nil {
		s.T().Fatal(err)
	}
	if !assert.Equal(s.T(), len(m), 1) {
		s.T().Fatal("invalid number of messages from neighbor")
	}
	assert.Equal(s.T(), m[0].MessageType(), KeepAliveMessageType)

	evt := <-s.events
	e, ok := evt.(*EventNeighborStateTransition)
	if ok {
		assert.Equal(s.T(), e.State, EstablishedState)
	} else {
		s.T().Fatalf("not a state transition event: %s", evt.Type())
	}
}

func (s *fsmTestSuite) sendInvalidMsgExpectNeighborErr() {
	_, err := s.conn.Write([]byte{0})
	if err != nil {
		s.T().Fatal(err)
	}

	m, err := s.readMessagesFromConn()
	if err != nil {
		s.T().Fatal(err)
	}
	if assert.Len(s.T(), m, 1) {
		assert.IsType(s.T(), &NotificationMessage{}, m[0])
	}

	e := <-s.events
	assert.IsType(s.T(), &EventNeighborErr{}, e)
}

// advance to open sent state then cleanup
func (s *fsmTestSuite) TestFSMOpenSentDisable() {
	s.advanceToOpenSentState()
}

// advance to open sent state then send an invalid message
// expect a notification and EventNeighborErr to be received
func (s *fsmTestSuite) TestFSMOpenSentReaderErr() {
	s.advanceToOpenSentState()
	s.sendInvalidMsgExpectNeighborErr()
}

// advance to open sent state and wait for hold timer to expire
// expect an EventNeighborHoldTimerExpired
func (s *fsmTestSuite) TestFSMOpenSentHoldTimerExpired() {
	s.advanceToOpenSentState()
	time.Sleep(time.Second * 3)
	e := <-s.events
	assert.IsType(s.T(), &EventNeighborHoldTimerExpired{}, e)
}

// advance to open sent state and send KA
// expect an EventNeighborStateTransition
func (s *fsmTestSuite) TestFSMOpenSentSendKA() {
	s.advanceToOpenSentState()
	err := s.sendKeepalive()
	if err != nil {
		s.T().Fatal(err)
	}
	e := <-s.events
	assert.IsType(s.T(), &EventNeighborStateTransition{}, e)
}

// advance to open sent state and send notif
// expect an EventNeighborNotificationReceived
func (s *fsmTestSuite) TestFSMOpenSentSendNotif() {
	s.advanceToOpenSentState()
	n := &NotificationMessage{Code: NotifErrCodeUpdateMessage, Subcode: NotifErrSubcodeMalformedAttr}
	b, err := n.serialize()
	if err != nil {
		s.T().Fatal(err)
	}
	_, err = s.conn.Write(b)
	if err != nil {
		s.T().Fatal(err)
	}
	e := <-s.events
	assert.IsType(s.T(), &EventNeighborNotificationReceived{}, e)
}

// advance to open sent state and send an invalid open message
// expect an EventNeighborErr
func (s *fsmTestSuite) TestFSMOpenSentSendInvalidOpen() {
	s.advanceToOpenSentState()
	o, err := newOpenMessage(12, time.Second*3, []byte{0, 0, 0, 0})
	if err != nil {
		s.T().Fatal(err)
	}
	b, err := o.serialize()
	if err != nil {
		s.T().Fatal(err)
	}
	_, err = s.conn.Write(b)
	if err != nil {
		s.T().Fatal(err)
	}
	e := <-s.events
	assert.IsType(s.T(), &EventNeighborErr{}, e)
}

// advance to established state then cleanup
func (s *fsmTestSuite) TestFSMEstablishedDisable() {
	s.advanceToEstablishedState()
}

// advance to established state then send an invalid message
// expect a notification and EventNeighborErr to be received
func (s *fsmTestSuite) TestFSMEstablishedReaderErr() {
	s.advanceToEstablishedState()
	s.sendInvalidMsgExpectNeighborErr()
}

// advance to established state and wait for hold timer to expire
// expect an EventNeighborHoldTimerExpired
func (s *fsmTestSuite) TestFSMEstablishedHoldTimerExpired() {
	s.advanceToEstablishedState()
	time.Sleep(time.Second * 3)
	e := <-s.events
	assert.IsType(s.T(), &EventNeighborHoldTimerExpired{}, e)
}

// advance to established state and send a keepalive
func (s *fsmTestSuite) TestFSMEstablishedSendKA() {
	s.advanceToEstablishedState()
	err := s.sendKeepalive()
	if err != nil {
		s.T().Fatal(err)
	}
}

// advance to established state and send an update message
// expect EventNeighborUpdateReceived
func (s *fsmTestSuite) TestFSMEstablishedSendUpdate() {
	s.advanceToEstablishedState()
	u := &UpdateMessage{
		PathAttrs: []PathAttr{
			&PathAttrLocalPref{Preference: 100},
			&PathAttrOrigin{Origin: OriginCodeIGP},
		},
	}
	b, err := u.serialize()
	if err != nil {
		s.T().Fatal(err)
	}
	_, err = s.conn.Write(b)
	if err != nil {
		s.T().Fatal(err)
	}

	e := <-s.events
	if assert.IsType(s.T(), &EventNeighborUpdateReceived{}, e) {
		assert.Equal(s.T(), e.(*EventNeighborUpdateReceived).Message, u)
	}
}

// advance to established state and send a notification message
// expect EventNeighborNotificationReceived
func (s *fsmTestSuite) TestFSMEstablishedSendNotif() {
	s.advanceToEstablishedState()
	n := &NotificationMessage{
		Code:    NotifErrCodeUpdateMessage,
		Subcode: NotifErrSubcodeMalformedAttr,
	}
	b, err := n.serialize()
	if err != nil {
		s.T().Fatal(err)
	}
	_, err = s.conn.Write(b)
	if err != nil {
		s.T().Fatal(err)
	}

	e := <-s.events
	if assert.IsType(s.T(), &EventNeighborNotificationReceived{}, e) {
		assert.Equal(s.T(), e.(*EventNeighborNotificationReceived).Message, n)
	}
}

// advance to established state and send a notification message
// expect EventNeighborErr
func (s *fsmTestSuite) TestFSMEstablishedSendOpen() {
	s.advanceToEstablishedState()
	err := s.sendOpen()
	if err != nil {
		s.T().Fatal(err)
	}

	e := <-s.events
	assert.IsType(s.T(), &EventNeighborErr{}, e)
}

func TestFSM(t *testing.T) {
	s := &fsmTestSuite{}
	suite.Run(t, s)
}
