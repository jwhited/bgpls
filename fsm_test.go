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

func (s *fsmTestSuite) AfterTest(_, _ string) {
	s.fsm.terminate()
	s.conn.Close()
	s.ln.Close()
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
		assert.FailNow(s.T(), err.Error())
	}

	s.ln = ln

	split := strings.Split(s.ln.Addr().String(), ":")
	if len(split) != 2 {
		assert.FailNow(s.T(), "unable to split listener address string")
	}

	i, err := strconv.Atoi(split[1])
	if err != nil {
		assert.FailNow(s.T(), "unexpected split on listener address string")
	}

	s.neighborConfig = &NeighborConfig{
		Address:  net.ParseIP("127.0.0.1"),
		ASN:      64512,
		HoldTime: time.Second * 3,
	}

	s.events = make(chan Event)
	s.fsm = newFSM(s.neighborConfig, s.events, net.ParseIP("127.0.0.2").To4(), 64512, i)

	s.failNowIfNotStateTransition(IdleState)
	s.failNowIfNotStateTransition(ConnectState)

	conn, err := ln.Accept()
	if err != nil {
		assert.FailNow(s.T(), err.Error())
	}

	s.failNowIfNotStateTransition(OpenSentState)

	s.conn = conn

	m, err := s.readMessagesFromConn()
	if err != nil {
		assert.FailNow(s.T(), err.Error())
	}
	if !assert.Equal(s.T(), len(m), 1) {
		assert.FailNow(s.T(), "invalid number of messages")
	}
}

func (s *fsmTestSuite) advanceToOpenConfirmState() {
	s.advanceToOpenSentState()

	err := s.sendOpen()
	if err != nil {
		assert.FailNow(s.T(), err.Error())
	}

	m, err := s.readMessagesFromConn()
	if err != nil {
		assert.FailNow(s.T(), err.Error())
	}

	if assert.Len(s.T(), m, 1) {
		assert.IsType(s.T(), m[0], &keepAliveMessage{})
	}

	s.failNowIfNotStateTransition(OpenConfirmState)
}

func (s *fsmTestSuite) failNowIfNotStateTransition(state FSMState) {
	e := <-s.events
	if assert.IsType(s.T(), &EventNeighborStateTransition{}, e) {
		f, _ := e.(*EventNeighborStateTransition)
		if !assert.Equal(s.T(), f.State, state) {
			assert.FailNow(s.T(), "unexpected state")
		}
	} else {
		assert.FailNow(s.T(), "unexpected event type")
	}
}

func (s *fsmTestSuite) advanceToEstablishedState() {
	s.advanceToOpenConfirmState()

	err := s.sendKeepalive()
	if err != nil {
		assert.FailNow(s.T(), err.Error())
	}

	s.failNowIfNotStateTransition(EstablishedState)
}

func (s *fsmTestSuite) sendInvalidMsgExpectNeighborErr() {
	_, err := s.conn.Write([]byte{0})
	if err != nil {
		assert.FailNow(s.T(), err.Error())
	}

	m, err := s.readMessagesFromConn()
	if err != nil {
		assert.FailNow(s.T(), err.Error())
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
func (s *fsmTestSuite) TestFSMOpenSentReaderErr() {
	s.advanceToOpenSentState()
	s.sendInvalidMsgExpectNeighborErr()
}

// advance to open sent state and wait for hold timer to expire
func (s *fsmTestSuite) TestFSMOpenSentHoldTimerExpired() {
	longHoldTime = time.Second * 1
	s.advanceToOpenSentState()
	e := <-s.events
	assert.IsType(s.T(), &EventNeighborHoldTimerExpired{}, e)
}

// advance to open sent state and send KA instead of open message
func (s *fsmTestSuite) TestFSMOpenSentSendKA() {
	s.advanceToOpenSentState()
	err := s.sendKeepalive()
	if err != nil {
		assert.FailNow(s.T(), err.Error())
	}
	e := <-s.events
	assert.IsType(s.T(), &EventNeighborErr{}, e)
	s.failNowIfNotStateTransition(IdleState)
}

// advance to open sent state and send notif
func (s *fsmTestSuite) TestFSMOpenSentSendNotif() {
	s.advanceToOpenSentState()
	n := &NotificationMessage{Code: NotifErrCodeUpdateMessage, Subcode: NotifErrSubcodeMalformedAttr}
	b, err := n.serialize()
	if err != nil {
		assert.FailNow(s.T(), err.Error())
	}
	_, err = s.conn.Write(b)
	if err != nil {
		assert.FailNow(s.T(), err.Error())
	}
	e := <-s.events
	if assert.IsType(s.T(), &EventNeighborNotificationReceived{}, e) {
		f, _ := e.(*EventNeighborNotificationReceived)
		assert.Equal(s.T(), f.Message, n)
	}
	s.failNowIfNotStateTransition(IdleState)
}

// advance to open sent state and send an invalid open message
func (s *fsmTestSuite) TestFSMOpenSentSendInvalidOpen() {
	s.advanceToOpenSentState()
	o, err := newOpenMessage(12, time.Second*3, []byte{0, 0, 0, 0})
	if err != nil {
		assert.FailNow(s.T(), err.Error())
	}
	b, err := o.serialize()
	if err != nil {
		assert.FailNow(s.T(), err.Error())
	}
	_, err = s.conn.Write(b)
	if err != nil {
		assert.FailNow(s.T(), err.Error())
	}
	m, err := s.readMessagesFromConn()
	assert.Nil(s.T(), err)
	if assert.Len(s.T(), m, 1) {
		assert.IsType(s.T(), m[0], &NotificationMessage{})
	}
	e := <-s.events
	assert.IsType(s.T(), &EventNeighborErr{}, e)
	s.failNowIfNotStateTransition(IdleState)
}

// advance to open confirm state then cleanup
func (s *fsmTestSuite) TestFSMOpenConfirmDisable() {
	s.advanceToOpenConfirmState()
}

// advance to open confirm state then send an invalid message
func (s *fsmTestSuite) TestFSMOpenConfirmReaderErr() {
	s.advanceToOpenConfirmState()
	s.sendInvalidMsgExpectNeighborErr()
	s.failNowIfNotStateTransition(IdleState)
}

// advance to open confirm state and wait for hold timer to expire
func (s *fsmTestSuite) TestFSMOpenConfirmHoldTimerExpire() {
	s.advanceToOpenConfirmState()
	e := <-s.events
	assert.IsType(s.T(), &EventNeighborHoldTimerExpired{}, e)
	s.failNowIfNotStateTransition(IdleState)
}

// advance to established state then cleanup
func (s *fsmTestSuite) TestFSMEstablishedDisable() {
	s.advanceToEstablishedState()
}

// advance to established state then send an invalid message
func (s *fsmTestSuite) TestFSMEstablishedReaderErr() {
	s.advanceToEstablishedState()
	s.sendInvalidMsgExpectNeighborErr()
	s.failNowIfNotStateTransition(IdleState)
}

// advance to established state and wait for hold timer to expire
func (s *fsmTestSuite) TestFSMEstablishedHoldTimerExpired() {
	s.advanceToEstablishedState()
	e := <-s.events
	assert.IsType(s.T(), &EventNeighborHoldTimerExpired{}, e)
	s.failNowIfNotStateTransition(IdleState)
}

// advance to established state and send a keepalive
func (s *fsmTestSuite) TestFSMEstablishedSendKA() {
	s.advanceToEstablishedState()
	err := s.sendKeepalive()
	assert.Nil(s.T(), err)
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
		assert.FailNow(s.T(), err.Error())
	}
	_, err = s.conn.Write(b)
	if err != nil {
		assert.FailNow(s.T(), err.Error())
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
		assert.FailNow(s.T(), err.Error())
	}
	_, err = s.conn.Write(b)
	if err != nil {
		assert.FailNow(s.T(), err.Error())
	}

	e := <-s.events
	if assert.IsType(s.T(), &EventNeighborNotificationReceived{}, e) {
		assert.Equal(s.T(), e.(*EventNeighborNotificationReceived).Message, n)
	}
}

// advance to established state and send an open message
// expect EventNeighborErr and EventNeighborStateTransition
func (s *fsmTestSuite) TestFSMEstablishedSendOpen() {
	s.advanceToEstablishedState()
	err := s.sendOpen()
	if err != nil {
		s.T().Fatal(err)
	}

	e := <-s.events
	assert.IsType(s.T(), &EventNeighborErr{}, e)
	s.failNowIfNotStateTransition(IdleState)
}

func TestFSM(t *testing.T) {
	s := &fsmTestSuite{}
	suite.Run(t, s)
}
