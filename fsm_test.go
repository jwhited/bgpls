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

func (s *fsmTestSuite) advanceToEstablishedState() {
	m, err := s.readMessagesFromConn()
	if err != nil {
		s.T().Fatal(err)
	}
	if !assert.Equal(s.T(), len(m), 1) {
		s.T().Fatal("invalid number of messages from neighbor")
	}

	err = s.sendOpen()
	if err != nil {
		s.T().Fatal(err)
	}

	err = s.sendKeepalive()
	if err != nil {
		s.T().Fatal(err)
	}

	m, err = s.readMessagesFromConn()
	if err != nil {
		s.T().Fatal(err)
	}
	if !assert.Equal(s.T(), len(m), 1) {
		s.T().Fatal("invalid number of messages from neighbor")
	}
	assert.Equal(s.T(), m[0].MessageType(), KeepAliveMessageType)

	for i := 0; i < 5; i++ {
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
			case 3:
				assert.Equal(s.T(), e.State, OpenConfirmState)
			case 4:
				assert.Equal(s.T(), e.State, EstablishedState)
			}
		} else {
			s.T().Fatalf("not a state transition event: %s", evt.Type())
		}
	}
}

// advance to established state then cleanup
func (s *fsmTestSuite) TestFSMEstablishedThenDisable() {
	s.advanceToEstablishedState()
}

// advance to established state then send an invalid message
// expect a notification and EventNeighborErr to be received
func (s *fsmTestSuite) TestFSMEstablishedThenReaderErr() {
	s.advanceToEstablishedState()
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

// advance to established state and wait for hold timer to expire
// expect an EventNeighborHoldTimerExpired
func (s *fsmTestSuite) TestFSMEstablishedThenHoldTimerExpired() {
	s.advanceToEstablishedState()
	time.Sleep(time.Second * 3)

	e := <-s.events
	assert.IsType(s.T(), &EventNeighborHoldTimerExpired{}, e)
}

// advance to established state and send a keepalive
func (s *fsmTestSuite) TestFSMEstablishedThenSendKA() {
	s.advanceToEstablishedState()
	ka := &keepAliveMessage{}
	b, err := ka.serialize()
	if err != nil {
		s.T().Fatal(err)
	}
	_, err = s.conn.Write(b)
	if err != nil {
		s.T().Fatal(err)
	}
}

// advance to established state and send an update message
// expect EventNeighborUpdateReceived
func (s *fsmTestSuite) TestFSMEstablishedThenSendUpdate() {
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
func (s *fsmTestSuite) TestFSMEstablishedThenSendNotif() {
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
func (s *fsmTestSuite) TestFSMEstablishedThenSendOpen() {
	s.advanceToEstablishedState()
	o, err := newOpenMessage(123, time.Second*3, net.ParseIP("1.1.1.1"))
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

func TestFSM(t *testing.T) {
	s := &fsmTestSuite{}
	suite.Run(t, s)
}
