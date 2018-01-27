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

func (s *fsmTestSuite) TestToEstablished() {
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

func TestFSM(t *testing.T) {
	s := &fsmTestSuite{}
	suite.Run(t, s)
}
