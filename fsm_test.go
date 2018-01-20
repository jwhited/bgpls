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

type fsmTestSuite struct {
	suite.Suite
	neighborConfig *NeighborConfig
	ln             net.Listener
	conn           net.Conn
	events         chan Event
	fsm            fsm
}

func (s *fsmTestSuite) SetupSuite() {
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

	defaultPort = i

	s.neighborConfig = &NeighborConfig{
		Address:  net.ParseIP("127.0.0.1"),
		ASN:      64512,
		HoldTime: time.Second * 3,
	}

	s.events = make(chan Event, 1024)
	s.fsm = newFSM(s.neighborConfig, s.events, 64512)

	conn, err := ln.Accept()
	if err != nil {
		s.T().Fatal(err)
	}

	s.conn = conn
}

func (s *fsmTestSuite) TearDownSuite() {
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

	_, err = s.readMessagesFromConn()
	if err != nil {
		s.T().Fatal(err)
	}

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
			s.T().Fatal("not a state transition event")
		}
	}
}

func TestFSM(t *testing.T) {
	s := &fsmTestSuite{}
	suite.Run(t, s)
}
