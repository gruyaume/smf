// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package udp

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/logger"
	"github.com/omec-project/smf/metrics"
	"github.com/wmnsk/go-pfcp/message"
)

const (
	PFCP_PORT        = 8805
	PFCP_MAX_UDP_LEN = 2048
)

type ConsumerTable struct {
	m sync.Map // map[string]TxTable
}

type PfcpEventData struct {
	ErrHandler func(message.Message, error)
	LSEID      uint64
}

type PfcpServer struct {
	Addr string
	Conn *net.UDPConn
	// Consumer Table
	// Map Consumer IP to its tx table
	ConsumerTable ConsumerTable
}

var Server *PfcpServer

var ServerStartTime time.Time

func NewPfcpServer(addr string) *PfcpServer {
	server := PfcpServer{Addr: addr}
	return &server
}

func (t *ConsumerTable) Load(consumerAddr string) (*TxTable, bool) {
	txTable, ok := t.m.Load(consumerAddr)
	if ok {
		return txTable.(*TxTable), ok
	}
	return nil, false
}

func (t *ConsumerTable) Store(consumerAddr string, txTable *TxTable) {
	t.m.Store(consumerAddr, txTable)
}

func (pfcpServer *PfcpServer) Listen() error {
	var serverIp net.IP
	if pfcpServer.Addr == "" {
		serverIp = net.IPv4zero
	} else {
		serverIp = net.ParseIP(pfcpServer.Addr)
	}

	addr := &net.UDPAddr{
		IP:   serverIp,
		Port: PFCP_PORT,
	}

	conn, err := net.ListenUDP("udp", addr)
	pfcpServer.Conn = conn
	return err
}

func Run(Dispatch func(*UDPMessage)) {
	CPNodeID := context.SMF_Self().CPNodeID
	Server = NewPfcpServer(CPNodeID.ResolveNodeIdToIp().String())

	err := Server.Listen()
	if err != nil {
		logger.PfcpLog.Errorf("Failed to listen: %v", err)
	}
	logger.PfcpLog.Infof("Listen on %s", Server.Conn.LocalAddr().String())

	go func(p *PfcpServer) {
		for {
			remoteAddr, pfcpMessage, eventData, err := p.ReadFrom()
			if err != nil {
				if err.Error() == "Receive resend PFCP request" {
					logger.PfcpLog.Infoln(err)
				} else {
					logger.PfcpLog.Warnf("Read PFCP error: %v", err)
				}

				continue
			}

			msg := NewUDPMessage(remoteAddr, pfcpMessage, eventData)
			go Dispatch(&msg)
		}
	}(Server)

	ServerStartTime = time.Now()
}

func SendPfcp(msg message.Message, addr *net.UDPAddr, eventData interface{}) error {
	err := Server.WriteTo(msg, addr, eventData)
	if err != nil {
		logger.PfcpLog.Errorf("Failed to send PFCP message: %v", err)
		metrics.IncrementN4MsgStats(context.SMF_Self().NfInstanceID, msg.MessageTypeName(), "Out", "Failure", err.Error())
		return err
	}

	metrics.IncrementN4MsgStats(context.SMF_Self().NfInstanceID, msg.MessageTypeName(), "Out", "Success", "")
	return nil
}

func (pfcpServer *PfcpServer) ReadFrom() (*net.UDPAddr, message.Message, interface{}, error) {
	buf := make([]byte, PFCP_MAX_UDP_LEN)
	n, addr, err := pfcpServer.Conn.ReadFromUDP(buf)
	if err != nil {
		return addr, nil, nil, err
	}

	msg, err := message.Parse(buf[:n])
	if err != nil {
		logger.PfcpLog.Errorf("Error parsing PFCP message: %v", err)
		return addr, nil, nil, err
	}

	var eventData interface{}
	if IsRequest(msg) {
		// Todo: Implement SendingResponse type of reliable delivery
		tx, err := pfcpServer.FindTransaction(msg, addr)
		if err != nil {
			return addr, msg, nil, err
		} else if tx != nil {
			// err == nil && tx != nil => Resend Request
			err = fmt.Errorf("receive resend PFCP request")
			tx.EventChannel <- ReceiveResendRequest
			return addr, msg, nil, err
		} else {
			// err == nil && tx == nil => New Request
			return addr, msg, nil, nil
		}
	} else if IsResponse(msg) {
		tx, err := pfcpServer.FindTransaction(msg, pfcpServer.Conn.LocalAddr().(*net.UDPAddr))
		if err != nil {
			return addr, msg, nil, err
		}
		eventData = tx.EventData
		tx.EventChannel <- ReceiveValidResponse
	}

	return addr, msg, eventData, nil
}

func (pfcpServer *PfcpServer) WriteTo(msg message.Message, addr *net.UDPAddr, eventData interface{}) error {
	buf := make([]byte, msg.MarshalLen())
	err := msg.MarshalTo(buf)
	if err != nil {
		return err
	}

	/*TODO: check if all bytes of buf are sent*/
	tx := NewTransaction(msg, buf, pfcpServer.Conn, addr, eventData)

	err = pfcpServer.PutTransaction(tx)
	if err != nil {
		return err
	}

	go pfcpServer.StartTxLifeCycle(tx)
	return nil
}

func (pfcpServer *PfcpServer) FindTransaction(msg message.Message, addr *net.UDPAddr) (*Transaction, error) {
	var tx *Transaction

	logger.PfcpLog.Traceln("In FindTransaction")
	consumerAddr := addr.String()

	if IsResponse(msg) {
		if _, exist := pfcpServer.ConsumerTable.Load(consumerAddr); !exist {
			logger.PfcpLog.Warnln("In FindTransaction")
			logger.PfcpLog.Warnf("Can't find txTable from consumer addr: [%s]", consumerAddr)
			return nil, fmt.Errorf("FindTransaction Error: txTable not found")
		}

		txTable, _ := pfcpServer.ConsumerTable.Load(consumerAddr)
		seqNum := msg.Sequence()

		if _, exist := txTable.Load(seqNum); !exist {
			logger.PfcpLog.Warnln("In FindTransaction")
			logger.PfcpLog.Warnln("Consumer Addr: ", consumerAddr)
			logger.PfcpLog.Warnf("Can't find tx [%d] from txTable: ", seqNum)
			return nil, fmt.Errorf("FindTransaction Error: sequence number [%d] not found", seqNum)
		}

		tx, _ = txTable.Load(seqNum)
	} else if IsRequest(msg) {
		if _, exist := pfcpServer.ConsumerTable.Load(consumerAddr); !exist {
			return nil, nil
		}

		txTable, _ := pfcpServer.ConsumerTable.Load(consumerAddr)
		seqNum := msg.Sequence()

		if _, exist := txTable.Load(seqNum); !exist {
			return nil, nil
		}

		tx, _ = txTable.Load(seqNum)
	}
	logger.PfcpLog.Traceln("End FindTransaction")
	return tx, nil
}

func (pfcpServer *PfcpServer) PutTransaction(tx *Transaction) (err error) {
	logger.PfcpLog.Traceln("In PutTransaction")

	consumerAddr := tx.ConsumerAddr
	if _, exist := pfcpServer.ConsumerTable.Load(consumerAddr); !exist {
		pfcpServer.ConsumerTable.Store(consumerAddr, &TxTable{})
	}

	txTable, _ := pfcpServer.ConsumerTable.Load(consumerAddr)
	if _, exist := txTable.Load(tx.SequenceNumber); !exist {
		txTable.Store(tx.SequenceNumber, tx)
	} else {
		logger.PfcpLog.Warnln("In PutTransaction")
		logger.PfcpLog.Warnln("Consumer Addr: ", consumerAddr)
		logger.PfcpLog.Warnln("Sequence number ", tx.SequenceNumber, " already exist!")
		err = fmt.Errorf("insert tx error: duplicate sequence number %d", tx.SequenceNumber)
	}

	logger.PfcpLog.Traceln("End PutTransaction")
	return
}

func (pfcpServer *PfcpServer) StartTxLifeCycle(tx *Transaction) {
	// Start Transaction
	sendErr := tx.Start()

	// End Transaction
	err := pfcpServer.RemoveTransaction(tx)
	if err != nil {
		logger.PfcpLog.Warnln(err)
	}

	if sendErr != nil && tx.EventData != nil {
		if eventData, ok := tx.EventData.(PfcpEventData); ok {
			if errHandler := eventData.ErrHandler; errHandler != nil {
				msg, err := message.Parse(tx.SendMsg)
				if err != nil {
					logger.PfcpLog.Warnf("Parse message error: %v", err)
					return
				}
				errHandler(msg, sendErr)
			}
		}
	}
}

func (pfcpServer *PfcpServer) RemoveTransaction(tx *Transaction) (err error) {
	logger.PfcpLog.Traceln("In RemoveTransaction")
	consumerAddr := tx.ConsumerAddr
	txTable, _ := pfcpServer.ConsumerTable.Load(consumerAddr)

	if txTmp, exist := txTable.Load(tx.SequenceNumber); exist {
		tx = txTmp
		if tx.TxType == SendingRequest {
			logger.PfcpLog.Debugf("Remove Request Transaction [%d]\n", tx.SequenceNumber)
		} else if tx.TxType == SendingResponse {
			logger.PfcpLog.Debugf("Remove Response Transaction [%d]\n", tx.SequenceNumber)
		}

		txTable.Delete(tx.SequenceNumber)
	} else {
		logger.PfcpLog.Warnln("In RemoveTransaction")
		logger.PfcpLog.Warnln("Consumer IP: ", consumerAddr)
		logger.PfcpLog.Warnln("Sequence number ", tx.SequenceNumber, " doesn't exist!")
		err = fmt.Errorf("remove tx error: transaction [%d] doesn't exist", tx.SequenceNumber)
	}

	logger.PfcpLog.Traceln("End RemoveTransaction")
	return
}
