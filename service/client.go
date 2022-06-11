package service

import (
	"bytes"
	"errors"
	"net"
)

type HsmTcpClient struct {
	ServAddr   string
	Conn       *net.TCPConn
	Zpk        string
	HsmCmdHead string
	BufferSize int
}

func (client *HsmTcpClient) DialTcp() error {
	tcpAddr, errResolve := net.ResolveTCPAddr("tcp", client.ServAddr)
	if errResolve != nil {
		return errResolve
	}

	conn, errDial := net.DialTCP("tcp", nil, tcpAddr)
	if errDial != nil {
		return errDial
	}

	client.Conn = conn

	return nil
}

func (client *HsmTcpClient) Close() {
	client.Conn.Close()
}

func (client *HsmTcpClient) SendRawToHSM(cmd string) (string, error) {
	_, errWrite := client.Conn.Write([]byte(ExcludeBigendianHdr(client.HsmCmdHead, cmd)))
	if errWrite != nil {
		return "", errWrite
	}

	buffer := make([]byte, client.BufferSize)
	_, errBuffer := client.Conn.Read(buffer)
	if errBuffer != nil {
		return "", errBuffer
	}

	if string(buffer[8:10]) != "00" {
		return "", errors.New(ErrDesc(string(buffer[8:10])))
	}

	buffer = bytes.Trim(buffer, "\x00")
	return string(buffer[:]), nil
}
