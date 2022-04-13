package tcplib

import "time"

// client: 'sudo iptables -t filter -I OUTPUT -p tcp --sport YOUR_SOURCE_PORT --tcp-flags RST RST -j DROP'
// Run Server as:
/*
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(("0.0.0.0", 9999))
sock.listen(16)
*/
//just skip seq and send packet to make server treat pakcet as out of order packet
func (tcp *TCPIP) OfoNormal(userData []byte) {
	if err := tcp.DoHandshake(); err != nil {
		panic(err)
	}

	//packet 1, 3 byte
	tcp.AddData(userData[:3])
	tcp.CalcTCPChecksum()
	tcp.Send()
	tcp.IncrSeq(uint32(len(tcp.UserData)))

	// make a 2 byte hole for packet 2
	tcp.IncrSeq(uint32(2))

	//packet 3, x-5 byte, before packet 2 sent
	tcp.AddData(userData[5:])
	tcp.CalcTCPChecksum()
	tcp.Send()
	tcp.IncrSeq(uint32(len(tcp.UserData)))
}

// client: 'sudo iptables -t filter -I OUTPUT -p tcp --sport YOUR_SOURCE_PORT --tcp-flags RST RST -j DROP'
// Run Server as:
/*
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(("0.0.0.0", 9999))
sock.listen(16)
*/
//just skip seq and send packet to make server treat pakcet as out of order packet
func (tcp *TCPIP) OfoRecover(userData []byte) {
	if err := tcp.DoHandshake(); err != nil {
		panic(err)
	}

	//packet 1, 3 byte
	tcp.AddData(userData[:3])
	tcp.CalcTCPChecksum()
	tcp.Send()
	tcp.IncrSeq(uint32(len(tcp.UserData)))

	savedSeq := tcp.GetSeq()

	// make a 2 byte hole for packet 2
	tcp.IncrSeq(uint32(2))

	//packet 3, x-5 byte, before packet 2 sent
	tcp.AddData(userData[5:])
	tcp.CalcTCPChecksum()
	tcp.Send()
	tcp.IncrSeq(uint32(len(tcp.UserData)))

	//now send packet 2
	//packet 2's seq must greater than packet 1's seq
	//packet 2's seq must less than packet 1's seq
	//packet 2's end_seq must not less than packet 1's end seq
	/*
		packet1  |------|
		packet3            |-----|
		packet2         |--|          -> TCP excepted
	*/
	time.Sleep(10 * time.Millisecond)
	tcp.SetSeq(savedSeq)
	tcp.AddData(userData[3:5])
	tcp.CalcTCPChecksum()
	tcp.Send()
	time.Sleep(100 * time.Millisecond)
}

// client: 'sudo iptables -t filter -I OUTPUT -p tcp --sport YOUR_SOURCE_PORT --tcp-flags RST RST -j DROP'
// Run Server as:
/*
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(("0.0.0.0", 9999))
sock.listen(16)
*/
//skip seq and send packet to make server treat pakcet as out of order packet
func (tcp *TCPIP) OfoMerge(userData []byte) {
	if err := tcp.DoHandshake(); err != nil {
		panic(err)
	}
	//savedSeq0 := tcp.GetSeq()
	//make a 1 byte hole
	tcp.IncrSeq(1)

	//packet 1, 2 byte, ofo
	tcp.AddData(userData[1:3])
	tcp.CalcTCPChecksum()
	tcp.Send()
	tcp.IncrSeq(uint32(len(tcp.UserData)))

	savedSeq := tcp.GetSeq()

	//make a 2 byte hole for packet 2
	tcp.IncrSeq(uint32(2))

	//packet 3, x-5 byte, before packet 2 sent
	tcp.AddData(userData[5:])
	tcp.CalcTCPChecksum()
	tcp.Send()
	tcp.IncrSeq(uint32(len(tcp.UserData)))

	//now send packet 2
	/*
		    packet0 .| after tcp handshake
			packet1   |------|
			packet3             |-----|
			packet2         |-|
	*/
	time.Sleep(10 * time.Millisecond)
	tcp.SetSeq(savedSeq)
	tcp.DecSeq(1)
	tcp.AddData(userData[2:3])
	tcp.CalcTCPChecksum()
	tcp.Send()
	time.Sleep(100 * time.Millisecond)
}

// client: 'sudo iptables -t filter -I OUTPUT -p tcp --sport YOUR_SOURCE_PORT --tcp-flags RST RST -j DROP'
// Run Server as:
/*
import socket
import time
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_DEBUG, 1)
sock.bind(("0.0.0.0", 9999))
sock.listen(16)
while True:
    c, addr = sock.accept()
    c.setsockopt(socket.SOL_SOCKET, socket.SO_DEBUG, 1)
    c.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUFFORCE, 1024)
    time.sleep(5)
    c.close()
*/
//skip seq and send packet to make server treat pakcet as out of order packet
func (tcp *TCPIP) OfoPrune(userData []byte) {
	if err := tcp.DoHandshake(); err != nil {
		panic(err)
	}

	n := 0
	for n < len(userData) {
		tcp.AddData(userData[n : n+1])
		tcp.CalcTCPChecksum()
		tcp.Send()
		tcp.IncrSeq(uint32(len(tcp.UserData)))
		//make a hole
		tcp.IncrSeq(1)
		time.Sleep(100 * time.Millisecond)
		n++
	}
}
