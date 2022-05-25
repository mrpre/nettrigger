package tcplib

import (
	"fmt"
	"log"
	"net"
	"time"
)

/*
Run Server as:
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(("0.0.0.0", 9999))
sock.listen(16)
*/
//just do as much as handshake
func (tcp *TCPIP) AcceptFull(dst string) {
	connChan := make(chan net.Conn, 200)
	var i int = 0
	for {
		i++
		fmt.Println("[test accept full]tcp connect ", i)
		conn, err := net.DialTimeout("tcp", dst, 2*time.Second)
		if err != nil {
			panic(err)
		}
		connChan <- conn
		defer conn.Close()
		time.Sleep(100 * time.Millisecond)
	}

	//SUCCSS
	fmt.Println("[SUCCESS]Tcp Accept")
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
    time.sleep(20)
    c.close()
*/
func (tcp *TCPIP) RecvDrop(userData []byte) {
	if err := tcp.DoHandshake(); err != nil {
		panic(err)
	}

	//userData is too small to trigger drop
	tmp := make([]byte, 1024)

	n := 0
	for n < 20 {
		tcp.AddData(tmp)
		tcp.CalcTCPChecksum()
		tcp.Send()
		tcp.IncrSeq(uint32(len(tcp.UserData)))
		time.Sleep(100 * time.Millisecond)
		n++
	}
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
*/
func (tcp *TCPIP) SynAckDrop(userData []byte) {

	fd := tcp.NewSocket()
	tcp.FD = fd

	tcp.InitTcpOptions()

	tcp.InitSYN(0xf0f1f2f3)
	tcp.CalcTCPChecksum()

	//send SYN
	tcp.Send()
	time.Sleep(100 * time.Second)
}

func (tcp *TCPIP) SendData(size int) {

	if err := tcp.DoHandshake(); err != nil {
		panic(err)
	}

	tmp := make([]byte, size)
	round := size / 1000
	roundRmain := size % 1000
	n := 0
	for n = 0; n < round; n++ {
		log.Println("send data ", n)
		tcp.AddData(tmp[n*1000 : n*1000+1000])
		tcp.CalcTCPChecksum()
		tcp.Send()
		tcp.IncrSeq(uint32(len(tcp.UserData)))
		time.Sleep(100 * time.Millisecond)
	}

	if roundRmain > 0 {
		log.Println("send data ", n)
		tcp.AddData(tmp[n*1000:])
		tcp.CalcTCPChecksum()
		tcp.Send()
		tcp.IncrSeq(uint32(len(tcp.UserData)))
		time.Sleep(100 * time.Millisecond)
	}
	fmt.Println("type ctrl-c to stop")
	time.Sleep(100 * time.Second)
}
