package tcplib

import (
	"fmt"
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
