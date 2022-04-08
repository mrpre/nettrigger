package tcplib

import (
	"context"
	"fmt"
	"time"
)

// 0. sudo iptables -t filter -I OUTPUT -p tcp --sport SRCPORT:SRCPORT+100 --tcp-flags RST RST -j DROP
// 1. stop sysctl_tcp_syncookies in server: echo "0" > /proc/sys/net/ipv4/tcp_syncookies
// 2. set sysctl_max_syn_backlog to VAR: 'echo "VAR" > /proc/sys/net/ipv4/tcp_max_syn_backlog', e.g. VAR=32
// 3. sudo ip tcp_metrics delete 11.164.2.90
// 4. Run Server as:
/*
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(("0.0.0.0", 9999))
#replace VAR to tcp_max_syn_backlog
sock.listen(VAR)
*/
// 5. Cleint will connect fail
func (tcp *TCPIP) ProvenDrop(dst string) {

	var i int = 0
	fd := tcp.NewSocket()
	tcp.FD = fd

	for {
		i++
		fmt.Println("[test ProvenDrop] tcp half connect", i)
		tcp.InitTcpOptions()
		//please remember bolck this port using iptables
		tcp.SrcPort++
		seq := 0xf0f1f2f3 + uint32(i)*10

		tcp.InitSYN(seq)
		tcp.CalcTCPChecksum()
		//send SYN
		tcp.Send()
		ctx, _ := context.WithTimeout(context.Background(), 1*time.Second)
		exceptAck := seq + 1
		resp := tcp.Recv(ctx, tcp.FD, &exceptAck)
		if resp == nil {
			if i <= 26 {
				fmt.Println("[SUCCESS]trigger tcp_peer_is_proven success")
				return
			}
			panic(fmt.Errorf("time out waiting SYN ACK"))
		}
		if !resp.ACK() || !resp.SYN() {
			panic(fmt.Errorf("unexpected Packet, not SYNACK"))
		}

		/*
			i++
			fmt.Println("[test accept full]tcp connect ", i)
			conn, err := net.DialTimeout("tcp", dst, 2*time.Second)
			if err != nil {
				fmt.Println(err)
				//leave more time to see debug or other things
				time.Sleep(10 * time.Second)
				panic(err)
			}
			if i == 26 {
				fmt.Println("please do sudo 'ip tcp_metrics delete $SRC' in server in 10s")
				time.Sleep(10 * time.Second)
			}
			connChan <- conn
			defer conn.Close()
			time.Sleep(100 * time.Millisecond)
		*/
	}

	//SUCCSS
	fmt.Println("[SUCCESS]Tcp Accept")
}
