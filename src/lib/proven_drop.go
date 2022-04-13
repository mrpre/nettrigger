package tcplib

import (
	"context"
	"fmt"
	"time"
)

// 0. client: sudo iptables -t filter -I OUTPUT -p tcp --sport SRCPORT:SRCPORT+100 --tcp-flags RST RST -j DROP
// 1. server: stop sysctl_tcp_syncookies in server: echo "0" > /proc/sys/net/ipv4/tcp_syncookies
// 2. server: cho "1" > /proc/sys/net/ipv4/tcp_no_metrics_save
// 3. server: set sysctl_max_syn_backlog to VAR: 'echo "VAR" > /proc/sys/net/ipv4/tcp_max_syn_backlog', e.g. VAR=32
// 4. server: sudo ip tcp_metrics delete SRC
// 5. Run Server as:
/*
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(("0.0.0.0", 9999))
#replace VAR to tcp_max_syn_backlog
sock.listen(VAR)
*/
// 6. Cleint will connect fail until VAR-i > VAR>>2
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
			//if VAR is 32 fail in 26 is excepted
			if i <= 26 {
				fmt.Println("[SUCCESS]trigger tcp_peer_is_proven success")
				return
			}
			panic(fmt.Errorf("time out waiting SYN ACK"))
		}
		if !resp.ACK() || !resp.SYN() {
			panic(fmt.Errorf("unexpected Packet, not SYNACK"))
		}
	}

	//SUCCSS
	fmt.Println("[SUCCESS]Tcp Accept")
}

// 0. sudo iptables -t filter -I OUTPUT -p tcp --sport SRCPORT:SRCPORT+100 --tcp-flags RST RST -j DROP
// 1. stop sysctl_tcp_syncookies in server: echo "0" > /proc/sys/net/ipv4/tcp_syncookies
// 2. echo "0" > /proc/sys/net/ipv4/tcp_no_metrics_save
// 3. set sysctl_max_syn_backlog to VAR: 'echo "VAR" > /proc/sys/net/ipv4/tcp_max_syn_backlog', e.g. VAR=32
// 4. Request server and close normally.
// 5. sudo ip tcp_metrics show| grep SR
//    SRC age 3.689sec cwnd 10 rtt 208us rttvar 180us source SR
//    The result should be list with rtt/rttvar as above
// 6. Run Server as:
/*
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(("0.0.0.0", 9999))
#replace VAR to tcp_max_syn_backlog
sock.listen(VAR)
*/
// 7. Cleint will connect fail until i == VAR+1
func (tcp *TCPIP) HalfOpenFULL(dst string) {

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
			if i == 33 {
				fmt.Println("[SUCCESS]trigger tcp_peer_is_proven success")
				return
			}
			panic(fmt.Errorf("time out waiting SYN ACK"))
		}
		if !resp.ACK() || !resp.SYN() {
			panic(fmt.Errorf("unexpected Packet, not SYNACK"))
		}
	}

	//SUCCSS
	fmt.Println("[SUCCESS]Tcp Accept")
}
