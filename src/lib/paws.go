package tcplib

import (
	"context"
	"fmt"
	"time"
)

// client: 'sudo iptables -t filter -I OUTPUT -p tcp --sport YOUR_SOURCE_PORT --tcp-flags RST RST -j DROP'
// server: a server which will close normally when recv userData
// by default userData is HTTP GET and you can just start HTTP server like 'python -m SimpleHTTPServer 8080'
func (tcp *TCPIP) PAWSPassiveReject(userData []byte) {
	// 3-way tcp handshake
	// make tcp connection active closed by remote
	// 4-way handshake
	// send new packet with invalid TS

	//it's seconds
	tcp.UserTS = []byte{
		0xff, 0xff, 0xff, 0x01,
	}

	if err := tcp.DoHandshake(); err != nil {
		panic(err)
	}

	if len(tcp.PeerTS) == 0 {
		panic(fmt.Errorf("peer doesn't send TS. May server disable it or some Gateway remove it"))
	}

	tcp.AddData(userData)
	tcp.CalcTCPChecksum()
	tcp.Send()
	tcp.IncrSeq(uint32(len(tcp.UserData)))
	var resp *TCPIP
	var respSaved *TCPIP

	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	//remote may send ACK,DATA,FIN or DATA+ACK,FIN or DATA+ACK+FIN
	//we just care about whether remote send the FIN
	//5s may cause a lot of retransmission of remote
	for {
		resp = tcp.Recv(ctx, tcp.FD, nil)
		if resp != nil {
			respSaved = resp
		} else {
			//timeout
			if respSaved == nil {
				//timeout and no previous packet received
				panic(fmt.Errorf("we receive nothing after sending data"))
			}
			break
		}
	}

	//receive FIN ACK
	if !respSaved.FIN() {
		panic(fmt.Errorf("the server doesn't send FIN to us after end data so that connection in server can't be translated to TIMEWAIT. You should change your User data"))
	}

	tcp.Accept(respSaved)
	//send FIN ACK
	tcp.RemoveData()
	tcp.SetFlag(FLAGFIN | FLAGACK)
	tcp.CalcTCPChecksum()
	tcp.Send()
	//consume the server last ACK
	ctx, _ = context.WithTimeout(context.Background(), 2*time.Second)
	resp = tcp.Recv(ctx, tcp.FD, nil)
	if resp != nil && !resp.ACK() {
		panic("last ack not received")
	}

	//now server is in TIMEWAIT
	//use smaller TS to send SYN, that's what PAWS happens
	//There is different in kernel >= 4.12
	//3.10
	//https://elixir.bootlin.com/linux/v3.10.108/source/net/ipv4/tcp_ipv4.c#L1565
	//https://elixir.bootlin.com/linux/v3.10.108/source/net/ipv4/tcp_metrics.c#L49

	/* 4.12
	//see more in tcp_timewait_state_process

	static inline bool tcp_paws_check(const struct tcp_options_received *rx_opt,
					  int paws_win)
	{
		if ((s32)(rx_opt->ts_recent - rx_opt->rcv_tsval) <= paws_win)
			return true;
		if (unlikely(!time_before32(ktime_get_seconds(),
					    rx_opt->ts_recent_stamp + TCP_PAWS_24DAYS)))
			return true;
		...
	}
	*/
	//originalTs - 1
	tcp.UserTS = []byte{
		0xff, 0xff, 0xff, 0x00,
	}
	tcp.InitTcpOptions()
	tcp.InitSYN(0xf0f1f2f3)
	tcp.CalcTCPChecksum()

	//wait al least /proc/sys/net/ipv4/tcp_invalid_ratelimit in server otherwise an ACK may received even PAWS happens
	time.Sleep(1 * time.Second)
	//send SYN
	tcp.Send()

	ctx, _ = context.WithTimeout(context.Background(), 5*time.Second)
	for {
		resp = tcp.Recv(ctx, tcp.FD, nil)
		if resp != nil {
			respSaved = resp
		} else {
			if respSaved == nil {
				panic(fmt.Errorf("we receive nothing after sending data"))
			}
			break
		}
	}
	if respSaved != nil {
		if respSaved.SYN() && respSaved.ACK() {
			panic(fmt.Errorf("should not receive packet after send PAWS SYN. Does some Gateway change the behavior ?"))
		}
	}

	//SUCCSS
	fmt.Println("[SUCCESS]PAWS Passive Reject")
}
