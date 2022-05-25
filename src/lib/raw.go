package tcplib

import "time"

func (tcp *TCPIP) RawAck() {
	fd := tcp.NewSocket()
	tcp.FD = fd

	tcp.InitTcpOptions()

	tcp.InitACK(0xf0f1f2f3)

	tcp.CalcTCPChecksum()

	//send ACK
	tcp.Send()
	time.Sleep(time.Second)
}
