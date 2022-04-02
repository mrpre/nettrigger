package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	tcplib "nettrigger/src/lib"
	"os"
	"os/user"
	"strings"
)

func exitErr(reason error) {
	fmt.Println(reason)
	os.Exit(1)
}

func main() {
	user, err := user.Current()
	if err != nil || user.Name != "root" {
		exitErr(fmt.Errorf("root privileges required for execution"))
	}

	//sudo iptables -t filter -I OUTPUT -p tcp --sport 12345 --tcp-flags RST RST -j DROP
	sourceAddr := flag.String("s", "", "source address ip:port")
	destAddr := flag.String("d", "", "destination address ip:port")
	content := flag.String("h", "474554202f20485454502f312e310d0a0d0a", "hex string content that will send to remote if tcp handshake success. Defeult is 'GET / HTTP/1.1\\r\\n\\r\\n'")
	ifaceName := flag.String("i", "", "Network Interface")
	flag.Parse()

	userData, err := hex.DecodeString(*content)
	if err != nil {
		exitErr(err)
	}

	source, err := net.ResolveTCPAddr("tcp4", *sourceAddr)
	if err != nil {
		exitErr(err)
	}

	dest, err := net.ResolveTCPAddr("tcp4", *destAddr)
	if err != nil {
		exitErr(err)
	}

	var packet = &tcplib.TCPIP{}
	var foundIface bool = false
	foundIfaces := packet.GetInterfaces()
	for _, name := range foundIfaces {
		if name != *ifaceName {
			continue
		}
		foundIface = true
	}

	if !foundIface {
		msg := "Invalid argument for -i <interface> Found: %s"
		errmsg := fmt.Errorf(msg, strings.Join(foundIfaces, ", "))
		exitErr(errmsg)
	}

	defer func() {
		if err := recover(); err != nil {
			exitErr(fmt.Errorf("error: %v", err))
		}
	}()

	packet.SetSource(source.IP.String(), uint16(source.Port))
	packet.SetTarget(dest.IP.String(), uint16(dest.Port))

	packet.PAWSPassiveReject(userData)

	/*
		packet.FloodTarget(
			reflect.TypeOf(packet).Elem(),
			reflect.ValueOf(packet).Elem(),
		)
	*/
}
