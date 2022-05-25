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

	sourceAddr := flag.String("s", "", "source address ip:port")
	destAddr := flag.String("d", "", "destination address ip:port")
	content := flag.String("h", "474554202f20485454502f312e310d0a0d0a", "hex string content that will send to remote after tcp handshake success. Defeult is 'GET / HTTP/1.1\\r\\n\\r\\n'")
	devName := flag.String("i", "", "Network Interface")
	action := flag.String("action", "", "the true action")

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
	var foundDev bool = false
	foundDevs := packet.GetInterfaces()
	for _, name := range foundDevs {
		if name != *devName {
			continue
		}
		foundDev = true
	}

	if !foundDev {
		msg := "Invalid argument for -i <interface> Found: %s"
		errmsg := fmt.Errorf(msg, strings.Join(foundDevs, ", "))
		exitErr(errmsg)
	}

	defer func() {
		if err := recover(); err != nil {
			exitErr(fmt.Errorf("error: %v", err))
		}
	}()

	packet.SetSource(source.IP.String(), uint16(source.Port))
	packet.SetTarget(dest.IP.String(), uint16(dest.Port))

	if *action == "paws" {
		packet.PAWSPassiveReject(userData)
	} else if *action == "accept" {
		packet.AcceptFull(*destAddr)
	} else if *action == "proven" {
		packet.ProvenDrop(*destAddr)
	} else if *action == "half" {
		packet.HalfOpenFULL(*destAddr)
	} else if *action == "ofo" {
		packet.OfoNormal(userData)
	} else if *action == "ofocoalesce" {
		//coalesce also triggered by OfoRecover
		packet.OfoRecover(userData)
	} else if *action == "oforecover" {
		packet.OfoRecover(userData)
	} else if *action == "ofoprune" {
		packet.OfoPrune(userData)
	} else if *action == "ofoprunedrop" {
		packet.OfoPruneDrop(userData)
	} else if *action == "recvdrop" {
		packet.RecvDrop(userData)
	} else if *action == "synackdrop" {
		packet.SynAckDrop(userData)
	} else if *action == "send4k" {
		packet.SendData(4000)
	} else if *action == "rawack" {
		packet.RawAck()
	}
}
