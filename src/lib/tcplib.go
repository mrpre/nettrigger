package tcplib

import "net"

func (tcp TCPIP) GetInterfaces() []string {
	var interfaces []string
	ifaces, err := net.Interfaces()
	if err != nil {
		panic(err)
	}

	for _, dev := range ifaces {
		interfaces = append(interfaces, dev.Name)
	}
	return interfaces
}
