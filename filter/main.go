package main

import (
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
	filter   = "tcp and port 80"
	devFound = false
)

func main() {
	devices, err := pcap.FindAllDevs() // Enumerate all devices.
	if err != nil {
		log.Panicln(err)
	}

	for _, device := range devices {
		// Check if the device exists.
		if strings.Contains(device.Name, iface) {
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

	if err := handle.SetBPFFilter(filter); err != nil {
		log.Panicln(err)
	}

	source := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range source.Packets() {
		packet := packet
		log.Printf("[PUP]: %v", packet.String())
	}
}
