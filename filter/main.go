package main

import (
	"fmt"
	"log"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var (
	iface    = "\\Device\\NPF_{D42656AA-5625-4ED4-9202-DFCD451B3F78}"
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
	fmt.Println("Only capturing TCP port 80 packets.")
	fmt.Printf("Sources: %v\n", source)
	for packet := range source.Packets() {
		fmt.Println(packet)
	}
}
