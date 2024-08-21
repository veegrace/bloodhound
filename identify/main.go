package main

import (
	"fmt"
	"log"

	"github.com/google/gopacket/pcap"
)

func main() {
	devices, err := pcap.FindAllDevs() // Enumerate all devices.
	if err != nil {
		log.Panicln(err)
	}

	fmt.Printf("Total Number of Devices: %v\n", len(devices))

	for count, device := range devices {
		fmt.Printf("Device #%v\n   - Name: %v\n   - Description: %v\n",
			count+1, device.Name, device.Description)

		for _, address := range device.Addresses {
			fmt.Printf("    	IP:      %s\n", address.IP)
			fmt.Printf("    	Netmask: %s\n", address.Netmask)
		}
	}
}
