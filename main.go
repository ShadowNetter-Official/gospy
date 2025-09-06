package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"github.com/fatih/color"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// get user IP for filtering
func getLocalIP() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && ip.To4() != nil && !ip.IsLoopback() {
				return ip.String(), nil
			}
		}
	}
	return "", fmt.Errorf("no valid local IP found")
}

// help message
func help() {
	fmt.Println("gospy | a minimal packet sniffer written in 🇬 🇴")
	fmt.Println("")
	fmt.Println("usage:")
	fmt.Println("")
	fmt.Println("gospy <interface>   | requires root privileges, default interface is wlan0")
	fmt.Println("")
}

func main() {
	// define coloring function
	yellow := color.New(color.FgYellow).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()

	// set default interface
	intf := "wlan0"
	// get interface custom interface
	if len(os.Args) >= 1 {
		intf = os.Args[1]
	}
	if intf == "help" {
		help()
	} else {
		// open capture on interface
		handle, err := pcap.OpenLive(intf, 65536, true, pcap.BlockForever)
		if err != nil {
			log.Fatal("Failed to initialize interface:", err)
		}
		defer handle.Close()

		// apply user IP filtering
		myIP, err := getLocalIP()
		if err != nil {
			log.Fatal("Could not determine local IP:", err)
		}
		filter := fmt.Sprintf("not host %s", myIP)
		if err := handle.SetBPFFilter(filter); err != nil {
			log.Fatal("Failed to set BPF filter:", err)
		}
		fmt.Printf("%v %v %v %v \n \n", green("Sniffing on:"), yellow(intf), green("ignoring host:"), yellow(myIP))

		// capture packets and display source and destination
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			if netLayer := packet.NetworkLayer(); netLayer != nil {
				src, dst := netLayer.NetworkFlow().Endpoints()
				host, _ := net.LookupAddr(dst.String())
				if len(host) > 0 {
					fmt.Printf("%v %v %v %v %v %v \n", green(" :"), yellow(src), green(" "), yellow(dst), green("|"), yellow(host))
				} else {
					fmt.Printf("%v %v %v %v \n", green(" :"), yellow(src), green(" "), yellow(dst))
				}
			}
		}
	}
}

