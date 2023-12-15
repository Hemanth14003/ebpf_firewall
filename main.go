package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
)

const (
	blockMapName = "blocked_ips"
)

// convert ip address into network byte order
func ipToInt(val string) uint32 {
	ip := net.ParseIP(val).To4()
	return binary.LittleEndian.Uint32(ip)
}

func sbnToInt(val string) uint32 {
	ip := net.ParseIP(val).To4()
	return binary.BigEndian.Uint32(ip)
}
func portToInt(val string) uint16 {
	// Convert the string to an integer
	port, _ := strconv.ParseUint(val, 10, 16)

	// Convert the integer to network byte order (little-endian)
	portBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(portBytes, uint16(port))

	return binary.LittleEndian.Uint16(portBytes)
}

// convert network byte order to ip address
func intToIP(val uint32) net.IP {
	var bytes [4]byte
	binary.LittleEndian.PutUint32(bytes[:], val)
	if bytes[0] == 0 {
		return net.IPv4(bytes[3], bytes[2], bytes[1], bytes[0])
	}
	return net.IPv4(bytes[0], bytes[1], bytes[2], bytes[3])
}

func main() {
	if len(os.Args) == 1 {
		fmt.Println("Give me an action: load, show, unload, allow_(ip/dns/sbn) [address] or block_(ip/dns/sbn) [address]")
		return
	}

	action := os.Args[1]
	if action == "load" {
		// terminal commands for loading ebpf program
		cmd := exec.Command("tc", "qdisc", "add", "dev", "ens33", "clsact")
		if err := cmd.Run(); err != nil {
			fmt.Println("Failed to add qdisc:", err)
			return
		}

		cmd = exec.Command("tc", "filter", "add", "dev", "ens33", "ingress", "bpf", "da", "obj", "/home/hemanth1/GolandProjects/awesomeProject1/ebpf.o", "sec", "tc/ingress")
		if err := cmd.Run(); err != nil {
			fmt.Println("Failed to add tc filter:", err)
			return
		}

		// Wait for the execution of the external commands to finish
		cmd.Wait()

	} else {
		// Loading ebpf map
		loadPinOptions := ebpf.LoadPinOptions{}
		blockMap_ips, err := ebpf.LoadPinnedMap(fmt.Sprintf("/sys/fs/bpf/tc/globals/%s", blockMapName), &loadPinOptions)
		if err != nil {
			log.Fatal(err)
		}

		if action == "unload" {
			// terminal commands for unloading ebpf program
			cmd := exec.Command("tc", "qdisc", "del", "dev", "ens33", "clsact")
			if err := cmd.Run(); err != nil {
				fmt.Println("Failed to delete qdisc:", err)
				return
			}

			// Wait for the execution of the external command to finish
			cmd.Wait()

		} else if action == "show" {
			ct := 1
			var key uint32
			var value uint32

			fmt.Printf("+%s+\n", strings.Repeat("-", 30))
			fmt.Printf("| %-10s | %-15s |\n", "S.no", "Blocked IPs")

			// Iterate over the eBPF map
			iter := blockMap_ips.Iterate()
			for iter.Next(&key, &value) {
				ips := intToIP(value) //convert network byte order to ip address
				fmt.Printf("|%s|\n", strings.Repeat("-", 30))
				fmt.Printf("| %-10d | %-15v |\n", ct, ips)
				ct += 1
			}
			fmt.Printf("+%s+\n", strings.Repeat("-", 30))

		} else if action == "allow_ip" && len(os.Args) == 3 {
			ip := ipToInt(os.Args[2]) //convert ip address into network byte order

			if err := blockMap_ips.Delete(&ip); err != nil { // Adding ip to the map
				fmt.Println("Failed to update the element in the 'allowed_ips' map:", err)
				return
			}

		} else if action == "allow_dns" && len(os.Args) == 3 {

			ips, err := net.LookupIP(os.Args[2])
			if err != nil {
				fmt.Printf("DNS lookup failed: %v\n", err)
				return
			}
			for _, ip := range ips {
				if ip.To4() != nil {
					//convert ip address into network byte order
					ipNB := ipToInt(ip.String())
					if err := blockMap_ips.Delete(&ipNB); err != nil { // Adding ip to the map
						fmt.Println("Failed to update the element in the 'allowed_ips' map:", err)
						return
					}
				}
			}
		} else if action == "allow_sbn" && len(os.Args) == 3 {
			sbn := sbnToInt(os.Args[2]) //convert ip address into network byte order

			if err := blockMap_ips.Delete(&sbn); err != nil { // Adding ip to the map
				fmt.Println("Failed to update the element in the 'allowed_ips' map:", err)
				return
			}

		} else if action == "block_ip" && len(os.Args) == 3 {
			ip := ipToInt(os.Args[2])                          //convert ip address into network byte order
			if err := blockMap_ips.Put(&ip, &ip); err != nil { // Deleting ip from the map
				fmt.Println("Failed to delete the element from the 'allowed_ips' map:", err)
				return
			}

		} else if action == "block_dns" && len(os.Args) == 3 {

			ips, err := net.LookupIP(os.Args[2])
			if err != nil {
				fmt.Printf("DNS lookup failed: %v\n", err)
				return
			}
			for _, ip := range ips {
				if ip.To4() != nil {
					//convert ip address into network byte order
					ipNB := ipToInt(ip.String())
					if err := blockMap_ips.Put(&ipNB, &ipNB); err != nil { // Adding ip to the map
						fmt.Println("Failed to update the element in the 'allowed_ips' map:", err)
						return
					}
				}
			}
		} else if action == "block_sbn" && len(os.Args) == 3 {
			sbn := sbnToInt(os.Args[2]) //convert ip address into network byte order

			if err := blockMap_ips.Put(&sbn, &sbn); err != nil { // Adding ip to the map
				fmt.Println("Failed to update the element in the 'allowed_ips' map:", err)
				return
			}

		} else {
			fmt.Println("Unknown action given or wrong number of params:", action)
		}
	}
}
