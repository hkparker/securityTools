package main

//
//	QUANTUMDETECT
//
//	This script identifies two TCP packets that
//		have identical source ip
//		have identical source port
//		have identical destination port
//		have identical sequence numbers
//		are both not empty
//		contain different data, not just more data
//		occur within --window seconds of each other
//
//	These conditions could indicate a QUANTUMINSERT attack, see
//		http://www.spiegel.de/fotostrecke/qfire-die-vorwaertsverteidigng-der-nsa-fotostrecke-105358-15.html
//		https://www.schneier.com/blog/archives/2013/10/how_the_nsa_att.html
//		https://bro-tracker.atlassian.net/browse/BIT-1314
//

import (
	"fmt"
	"time"
	"strconv"
	"bytes"
	"sync"
	"flag"
	"io/ioutil"
	"os"
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/pcap"
	"code.google.com/p/gopacket/layers"
	)

//
//	Compare byte arrays equality, used to compare tcp payloads
//
func Equal(a, b []byte) bool {
    if len(a) != len(b) {
	return false
    }

    for i := range a {
        if a[i] != b[i] {
            return false
        }
    }

    return true
}

//
//	Used to write packet details to file when QUANTUMINSERT is detected
//
func WriteAlert(source_ip, source_port, destination_port, seq string, body, data []byte) {
	
	//
	//	Alert in the console
	//
	fmt.Println("POSSIBLE QUANTUMINSERT ATTACK DETECTED!!! SrcIP:", source_ip, "SrcPort:", source_port, "DstPort:", destination_port, "Seq:", seq)
	
	//
	//	Prepare path to save data
	//
	var dirs bytes.Buffer
	dirs.WriteString("QIlogs/")
	dirs.WriteString(source_ip)
	dirs.WriteString("/")
	dirs.WriteString(source_port)
	dirs.WriteString("/")
	dirs.WriteString(destination_port)
	dirs.WriteString("/")
	dirs.WriteString(seq)
	dirs.WriteString("/")
	path := dirs.String()
	
	//
	//	Write raw data and encoded byte array
	//
	os.MkdirAll(path, 0644)
	err := ioutil.WriteFile((path+"0.raw"), body, 0644)
	if err != nil { fmt.Println(err)}
	err = ioutil.WriteFile((path+"1.raw"), data, 0644)
	if err != nil { fmt.Println(err)}
	err = ioutil.WriteFile((path+"0.hex"), []byte(fmt.Sprintf("%#v", body)), 0644)
	if err != nil { fmt.Println(err)}
	err = ioutil.WriteFile((path+"1.hex"), []byte(fmt.Sprintf("%#v", data)), 0644)
	if err != nil { fmt.Println(err)}
}

func main() {
	var iface = flag.String("interface", "eth0", "interface to sniff for QUANTUMINSERT")
	var network = flag.String("network", "192.168.1.0/24", "CIDR notation of your local subnet")
	var window = flag.Int("window", 1, "seconds to hold onto packet information")
	flag.Parse()
	
	//
	//	A map is used to associate packet information, such as the ports, source ip,
	//	and sequence number with the packet payload.  Maps are not goroutine safe, so
	//	a mutex is used to prevent panics.
	//
	var mutex = &sync.Mutex{}
	responses := make(map[string][]byte)
	
	//
	//	The iface and network flags are used to open a pcap handle and filter packets
	//
	if handle, err := pcap.OpenLive(*iface, 1600, true, 0); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter("tcp and dst net " + *network); err != nil {
		panic(err)
	} else {
		
		//
		//	Now that we have a pcap handle, we create a packet source and start sniffing traffic
		//
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			
			//
			//	Access layers for parsing the packets
			//
			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			tcp, _ := tcpLayer.(*layers.TCP)
			ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
			ipv4, _ := ipv4Layer.(*layers.IPv4)
			
			//
			//	Data to indentify a unique packet
			//		source ip
			//		source port
			//		destination port
			//		sequence number
			//
			//	This will be used as the key in the hash table if this packet contains data
			//
			source_ip := ipv4.SrcIP.String()
			source_port := strconv.Itoa(int(tcp.SrcPort))
			destination_port := strconv.Itoa(int(tcp.DstPort))
			seq := strconv.Itoa(int(tcp.Seq))
			var buffer bytes.Buffer
			buffer.WriteString(source_ip)
			buffer.WriteString(source_port)
			buffer.WriteString(destination_port)
			buffer.WriteString(seq)
			entry := buffer.String()
			
			//
			//	If we have seen the combination of the above packet information in the last second...
			//
			if body, present := responses[entry]; present {
				
				//
				//	...and the last time we saw this packet it contained different data...
				//
				data := tcp.LayerPayload()
				if !Equal(body, data) {
					
					//
					//	...then this is possibly a QUANTUMINSERT attack.  Print a warning and log everything to file.
					//
					go WriteAlert(source_ip, source_port, destination_port, seq, body, data)
				}
				
			//
			//	If we have not seen this packet before, but it contains data...
			//
			} else if !(len(tcp.LayerPayload()) == 0) {
				
				//
				//	...add this packet to the map.  Start a goroutine to delete it in --window seconds.
				//
				mutex.Lock()
				responses[entry] = tcp.LayerPayload()
				mutex.Unlock()
				go func() {
					time.Sleep(time.Duration(*window) * time.Second)
					mutex.Lock()
					delete(responses, entry)
					mutex.Unlock()
				}()
			}
		}
	}
}