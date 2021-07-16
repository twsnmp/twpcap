package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// startPcap : start packet capchare
func startPcap(ctx context.Context) {
	handle, err := pcap.OpenLive(iface, int32(65540), true, time.Second*30)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	timer := time.NewTicker(time.Second * 60)
	defer timer.Stop()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	total := int64(0)
	count := int64(0)
	for {
		select {
		case packet := <-packetSource.Packets():
			checkPacket(packet)
			count++
			total++
		case <-timer.C:
			syslogCh <- fmt.Sprintf("type=Stats,total=%d,count=%d,ps=%.2f", total, count, float64(count)/60.0)
			count = 0
			go sendReport()
		case <-ctx.Done():
			log.Println("stop pcap")
			return
		}
	}
}

// check packet
func checkPacket(packet gopacket.Packet) {
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer == nil {
		return
	}
	eth, ok := ethernetLayer.(*layers.Ethernet)
	if !ok {
		return
	}
	macaddr := eth.SrcMAC.String()
	updateEtherType(uint16(eth.EthernetType))
	arpLayer := packet.Layer(layers.LayerTypeARP)
	if arpLayer != nil {
		arp, ok := arpLayer.(*layers.ARP)
		if !ok {
			return
		}
		if arp.HwAddressSize != 6 || arp.ProtAddressSize != 4 {
			return
		}
		updateIPToMAC(net.IP(arp.SourceProtAddress).String(),
			net.HardwareAddr(arp.SourceHwAddress).String(), 0)
		return
	}
	src := ""
	dst := ""
	ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
	if ipv4Layer != nil {
		ip, ok := ipv4Layer.(*layers.IPv4)
		if !ok {
			return
		}
		src = ip.SrcIP.String()
		dst = ip.DstIP.String()
	} else {
		ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
		if ipv6Layer != nil {
			ipv6, ok := ipv6Layer.(*layers.IPv6)
			if !ok {
				return
			}
			src = ipv6.SrcIP.String()
			dst = ipv6.DstIP.String()
			icmpv6NALayer := packet.Layer(layers.LayerTypeICMPv6NeighborAdvertisement)
			icmpv6RALayer := packet.Layer(layers.LayerTypeICMPv6RouterAdvertisement)
			if icmpv6NALayer != nil || icmpv6RALayer != nil {
				updateIPToMAC(src, macaddr, 0)
				return
			}
			if packet.Layer(layers.LayerTypeICMPv6) != nil {
				return
			}
		}
	}
	// UDP
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		_, ok := udpLayer.(*layers.UDP)
		if !ok {
			return
		}
		dnsLayer := packet.Layer(layers.LayerTypeDNS)
		if dnsLayer != nil {
			dns, ok := dnsLayer.(*layers.DNS)
			if !ok {
				return
			}
			updateDNS(dns, src, macaddr)
			return
		}
		ntpLater := packet.Layer(layers.LayerTypeNTP)
		if ntpLater != nil {
			ntp, ok := ntpLater.(*layers.NTP)
			if !ok {
				return
			}
			updateNTP(ntp, src, dst)
		}
		dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4)
		if dhcpLayer != nil {
			dhcp, ok := dhcpLayer.(*layers.DHCPv4)
			if !ok {
				return
			}
			updateDHCP(dhcp, src)
		}
		radiusLayer := packet.Layer(layers.LayerTypeRADIUS)
		if radiusLayer != nil {
			radius, ok := radiusLayer.(*layers.RADIUS)
			if !ok {
				return
			}
			updateRADIUS(radius, src, dst)
		}
	} else {
		// TCP
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			tcp, ok := tcpLayer.(*layers.TCP)
			if !ok {
				return
			}
			if packet.ApplicationLayer() != nil {
				var tls layers.TLS
				var decoded []gopacket.LayerType
				b := packet.ApplicationLayer().LayerContents()
				parser := gopacket.NewDecodingLayerParser(layers.LayerTypeTLS, &tls)
				err := parser.DecodeLayers(b, &decoded)
				if err != nil {
					if len(b) > (5+4+2+32) && b[0] == 0x16 && b[5] == 0x02 {
						checkDecodeErrorTLSPacket(src, dst, int(tcp.SrcPort), b)
					}
					return
				}
				for _, layerType := range decoded {
					switch layerType {
					case layers.LayerTypeTLS:
						// TLS
						updateTLS(&tls, src, dst, int(tcp.SrcPort), int(tcp.DstPort))
					}
				}
			}
		}
	}
}

var busy = false

// syslogでレポートを送信する
func sendReport() {
	if busy {
		log.Printf("send report busy")
		return
	}
	busy = true
	now := time.Now().Unix()
	st := time.Now().Add(-time.Second * time.Duration(syslogInterval)).Unix()
	rt := time.Now().Add(-time.Second * time.Duration(retentionData)).Unix()
	sendIPToMACReport(now, st, rt)
	sendEtherTypeReport(st)
	sendDNSReport(now, st, rt)
	sendNTPReport(now, st, rt)
	sendDHCPReport(now, st, rt)
	sendTLSReport(now, st, rt)
	sendRADIUSReport(now, st, rt)
	busy = false
}
