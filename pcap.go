package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type IPToMACEnt struct {
	IP        string
	MAC       string
	Count     int64
	Change    int64
	FirstTime int64
	LastTime  int64
	SendTime  int64
}

func (e *IPToMACEnt) String() string {
	return fmt.Sprintf("ip=%s,mac=%s,count=%d,change=%d,ft=%s,lt=%s",
		e.IP, e.MAC, e.Count, e.Change,
		time.Unix(e.FirstTime, 0).Format(time.RFC3339),
		time.Unix(e.LastTime, 0).Format(time.RFC3339),
	)
}

var (
	IPToMAC sync.Map
)

func startPcap(ctx context.Context) {
	handle, err := pcap.OpenLive(iface, int32(65540), true, time.Second*30)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	timer := time.NewTicker(time.Second * 30)
	defer timer.Stop()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		select {
		case packet := <-packetSource.Packets():
			checkPacket(packet)
		case <-timer.C:
			sendReport()
		case <-ctx.Done():
			log.Println("stop pcap")
			return
		}
	}
}

func checkPacket(packet gopacket.Packet) {
	// for _, layer := range packet.Layers() {
	// 	fmt.Println("- ", layer.LayerType())
	// }
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer == nil {
		return
	}
	eth, ok := ethernetLayer.(*layers.Ethernet)
	if !ok {
		return
	}
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
			net.HardwareAddr(arp.SourceHwAddress).String())
		return
	}
	// ipLayer := packet.Layer(layers.LayerTypeIPv4)
	// if ipLayer != nil {
	// 	ip, ok := ipLayer.(*layers.IPv4)
	// 	if !ok {
	// 		return
	// 	}
	// 	updateIPToMAC(ip.SrcIP.String(), eth.SrcMAC.String())
	// }
	ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
	if ipv6Layer != nil {
		ipv6, ok := ipv6Layer.(*layers.IPv6)
		if !ok {
			log.Println(packet)
			return
		}
		icmpv6NALayer := packet.Layer(layers.LayerTypeICMPv6NeighborAdvertisement)
		if icmpv6NALayer != nil {
			updateIPToMAC(ipv6.SrcIP.String(), eth.SrcMAC.String())
			return
		}
		icmpv6RALayer := packet.Layer(layers.LayerTypeICMPv6RouterAdvertisement)
		if icmpv6RALayer != nil {
			updateIPToMAC(ipv6.SrcIP.String(), eth.SrcMAC.String())
		}
	}
}

func sendReport() {
	now := time.Now().Unix()
	st := time.Now().Add(-time.Second * time.Duration(syslogInterval)).Unix()
	rt := time.Now().Add(-time.Second * time.Duration(retentionData)).Unix()
	IPToMAC.Range(func(k, v interface{}) bool {
		if e, ok := v.(*IPToMACEnt); ok {
			if e.LastTime < rt {
				IPToMAC.Delete(e.IP)
				return true
			}
			if e.SendTime < st {
				log.Println(e.String())
				syslogCh <- e.String()
				e.SendTime = now
			}
		}
		return true
	})
}

func updateIPToMAC(ip, mac string) {
	if v, ok := IPToMAC.Load(ip); ok {
		if e, ok := v.(*IPToMACEnt); ok {
			if e.MAC != mac {
				e.Change++
			}
			e.Count++
			e.LastTime = time.Now().Unix()
		}
		return
	}
	now := time.Now().Unix()
	IPToMAC.Store(ip, &IPToMACEnt{
		IP:        ip,
		MAC:       mac,
		Count:     1,
		FirstTime: now,
		LastTime:  now,
	})
	log.Println(ip, mac)
}
