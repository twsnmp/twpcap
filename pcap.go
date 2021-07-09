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
	return fmt.Sprintf("type=IPToMAC,ip=%s,mac=%s,count=%d,change=%d,ft=%s,lt=%s",
		e.IP, e.MAC, e.Count, e.Change,
		time.Unix(e.FirstTime, 0).Format(time.RFC3339),
		time.Unix(e.LastTime, 0).Format(time.RFC3339),
	)
}

type DNSEnt struct {
	Type      string
	Name      string
	Count     int64
	Change    int64
	LastIP    string
	LastMAC   string
	FirstTime int64
	LastTime  int64
	SendTime  int64
}

func (e *DNSEnt) String() string {
	return fmt.Sprintf("type=DNS,DNSType=%s,Name=%s,count=%d,change=%d,lastIP=%s,lastMAC=%s,ft=%s,lt=%s",
		e.Type, e.Name, e.Count, e.Change,
		e.LastIP,
		e.LastMAC,
		time.Unix(e.FirstTime, 0).Format(time.RFC3339),
		time.Unix(e.LastTime, 0).Format(time.RFC3339),
	)
}

var (
	IPToMAC   sync.Map
	EtherType sync.Map
	DNSQuery  sync.Map
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
			go sendReport()
		case <-ctx.Done():
			log.Println("stop pcap")
			return
		}
	}
}

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
			net.HardwareAddr(arp.SourceHwAddress).String())
		return
	}
	ipaddr := ""
	ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
	if ipv4Layer != nil {
		ip, ok := ipv4Layer.(*layers.IPv4)
		if !ok {
			return
		}
		ipaddr = ip.SrcIP.String()
	} else {
		ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
		if ipv6Layer != nil {
			ipv6, ok := ipv6Layer.(*layers.IPv6)
			if !ok {
				return
			}
			ipaddr = ipv6.SrcIP.String()
			icmpv6NALayer := packet.Layer(layers.LayerTypeICMPv6NeighborAdvertisement)
			icmpv6RALayer := packet.Layer(layers.LayerTypeICMPv6RouterAdvertisement)
			if icmpv6NALayer != nil || icmpv6RALayer != nil {
				updateIPToMAC(ipaddr, macaddr)
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
			updateDNS(dns, ipaddr, macaddr)
			return
		}
	}
	// test
	if eth.EthernetType == 0x8899 {
		return
	}

	log.Println(packet)
}

// EtherType別の集計
func updateEtherType(t uint16) {
	c := 0
	if e, ok := EtherType.Load(t); ok {
		c = e.(int)
	}
	c++
	EtherType.Store(t, c)
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
}

func updateDNS(dns *layers.DNS, ip, mac string) {
	if dns.OpCode != layers.DNSOpCodeQuery {
		return
	}
	for _, q := range dns.Questions {
		k := q.Type.String() + "," + string(q.Name)
		log.Println(k)
		if v, ok := DNSQuery.Load(k); ok {
			if e, ok := v.(*DNSEnt); ok {
				e.Count++
				if mac != e.LastMAC || ip != e.LastIP {
					e.Change++
					e.LastMAC = mac
					e.LastIP = ip
				}
				e.LastTime = time.Now().Unix()
			}
			continue
		}
		now := time.Now().Unix()
		DNSQuery.Store(k, &DNSEnt{
			Type:      q.Type.String(),
			Name:      string(q.Name),
			LastMAC:   mac,
			LastIP:    ip,
			Count:     1,
			FirstTime: now,
			LastTime:  now,
		})
	}
}

// syslogでレポートを送信する
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
				syslogCh <- e.String()
				e.SendTime = now
			}
		}
		return true
	})
	s := "type=EtherType"
	EtherType.Range(func(key, value interface{}) bool {
		if t, ok := key.(uint16); ok {
			if c, ok := value.(int); ok {
				s += fmt.Sprintf(",0x%04x=%d", t, c)
			}
		}
		//レポートしたらクリアする
		EtherType.Delete(key)
		return true
	})
	syslogCh <- s
	// DNSレポート
	DNSQuery.Range(func(k, v interface{}) bool {
		if e, ok := v.(*DNSEnt); ok {
			if e.LastTime < rt {
				DNSQuery.Delete(k)
				return true
			}
			if e.SendTime < st {
				syslogCh <- e.String()
				e.SendTime = now
			}
		}
		return true
	})
}
