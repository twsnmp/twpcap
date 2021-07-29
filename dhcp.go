package main

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket/layers"
)

type DHCPServerEnt struct {
	Server    string
	Count     int64
	Offer     int64
	Ack       int64
	Nak       int64
	FirstTime int64
	LastTime  int64
	SendTime  int64
}

func (e *DHCPServerEnt) String() string {
	return fmt.Sprintf("type=DHCP,sv=%s,count=%d,offer=%d,ack=%d,nak=%d,ft=%s,lt=%s",
		e.Server, e.Count, e.Offer, e.Ack, e.Nak,
		time.Unix(e.FirstTime, 0).Format(time.RFC3339),
		time.Unix(e.LastTime, 0).Format(time.RFC3339),
	)
}

var DHCPServer sync.Map

func updateDHCP(dhcp *layers.DHCPv4, src string) {
	if dhcp.Operation != layers.DHCPOpReply {
		return
	}
	var mt layers.DHCPMsgType
	for _, opt := range dhcp.Options {
		if opt.Type == layers.DHCPOptMessageType {
			mt = layers.DHCPMsgType(opt.Data[0])
			break
		}
	}
	offer := 0
	ack := 0
	nak := 0
	switch mt {
	case layers.DHCPMsgTypeAck:
		ack = 1
		updateIPToMAC(dhcp.YourClientIP.String(), net.HardwareAddr(dhcp.ClientHWAddr).String(), 1)
	case layers.DHCPMsgTypeNak:
		nak = 1
	case layers.DHCPMsgTypeOffer:
		offer = 1
	default:
		return
	}
	if v, ok := DHCPServer.Load(src); ok {
		if e, ok := v.(*DHCPServerEnt); ok {
			e.Count++
			e.Ack += int64(ack)
			e.Nak += int64(nak)
			e.Offer += int64(offer)
			e.LastTime = time.Now().Unix()
		}
		return
	}
	now := time.Now().Unix()
	DHCPServer.Store(src, &DHCPServerEnt{
		Server:    src,
		Count:     1,
		Offer:     int64(offer),
		Ack:       int64(ack),
		Nak:       int64(nak),
		FirstTime: now,
		LastTime:  now,
	})

}

// syslogでDHCP Serverレポートを送信する
func sendDHCPReport(now, st, rt int64) {
	DHCPServer.Range(func(k, v interface{}) bool {
		if e, ok := v.(*DHCPServerEnt); ok {
			if e.LastTime < rt {
				DHCPServer.Delete(e.Server)
				return true
			}
			if e.SendTime < st {
				dhcpCount++
				syslogCh <- e.String()
				e.SendTime = now
			}
		}
		return true
	})
}
