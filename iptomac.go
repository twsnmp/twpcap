package main

import (
	"fmt"
	"sync"
	"time"
)

type IPToMACEnt struct {
	IP        string
	MAC       string
	Count     int64
	Change    int64
	DHCP      int64
	FirstTime int64
	LastTime  int64
	SendTime  int64
}

func (e *IPToMACEnt) String() string {
	return fmt.Sprintf("type=IPToMAC,ip=%s,mac=%s,count=%d,change=%d,dchp=%d,ft=%s,lt=%s",
		e.IP, e.MAC, e.Count, e.Change, e.DHCP,
		time.Unix(e.FirstTime, 0).Format(time.RFC3339),
		time.Unix(e.LastTime, 0).Format(time.RFC3339),
	)
}

var IPToMAC sync.Map

func updateIPToMAC(ip, mac string, dhcp int64) {
	if v, ok := IPToMAC.Load(ip); ok {
		if e, ok := v.(*IPToMACEnt); ok {
			if e.MAC != mac {
				e.Change++
			}
			e.DHCP += dhcp
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
		DHCP:      dhcp,
		FirstTime: now,
		LastTime:  now,
	})
}

// syslogでレポートを送信する
func sendIPToMACReport(now, st, rt int64) {
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
}
