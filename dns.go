package main

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/gopacket/layers"
)

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

var DNSQuery sync.Map

func updateDNS(dns *layers.DNS, ip, mac string) {
	if dns.OpCode != layers.DNSOpCodeQuery {
		return
	}
	for _, q := range dns.Questions {
		k := q.Type.String() + "," + string(q.Name)
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
func sendDNSReport(now, st, rt int64) {
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
