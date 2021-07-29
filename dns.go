package main

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/gopacket/layers"
)

type DNSEnt struct {
	Type       string
	Name       string
	Count      int64
	Change     int64
	Server     string
	LastClient string
	LastMAC    string
	FirstTime  int64
	LastTime   int64
	SendTime   int64
}

func (e *DNSEnt) String() string {
	return fmt.Sprintf("type=DNS,sv=%s,DNSType=%s,Name=%s,count=%d,change=%d,lcl=%s,lMAC=%s,ft=%s,lt=%s",
		e.Server,
		e.Type, e.Name, e.Count, e.Change,
		e.LastClient,
		e.LastMAC,
		time.Unix(e.FirstTime, 0).Format(time.RFC3339),
		time.Unix(e.LastTime, 0).Format(time.RFC3339),
	)
}

var DNSQuery sync.Map

func updateDNS(dns *layers.DNS, src, dst, mac string) {
	if dns.OpCode != layers.DNSOpCodeQuery || dns.QR {
		// 問い合わせ以外は対象としない
		return
	}
	for _, q := range dns.Questions {
		k := dst + "," + q.Type.String() + "," + string(q.Name)
		if v, ok := DNSQuery.Load(k); ok {
			if e, ok := v.(*DNSEnt); ok {
				e.Count++
				if mac != e.LastMAC || src != e.LastClient {
					e.Change++
					e.LastMAC = mac
					e.LastClient = src
				}
				e.LastTime = time.Now().Unix()
			}
			continue
		}
		now := time.Now().Unix()
		DNSQuery.Store(k, &DNSEnt{
			Type:       q.Type.String(),
			Name:       string(q.Name),
			Server:     dst,
			LastMAC:    mac,
			LastClient: src,
			Count:      1,
			FirstTime:  now,
			LastTime:   now,
			SendTime:   now, //初回を遅延する
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
				dnsCount++
				syslogCh <- e.String()
				e.SendTime = now
			}
		}
		return true
	})
}
