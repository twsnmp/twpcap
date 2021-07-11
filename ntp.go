package main

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/gopacket/layers"
)

type NTPServerEnt struct {
	IP          string
	LastClient  string
	Version     uint8
	Stratum     uint8
	ReferenceID uint32
	Count       int64
	Change      int64
	FirstTime   int64
	LastTime    int64
	SendTime    int64
}

func (e *NTPServerEnt) String() string {
	return fmt.Sprintf("type=NTP,ip=%s,count=%d,change=%d,client=%s,version=%d,stratum=%d,refid=0x%0x,ft=%s,lt=%s",
		e.IP, e.Count, e.Change, e.LastClient,
		e.Version, e.Stratum, e.ReferenceID,
		time.Unix(e.FirstTime, 0).Format(time.RFC3339),
		time.Unix(e.LastTime, 0).Format(time.RFC3339),
	)
}

var NTPServer sync.Map

func updateNTP(ntp *layers.NTP, src, dst string) {
	if ntp.Mode != 0x04 {
		return
	}
	if v, ok := NTPServer.Load(src); ok {
		if e, ok := v.(*NTPServerEnt); ok {
			if e.LastClient != dst {
				e.Change++
			}
			e.Count++
			e.LastTime = time.Now().Unix()
		}
		return
	}
	now := time.Now().Unix()
	NTPServer.Store(src, &NTPServerEnt{
		IP:          src,
		LastClient:  dst,
		Count:       1,
		Version:     uint8(ntp.Version),
		Stratum:     uint8(ntp.Stratum),
		ReferenceID: uint32(ntp.ReferenceID),
		FirstTime:   now,
		LastTime:    now,
	})
}

// syslogでレポートを送信する
func sendNTPReport(now, st, rt int64) {
	NTPServer.Range(func(k, v interface{}) bool {
		if e, ok := v.(*NTPServerEnt); ok {
			if e.LastTime < rt {
				NTPServer.Delete(e.IP)
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
