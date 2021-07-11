package main

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/gopacket/layers"
)

type TLSEndPointEnt struct {
	IP         string
	MinVersion uint16
	MaxVersion uint16
	Count      int64
	Handshake  int64
	Alert      int64
	FirstTime  int64
	LastTime   int64
	SendTime   int64
}

func (e *TLSEndPointEnt) String() string {
	return fmt.Sprintf("type=TLS,ip=%s,count=%d,handshake=%d,alert=%d,minver=%s,maxver=%s,ft=%s,lt=%s",
		e.IP, e.Count, e.Handshake, e.Alert,
		layers.TLSVersion(e.MinVersion).String(), layers.TLSVersion(e.MaxVersion).String(),
		time.Unix(e.FirstTime, 0).Format(time.RFC3339),
		time.Unix(e.LastTime, 0).Format(time.RFC3339),
	)
}

var TLSEndPoint sync.Map

func updateTLS(tls *layers.TLS, ip string) {
	var e *TLSEndPointEnt
	v, ok := TLSEndPoint.Load(ip)
	if !ok {
		now := time.Now().Unix()
		e = &TLSEndPointEnt{
			IP:        ip,
			Count:     1,
			FirstTime: now,
			LastTime:  now,
		}
		TLSEndPoint.Store(ip, e)
	} else {
		e, ok = v.(*TLSEndPointEnt)
		if !ok {
			return
		}
		e.Count++
	}
	if len(tls.AppData) > 0 {
		ver := uint16(tls.AppData[0].Version)
		if e.MinVersion == 0 || e.MinVersion > ver {
			e.MinVersion = ver
		}
		if e.MaxVersion < ver {
			e.MaxVersion = ver
		}
	}
	if len(tls.Alert) > 0 {
		e.Alert++
	}
	if len(tls.Handshake) > 0 {
		e.Handshake++
	}
}

// syslogでTLSのレポートを送信する
func sendTLSReport(now, st, rt int64) {
	TLSEndPoint.Range(func(k, v interface{}) bool {
		if e, ok := v.(*TLSEndPointEnt); ok {
			if e.LastTime < rt {
				TLSEndPoint.Delete(e.IP)
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
