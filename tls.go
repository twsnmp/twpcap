package main

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/gopacket/layers"
)

type TLSFlowEnt struct {
	Client     string
	Server     string
	Service    string
	MinVersion uint16
	MaxVersion uint16
	Count      int64
	Handshake  int64
	Alert      int64
	FirstTime  int64
	LastTime   int64
	SendTime   int64
}

func (e *TLSFlowEnt) String() string {
	return fmt.Sprintf("type=TLSFlow,cl=%s,sv=%s,serv=%s,count=%d,handshake=%d,alert=%d,minver=%s,maxver=%s,ft=%s,lt=%s",
		e.Client, e.Server, e.Service, e.Count, e.Handshake, e.Alert,
		layers.TLSVersion(e.MinVersion).String(), layers.TLSVersion(e.MaxVersion).String(),
		time.Unix(e.FirstTime, 0).Format(time.RFC3339),
		time.Unix(e.LastTime, 0).Format(time.RFC3339),
	)
}

var TLSFlow sync.Map
var serviceMap = map[int]string{
	443:  "HTTPS",
	25:   "SMTP",
	465:  "SMTPS",
	587:  "SMTP",
	110:  "POP3",
	995:  "POP3S",
	143:  "IMAP4",
	993:  "IMAP4S",
	21:   "FTP",
	22:   "FTP-DATA",
	990:  "FTPS",
	991:  "FTPS-DATA",
	339:  "LDAP",
	636:  "LDAPS",
	5001: "UPnPMSv2",
}

func updateTLS(tls *layers.TLS, src, dst string, sport, dport int) {
	sv := src
	cl := dst
	serv, oks := serviceMap[sport]
	servd, okd := serviceMap[dport]
	if oks && okd {
		if sport > dport {
			sv = dst
			cl = src
			serv = servd
		}
	} else if okd {
		sv = dst
		cl = src
		serv = servd
	} else if !oks {
		serv = "OTEHR"
		if sport > dport {
			sv = dst
			cl = src
		}
	}
	key := cl + ":" + sv + ":" + serv
	var e *TLSFlowEnt
	v, ok := TLSFlow.Load(key)
	if !ok {
		now := time.Now().Unix()
		e = &TLSFlowEnt{
			Client:    cl,
			Server:    sv,
			Service:   serv,
			Count:     1,
			FirstTime: now,
			LastTime:  now,
		}
		TLSFlow.Store(key, e)
	} else {
		e, ok = v.(*TLSFlowEnt)
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
	TLSFlow.Range(func(k, v interface{}) bool {
		if e, ok := v.(*TLSFlowEnt); ok {
			if e.LastTime < rt {
				TLSFlow.Delete(k)
				return true
			}
			if e.SendTime < st && e.MinVersion > 0 {
				syslogCh <- e.String()
				e.SendTime = now
			}
		}
		return true
	})
}
