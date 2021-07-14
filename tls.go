package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"sync"
	"time"

	"github.com/google/gopacket/layers"
)

type TLSFlowEnt struct {
	Client      string
	Server      string
	Service     string
	MinVersion  uint16
	MaxVersion  uint16
	CipherSuite uint16
	Count       int64
	Handshake   int64
	Alert       int64
	FirstTime   int64
	LastTime    int64
	SendTime    int64
}

func (e *TLSFlowEnt) String() string {
	cs, ok := cipherSuiteMap[e.CipherSuite]
	if !ok {
		cs = "Unknown"
	}
	return fmt.Sprintf("type=TLSFlow,cl=%s,sv=%s,serv=%s,count=%d,handshake=%d,alert=%d,minver=%s,maxver=%s,cipher=%s,ft=%s,lt=%s",
		e.Client, e.Server, e.Service, e.Count, e.Handshake, e.Alert,
		layers.TLSVersion(e.MinVersion).String(), layers.TLSVersion(e.MaxVersion).String(),
		cs,
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

var cipherSuiteMap = make(map[uint16]string)

func updateTLS(tlsp *layers.TLS, src, dst string, sport, dport int) {
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
	if len(tlsp.AppData) > 0 {
		ver := uint16(tlsp.AppData[0].Version)
		if e.MinVersion == 0 || e.MinVersion > ver {
			e.MinVersion = ver
		}
		if e.MaxVersion < ver {
			e.MaxVersion = ver
		}
	}
	if len(tlsp.Alert) > 0 {
		e.Alert++
	}
	if len(tlsp.Handshake) > 0 {
		e.Handshake++
		if src == sv {
			if bytes.Contains(tlsp.Contents, []byte{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04}) {
				e.MaxVersion = 0x0304
			}
			if e.CipherSuite == 0 {
				e.CipherSuite = getCipherSuite(tlsp.Contents)
			}
		}
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

func checkDecodeErrorTLSPacket(src, dst string, sport int, b []byte) {
	serv, ok := serviceMap[sport]
	if !ok {
		serv = "OTEHR"
	}
	key := dst + ":" + src + ":" + serv
	v, ok := TLSFlow.Load(key)
	if !ok {
		return
	}
	if e, ok := v.(*TLSFlowEnt); ok {
		if bytes.Contains(b, []byte{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04}) {
			e.MaxVersion = 0x0304
		}
		if e.CipherSuite == 0 {
			e.CipherSuite = getCipherSuite(b)
		}
	}
}

func getCipherSuite(b []byte) uint16 {
	if len(b) < (5+4+2+32) || b[0] != 0x16 {
		// Not handshake
		return 0x0000
	}
	if b[5] != 0x02 {
		// Not Server Hello
		return 0x0000
	}
	sidlen := int(b[5+4+2+32])
	if sidlen < 0 || len(b) < sidlen+5+4+2+32 {
		// invalid length
		return 0x0000
	}
	pos := sidlen + 5 + 4 + 2 + 32 + 1
	return uint16(b[pos])<<8 + uint16(b[pos+1])
}

func makeCipherSuiteMap() {
	for _, cs := range tls.CipherSuites() {
		cipherSuiteMap[cs.ID] = cs.Name
	}
}

/*
TLS 1.3
0x16, 0x3, 0x3, 0x0, 0x7a,
0x2, 0x0, 0x0, 0x76,
0x3, 0x3,
0xa2, 0xd2, 0x75, 0x9d, 0x1d, 0x25, 0x67, 0xde,
0x92, 0x23, 0x3b, 0xe7, 0xfa, 0xce, 0x25, 0x49,
0x44, 0xd3, 0x63, 0xe2, 0x5e, 0xb8, 0x78, 0xf1,
0xe3, 0xc4, 0x13, 0x8b, 0xb, 0x92, 0x5f, 0xfe,

0x20,
0x92, 0xb, 0x14, 0xf8, 0x81, 0xf9, 0xcc, 0x79,
0x8c, 0xa1, 0x63, 0x85, 0xb1, 0xbf, 0x6d, 0x5,
0xc8, 0x2e, 0xbd, 0x2, 0x6d, 0xcf, 0xfe, 0x59,
0xdb, 0xbc, 0x39, 0x1, 0xc5, 0xf9, 0xc4, 0x6c,

0x13, 0x1,

*/
