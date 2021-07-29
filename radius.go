package main

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/gopacket/layers"
)

type RADIUSFlowEnt struct {
	Client          string
	Server          string
	Count           int64
	AccessRequest   int64
	AccessAccept    int64
	AccessReject    int64
	AccessChallenge int64
	FirstTime       int64
	LastTime        int64
	SendTime        int64
}

func (e *RADIUSFlowEnt) String() string {
	return fmt.Sprintf("type=RADIUS,cl=%s,sv=%s,count=%d,req=%d,accept=%d,reject=%d,challenge=%d,ft=%s,lt=%s",
		e.Client, e.Server, e.Count, e.AccessRequest, e.AccessAccept, e.AccessReject, e.AccessChallenge,
		time.Unix(e.FirstTime, 0).Format(time.RFC3339),
		time.Unix(e.LastTime, 0).Format(time.RFC3339),
	)
}

var RADIUSFlow sync.Map

func updateRADIUS(radius *layers.RADIUS, src, dst string) {
	sv := src
	cl := dst
	req := int64(0)
	accept := int64(0)
	reject := int64(0)
	challenge := int64(0)
	switch radius.Code {
	case layers.RADIUSCodeAccessRequest:
		sv = dst
		cl = src
		req = int64(1)
	case layers.RADIUSCodeAccessAccept:
		accept = int64(1)
	case layers.RADIUSCodeAccessReject:
		reject = int64(1)
	case layers.RADIUSCodeAccountingRequest:
		sv = dst
		cl = src
	case layers.RADIUSCodeAccountingResponse:
	case layers.RADIUSCodeAccessChallenge:
		challenge = int64(1)
	default:
		return
	}
	key := sv + ":" + cl
	if v, ok := RADIUSFlow.Load(key); ok {
		if e, ok := v.(*RADIUSFlowEnt); ok {
			e.Count++
			e.AccessRequest += req
			e.AccessAccept += accept
			e.AccessReject += reject
			e.AccessChallenge += challenge
			e.LastTime = time.Now().Unix()
		}
		return
	}
	now := time.Now().Unix()
	RADIUSFlow.Store(key, &RADIUSFlowEnt{
		Client:          cl,
		Server:          sv,
		Count:           1,
		AccessRequest:   req,
		AccessAccept:    accept,
		AccessReject:    reject,
		AccessChallenge: challenge,
		FirstTime:       now,
		LastTime:        now,
	})
}

// syslogでRADIUSレポートを送信する
func sendRADIUSReport(now, st, rt int64) {
	RADIUSFlow.Range(func(k, v interface{}) bool {
		if e, ok := v.(*RADIUSFlowEnt); ok {
			if e.LastTime < rt {
				RADIUSFlow.Delete(k)
				return true
			}
			if e.SendTime < st {
				radiusCount++
				syslogCh <- e.String()
				e.SendTime = now
			}
		}
		return true
	})
}
