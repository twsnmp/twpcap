package main

import (
	"context"
	"fmt"
	"log"
	"log/syslog"
	"strings"
)

var syslogCh chan string

func startSyslog(ctx context.Context) {
	syslogCh = make(chan string, 2000)
	dstList := strings.Split(syslogDst, ",")
	dst := []*syslog.Writer{}
	for _, d := range dstList {
		if !strings.Contains(d, ":") {
			d += ":514"
		}
		s, err := syslog.Dial("udp", d, syslog.LOG_INFO|syslog.LOG_LOCAL5, "twpcap")
		if err != nil {
			log.Fatal(err)
		}
		syslogCh <- fmt.Sprintf("start send syslog to %s", d)
		dst = append(dst, s)
	}
	defer func() {
		for _, d := range dst {
			d.Close()
		}
	}()
	for {
		select {
		case <-ctx.Done():
			log.Println("stop syslog")
			return
		case msg := <-syslogCh:
			for _, d := range dst {
				d.Info(msg)
			}
		}
	}
}
