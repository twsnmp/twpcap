package main

import (
	"fmt"
	"sync"
	"time"
)

var EtherType sync.Map
var lastSendEtherType int64

// EtherType別の集計
func updateEtherType(t uint16) {
	c := 0
	if e, ok := EtherType.Load(t); ok {
		c = e.(int)
	}
	c++
	EtherType.Store(t, c)
}

// syslogでEtherTypeのレポートを送信する
func sendEtherTypeReport(st int64) {
	if lastSendEtherType > st {
		return
	}
	s := "type=EtherType"
	et := &mqttEtherTypeDataEnt{
		Time:    time.Now().Format(time.RFC3339),
		TypeMap: make(map[string]int),
	}
	EtherType.Range(func(key, value interface{}) bool {
		if t, ok := key.(uint16); ok {
			if c, ok := value.(int); ok {
				s += fmt.Sprintf(",0x%04x=%d", t, c)
				et.TypeMap[fmt.Sprintf("0x%04x", t)] = c
			}
		}
		//レポートしたらクリアする
		EtherType.Delete(key)
		return true
	})
	etherTypeCount++
	sendSyslog(s)
	publishMQTT(et)
	lastSendEtherType = time.Now().Unix()
}
