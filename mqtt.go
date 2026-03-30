package main

import (
	"context"
	"encoding/json"
	"log"
	"strings"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

var mqttCh = make(chan interface{}, 2000)

type mqttDHCPDataEnt struct {
	Time      string `json:"time"`
	Server    string `json:"server"`
	Count     int    `json:"count"`
	Offer     int64  `json:"offer"`
	Ack       int64  `json:"ack"`
	Nak       int64  `json:"nak"`
	FirstTime string `json:"first_time"`
	LastTime  string `json:"last_time"`
}

type mqttDNSDataEnt struct {
	Time       string `json:"time"`
	Type       string `json:"type"`
	Name       string `json:"name"`
	Count      int    `json:"count"`
	Change     int64  `json:"change"`
	Server     string `json:"server"`
	LastClient string `json:"last_client"`
	LastMAC    string `json:"last_mac"`
	FirstTime  string `json:"first_time"`
	LastTime   string `json:"last_time"`
}

type mqttEtherTypeDataEnt struct {
	Time    string         `json:"time"`
	TypeMap map[string]int `json:"type_map"`
}

type mqttIPToMACDataEnt struct {
	Time      string `json:"time"`
	IP        string `json:"ip"`
	MAC       string `json:"mac"`
	Count     int64  `json:"count"`
	Change    int64  `json:"change"`
	DHCP      int64  `json:"dhcp"`
	FirstTime string `json:"first_time"`
	LastTime  string `json:"last_time"`
}

type mqttNTPDataEnt struct {
	Time        string `json:"time"`
	Server      string `json:"server"`
	LastClient  string `json:"last_client"`
	Version     uint8  `json:"version"`
	Stratum     uint8  `json:"stratum"`
	ReferenceID uint32 `json:"reference_id"`
	Count       int64  `json:"count"`
	Change      int64  `json:"change"`
	FirstTime   string `json:"first_time"`
	LastTime    string `json:"last_time"`
}

type mqttRadiusDataEnt struct {
	Time            string `json:"time"`
	Client          string `json:"client"`
	Server          string `json:"server"`
	Count           int64  `json:"count"`
	AccessRequest   int64  `json:"access_request"`
	AccessAccept    int64  `json:"access_accept"`
	AccessReject    int64  `json:"access_reject"`
	AccessChallenge int64  `json:"access_challenge"`
	FirstTime       string `json:"first_time"`
	LastTime        string `json:"last_time"`
}

type mqttTLSDataEnt struct {
	Time        string `json:"time"`
	Client      string `json:"client"`
	Server      string `json:"server"`
	Service     string `json:"service"`
	MinVersion  uint16 `json:"min_version"`
	MaxVersion  uint16 `json:"max_version"`
	CipherSuite uint16 `json:"cipher_suite"`
	Count       int64  `json:"count"`
	Handshake   int64  `json:"handshake"`
	Alert       int64  `json:"alert"`
	FirstTime   string `json:"first_time"`
	LastTime    string `json:"last_time"`
}

type mqttPcapStatsDataEnt struct {
	Time      string  `json:"time"`
	Total     int     `json:"total"`
	Count     int     `json:"count"`
	PS        float64 `json:"ps"`
	Interface string  `json:"interface"`
}

type mqttMonitorDataEnt struct {
	Time    string  `json:"time"`
	CPU     float64 `json:"cpu"`
	Memory  float64 `json:"memory"`
	Load    float64 `json:"load"`
	Sent    uint64  `json:"sent"`
	Recv    uint64  `json:"recv"`
	TxSpeed float64 `json:"tx_speed"`
	RxSpeed float64 `json:"rx_speed"`
	Process int     `json:"process"`
}

func startMQTT(ctx context.Context) {
	if mqttDst == "" {
		return
	}
	broker := mqttDst
	if !strings.Contains(broker, "://") {
		broker = "tcp://" + broker
	}
	if strings.LastIndex(broker, ":") <= 5 {
		broker += ":1883"
	}
	log.Printf("start mqtt broker=%s", broker)
	opts := mqtt.NewClientOptions()
	opts.AddBroker(broker)
	if mqttUser != "" && mqttPassword != "" {
		opts.SetUsername(mqttUser)
		opts.SetPassword(mqttPassword)
	}
	opts.SetClientID(mqttClientID)
	opts.SetAutoReconnect(true)
	opts.OnConnect = connectHandler
	opts.OnConnectionLost = connectLostHandler
	client := mqtt.NewClient(opts)
	for {
		if token := client.Connect(); token.Wait() && token.Error() == nil {
			break
		} else {
			log.Printf("mqtt connect error: %v, retrying...", token.Error())
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second * 10):
		}
	}
	defer client.Disconnect(250)
	for {
		select {
		case <-ctx.Done():
			log.Println("stop mqtt")
			return
		case msg := <-mqttCh:
			if s := makeMqttData(msg); s != "" {
				if debug {
					log.Println(s)
				}
				client.Publish(getMqttTopic(msg), 1, false, s).Wait()
			}
		}
	}
}

func getMqttTopic(msg interface{}) string {
	r := mqttTopic
	switch msg.(type) {
	case *mqttDHCPDataEnt:
		r += "/DHCP"
	case *mqttDNSDataEnt:
		r += "/DNS"
	case *mqttEtherTypeDataEnt:
		r += "/EtherType"
	case *mqttIPToMACDataEnt:
		r += "/IPToMAC"
	case *mqttNTPDataEnt:
		r += "/NTP"
	case *mqttRadiusDataEnt:
		r += "/Radius"
	case *mqttTLSDataEnt:
		r += "/TLS"
	case *mqttPcapStatsDataEnt:
		r += "/Stats"
	case *mqttMonitorDataEnt:
		r += "/Monitor"
	default:
		return ""
	}
	return r
}

func makeMqttData(msg interface{}) string {
	j, err := json.Marshal(msg)
	if err != nil {
		log.Printf("mqtt marshal error: %v", err)
		return ""
	}
	return string(j)
}

func publishMQTT(msg interface{}) {
	if mqttDst == "" {
		return
	}
	select {
	case mqttCh <- msg:
	default:
		if debug {
			log.Println("mqtt channel full, skipping message")
		}
	}
}

var connectHandler mqtt.OnConnectHandler = func(client mqtt.Client) {
	log.Println("Connected to MQTT broker")
}

var connectLostHandler mqtt.ConnectionLostHandler = func(client mqtt.Client, err error) {
	log.Printf("Connection to MQTT broker lost: %v", err)
}
