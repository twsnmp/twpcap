package main

import (
	"fmt"
	"log"
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
		k := dst + "," + getDNSTypeName(q.Type) + "," + string(q.Name)
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
			Type:       getDNSTypeName(q.Type),
			Name:       string(q.Name),
			Server:     dst,
			LastMAC:    mac,
			LastClient: src,
			Count:      1,
			FirstTime:  now,
			LastTime:   now,
		})
	}
}

func getDNSTypeName(dt layers.DNSType) string {
	switch dt {
	default:
		log.Printf("Unknown dt=%d", dt)
		return "Unknown"
	case layers.DNSTypeA:
		return "A"
	case layers.DNSTypeNS:
		return "NS"
	case layers.DNSTypeMD:
		return "MD"
	case layers.DNSTypeMF:
		return "MF"
	case layers.DNSTypeCNAME:
		return "CNAME"
	case layers.DNSTypeSOA:
		return "SOA"
	case layers.DNSTypeMB:
		return "MB"
	case layers.DNSTypeMG:
		return "MG"
	case layers.DNSTypeMR:
		return "MR"
	case layers.DNSTypeNULL:
		return "NULL"
	case layers.DNSTypeWKS:
		return "WKS"
	case layers.DNSTypePTR:
		return "PTR"
	case layers.DNSTypeHINFO:
		return "HINFO"
	case layers.DNSTypeMINFO:
		return "MINFO"
	case layers.DNSTypeMX:
		return "MX"
	case layers.DNSTypeTXT: //
		return "TXT"
	case layers.DNSTypeAAAA:
		return "AAAA"
	case layers.DNSTypeSRV:
		return "SRV"
	case layers.DNSTypeOPT:
		return "OPT"
	case layers.DNSTypeURI:
		return "URI"
	//	Add
	case 17:
		return "RP"
	case 18:
		return "AFSDB"
	case 19:
		return "X25"
	case 20:
		return "ISDN"
	case 21:
		return "RT"
	case 22:
		return "NSAP"
	case 23:
		return "NSAP-PTR"
	case 24:
		return "SIG"
	case 25:
		return "KEY"
	case 26:
		return "PX"
	case 27:
		return "GPOS"
	case 29:
		return "LOC"
	case 30:
		return "NXT"
	case 31:
		return "EID"
	case 32:
		return "NIMLOC"
	case 34:
		return "ATMA"
	case 35:
		return "NAPTR"
	case 36:
		return "KX"
	case 37:
		return "CERT"
	case 38:
		return "A6"
	case 39:
		return "DNAME"
	case 40:
		return "SINK"
	case 42:
		return "APL"
	case 43:
		return "DS"
	case 44:
		return "SSHFP"
	case 45:
		return "IPSECKEY"
	case 46:
		return "RRSIG"
	case 47:
		return "NSEC"
	case 48:
		return "DNSKEY"
	case 49:
		return "DHCID"
	case 50:
		return "NSEC3"
	case 51:
		return "NSEC3PARAM"
	case 52:
		return "TLSA"
	case 53:
		return "SMIMEA"
	case 55:
		return "HIP"
	case 56:
		return "NINFO"
	case 57:
		return "RKEY"
	case 58:
		return "TALINK"
	case 59:
		return "CDS"
	case 60:
		return "CDNSKEY"
	case 61:
		return "OPENPGPKEY"
	case 62:
		return "CSYNC"
	case 63:
		return "ZONEMD"
	case 64:
		return "SVCB"
	case 65:
		return "HTTPS"
	case 66:
		return "DSYNC"
	case 99:
		return "SPF"
	case 100:
		return "UINFO"
	case 101:
		return "UID"
	case 102:
		return "GID"
	case 103:
		return "UNSPEC"
	case 104:
		return "NID"
	case 105:
		return "L32"
	case 106:
		return "L64"
	case 107:
		return "LP"
	case 108:
		return "EUI48"
	case 109:
		return "EUI64"
	case 249:
		return "TKEY"
	case 250:
		return "TSIG"
	case 251:
		return "IXFR"
	case 252:
		return "AXFR"
	case 253:
		return "MAILB"
	case 254:
		return "MAILA"
	case 255:
		return "*"
	case 257:
		return "CAA"
	case 258:
		return "AVC"
	case 259:
		return "DOA"
	case 260:
		return "AMTRELAY"
	case 261:
		return "RESINFO"
	case 262:
		return "WALLET"
	case 263:
		return "CLA"
	case 264:
		return "IPN"
	case 32768:
		return "TA"
	case 32769:
		return "DLV"
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
