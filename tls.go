package main

import (
	"bytes"
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
		cs = fmt.Sprintf("0x%04x", e.CipherSuite)
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

var cipherSuiteMap = map[uint16]string{
	0x0000: "TLS_NULL_WITH_NULL_NULL",
	0x0001: "TLS_RSA_WITH_NULL_MD5",
	0x0002: "TLS_RSA_WITH_NULL_SHA",
	0x0003: "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
	0x0004: "TLS_RSA_WITH_RC4_128_MD5",
	0x0005: "TLS_RSA_WITH_RC4_128_SHA",
	0x0006: "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
	0x0007: "TLS_RSA_WITH_IDEA_CBC_SHA",
	0x0008: "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
	0x0009: "TLS_RSA_WITH_DES_CBC_SHA",
	0x000a: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	0x000b: "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA",
	0x000c: "TLS_DH_DSS_WITH_DES_CBC_SHA",
	0x000d: "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA",
	0x000e: "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA",
	0x000f: "TLS_DH_RSA_WITH_DES_CBC_SHA",
	0x0010: "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA",
	0x0011: "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
	0x0012: "TLS_DHE_DSS_WITH_DES_CBC_SHA",
	0x0013: "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
	0x0014: "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
	0x0015: "TLS_DHE_RSA_WITH_DES_CBC_SHA",
	0x0016: "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
	0x0017: "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5",
	0x0018: "TLS_DH_anon_WITH_RC4_128_MD5",
	0x0019: "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA",
	0x001a: "TLS_DH_anon_WITH_DES_CBC_SHA",
	0x001b: "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA",
	0x001e: "TLS_KRB5_WITH_DES_CBC_SHA",
	0x001f: "TLS_KRB5_WITH_3DES_EDE_CBC_SHA",
	0x0020: "TLS_KRB5_WITH_RC4_128_SHA",
	0x0021: "TLS_KRB5_WITH_IDEA_CBC_SHA",
	0x0022: "TLS_KRB5_WITH_DES_CBC_MD5",
	0x0023: "TLS_KRB5_WITH_3DES_EDE_CBC_MD5",
	0x0024: "TLS_KRB5_WITH_RC4_128_MD5",
	0x0025: "TLS_KRB5_WITH_IDEA_CBC_MD5",
	0x0026: "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA",
	0x0027: "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA",
	0x0028: "TLS_KRB5_EXPORT_WITH_RC4_40_SHA",
	0x0029: "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5",
	0x002a: "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5",
	0x002b: "TLS_KRB5_EXPORT_WITH_RC4_40_MD5",
	0x002c: "TLS_PSK_WITH_NULL_SHA",
	0x002d: "TLS_DHE_PSK_WITH_NULL_SHA",
	0x002e: "TLS_RSA_PSK_WITH_NULL_SHA",
	0x002f: "TLS_RSA_WITH_AES_128_CBC_SHA",
	0x0030: "TLS_DH_DSS_WITH_AES_128_CBC_SHA",
	0x0031: "TLS_DH_RSA_WITH_AES_128_CBC_SHA",
	0x0032: "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
	0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
	0x0034: "TLS_DH_anon_WITH_AES_128_CBC_SHA",
	0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
	0x0036: "TLS_DH_DSS_WITH_AES_256_CBC_SHA",
	0x0037: "TLS_DH_RSA_WITH_AES_256_CBC_SHA",
	0x0038: "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
	0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
	0x003a: "TLS_DH_anon_WITH_AES_256_CBC_SHA",
	0x003b: "TLS_RSA_WITH_NULL_SHA256",
	0x003c: "TLS_RSA_WITH_AES_128_CBC_SHA256",
	0x003d: "TLS_RSA_WITH_AES_256_CBC_SHA256",
	0x003e: "TLS_DH_DSS_WITH_AES_128_CBC_SHA256",
	0x003f: "TLS_DH_RSA_WITH_AES_128_CBC_SHA256",
	0x0040: "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
	0x0041: "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",
	0x0042: "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA",
	0x0043: "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA",
	0x0044: "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA",
	0x0045: "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA",
	0x0046: "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA",
	0x0067: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
	0x0068: "TLS_DH_DSS_WITH_AES_256_CBC_SHA256",
	0x0069: "TLS_DH_RSA_WITH_AES_256_CBC_SHA256",
	0x006a: "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
	0x006b: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
	0x006c: "TLS_DH_anon_WITH_AES_128_CBC_SHA256",
	0x006d: "TLS_DH_anon_WITH_AES_256_CBC_SHA256",
	0x0084: "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
	0x0085: "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA",
	0x0086: "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA",
	0x0087: "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA",
	0x0088: "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA",
	0x0089: "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA",
	0x008a: "TLS_PSK_WITH_RC4_128_SHA",
	0x008b: "TLS_PSK_WITH_3DES_EDE_CBC_SHA",
	0x008c: "TLS_PSK_WITH_AES_128_CBC_SHA",
	0x008d: "TLS_PSK_WITH_AES_256_CBC_SHA",
	0x008e: "TLS_DHE_PSK_WITH_RC4_128_SHA",
	0x008f: "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA",
	0x0090: "TLS_DHE_PSK_WITH_AES_128_CBC_SHA",
	0x0091: "TLS_DHE_PSK_WITH_AES_256_CBC_SHA",
	0x0092: "TLS_RSA_PSK_WITH_RC4_128_SHA",
	0x0093: "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA",
	0x0094: "TLS_RSA_PSK_WITH_AES_128_CBC_SHA",
	0x0095: "TLS_RSA_PSK_WITH_AES_256_CBC_SHA",
	0x0096: "TLS_RSA_WITH_SEED_CBC_SHA",
	0x0097: "TLS_DH_DSS_WITH_SEED_CBC_SHA",
	0x0098: "TLS_DH_RSA_WITH_SEED_CBC_SHA",
	0x0099: "TLS_DHE_DSS_WITH_SEED_CBC_SHA",
	0x009a: "TLS_DHE_RSA_WITH_SEED_CBC_SHA",
	0x009b: "TLS_DH_anon_WITH_SEED_CBC_SHA",
	0x009c: "TLS_RSA_WITH_AES_128_GCM_SHA256",
	0x009d: "TLS_RSA_WITH_AES_256_GCM_SHA384",
	0x009e: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
	0x009f: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
	0x00a0: "TLS_DH_RSA_WITH_AES_128_GCM_SHA256",
	0x00a1: "TLS_DH_RSA_WITH_AES_256_GCM_SHA384",
	0x00a2: "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
	0x00a3: "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
	0x00a4: "TLS_DH_DSS_WITH_AES_128_GCM_SHA256",
	0x00a5: "TLS_DH_DSS_WITH_AES_256_GCM_SHA384",
	0x00a6: "TLS_DH_anon_WITH_AES_128_GCM_SHA256",
	0x00a7: "TLS_DH_anon_WITH_AES_256_GCM_SHA384",
	0x00a8: "TLS_PSK_WITH_AES_128_GCM_SHA256",
	0x00a9: "TLS_PSK_WITH_AES_256_GCM_SHA384",
	0x00aa: "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256",
	0x00ab: "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384",
	0x00ac: "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256",
	0x00ad: "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384",
	0x00ae: "TLS_PSK_WITH_AES_128_CBC_SHA256",
	0x00af: "TLS_PSK_WITH_AES_256_CBC_SHA384",
	0x00b0: "TLS_PSK_WITH_NULL_SHA256",
	0x00b1: "TLS_PSK_WITH_NULL_SHA384",
	0x00b2: "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256",
	0x00b3: "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384",
	0x00b4: "TLS_DHE_PSK_WITH_NULL_SHA256",
	0x00b5: "TLS_DHE_PSK_WITH_NULL_SHA384",
	0x00b6: "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256",
	0x00b7: "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384",
	0x00b8: "TLS_RSA_PSK_WITH_NULL_SHA256",
	0x00b9: "TLS_RSA_PSK_WITH_NULL_SHA384",
	0x00ba: "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256",
	0x00bb: "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256",
	0x00bc: "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256",
	0x00bd: "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256",
	0x00be: "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
	0x00bf: "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256",
	0x00c0: "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256",
	0x00c1: "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256",
	0x00c2: "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256",
	0x00c3: "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256",
	0x00c4: "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256",
	0x00c5: "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256",
	0x00c6: "TLS_SM4_GCM_SM3",
	0x00c7: "TLS_SM4_CCM_SM3",
	0x00ff: "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
	0x1301: "TLS_AES_128_GCM_SHA256",
	0x1302: "TLS_AES_256_GCM_SHA384",
	0x1303: "TLS_CHACHA20_POLY1305_SHA256",
	0x1304: "TLS_AES_128_CCM_SHA256",
	0x1305: "TLS_AES_128_CCM_8_SHA256",
	0x1306: "TLS_AEGIS_256_SHA512",
	0x1307: "TLS_AEGIS_128L_SHA256",
	0x5600: "TLS_FALLBACK_SCSV",
	0xc001: "TLS_ECDH_ECDSA_WITH_NULL_SHA",
	0xc002: "TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
	0xc003: "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
	0xc004: "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
	0xc005: "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
	0xc006: "TLS_ECDHE_ECDSA_WITH_NULL_SHA",
	0xc007: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
	0xc008: "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
	0xc009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
	0xc00a: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
	0xc00b: "TLS_ECDH_RSA_WITH_NULL_SHA",
	0xc00c: "TLS_ECDH_RSA_WITH_RC4_128_SHA",
	0xc00d: "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
	0xc00e: "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
	0xc00f: "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
	0xc010: "TLS_ECDHE_RSA_WITH_NULL_SHA",
	0xc011: "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
	0xc012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
	0xc013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
	0xc014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
	0xc015: "TLS_ECDH_anon_WITH_NULL_SHA",
	0xc016: "TLS_ECDH_anon_WITH_RC4_128_SHA",
	0xc017: "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA",
	0xc018: "TLS_ECDH_anon_WITH_AES_128_CBC_SHA",
	0xc019: "TLS_ECDH_anon_WITH_AES_256_CBC_SHA",
	0xc01a: "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA",
	0xc01b: "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA",
	0xc01c: "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA",
	0xc01d: "TLS_SRP_SHA_WITH_AES_128_CBC_SHA",
	0xc01e: "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA",
	0xc01f: "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA",
	0xc020: "TLS_SRP_SHA_WITH_AES_256_CBC_SHA",
	0xc021: "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA",
	0xc022: "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA",
	0xc023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
	0xc024: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
	0xc025: "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
	0xc026: "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
	0xc027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
	0xc028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
	0xc029: "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",
	0xc02a: "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",
	0xc02b: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	0xc02c: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	0xc02d: "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
	0xc02e: "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
	0xc02f: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	0xc030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	0xc031: "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
	0xc032: "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",
	0xc033: "TLS_ECDHE_PSK_WITH_RC4_128_SHA",
	0xc034: "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA",
	0xc035: "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA",
	0xc036: "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA",
	0xc037: "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256",
	0xc038: "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384",
	0xc039: "TLS_ECDHE_PSK_WITH_NULL_SHA",
	0xc03a: "TLS_ECDHE_PSK_WITH_NULL_SHA256",
	0xc03b: "TLS_ECDHE_PSK_WITH_NULL_SHA384",
	0xc03c: "TLS_RSA_WITH_ARIA_128_CBC_SHA256",
	0xc03d: "TLS_RSA_WITH_ARIA_256_CBC_SHA384",
	0xc03e: "TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256",
	0xc03f: "TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384",
	0xc040: "TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256",
	0xc041: "TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384",
	0xc042: "TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256",
	0xc043: "TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384",
	0xc044: "TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256",
	0xc045: "TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384",
	0xc046: "TLS_DH_anon_WITH_ARIA_128_CBC_SHA256",
	0xc047: "TLS_DH_anon_WITH_ARIA_256_CBC_SHA384",
	0xc048: "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256",
	0xc049: "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384",
	0xc04a: "TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256",
	0xc04b: "TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384",
	0xc04c: "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256",
	0xc04d: "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384",
	0xc04e: "TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256",
	0xc04f: "TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384",
	0xc050: "TLS_RSA_WITH_ARIA_128_GCM_SHA256",
	0xc051: "TLS_RSA_WITH_ARIA_256_GCM_SHA384",
	0xc052: "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256",
	0xc053: "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384",
	0xc054: "TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256",
	0xc055: "TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384",
	0xc056: "TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256",
	0xc057: "TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384",
	0xc058: "TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256",
	0xc059: "TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384",
	0xc05a: "TLS_DH_anon_WITH_ARIA_128_GCM_SHA256",
	0xc05b: "TLS_DH_anon_WITH_ARIA_256_GCM_SHA384",
	0xc05c: "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256",
	0xc05d: "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384",
	0xc05e: "TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256",
	0xc05f: "TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384",
	0xc060: "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256",
	0xc061: "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384",
	0xc062: "TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256",
	0xc063: "TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384",
	0xc064: "TLS_PSK_WITH_ARIA_128_CBC_SHA256",
	0xc065: "TLS_PSK_WITH_ARIA_256_CBC_SHA384",
	0xc066: "TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256",
	0xc067: "TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384",
	0xc068: "TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256",
	0xc069: "TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384",
	0xc06a: "TLS_PSK_WITH_ARIA_128_GCM_SHA256",
	0xc06b: "TLS_PSK_WITH_ARIA_256_GCM_SHA384",
	0xc06c: "TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256",
	0xc06d: "TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384",
	0xc06e: "TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256",
	0xc06f: "TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384",
	0xc070: "TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256",
	0xc071: "TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384",
	0xc072: "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
	0xc073: "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
	0xc074: "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
	0xc075: "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
	0xc076: "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
	0xc077: "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384",
	0xc078: "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256",
	0xc079: "TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384",
	0xc07a: "TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256",
	0xc07b: "TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384",
	0xc07c: "TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256",
	0xc07d: "TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384",
	0xc07e: "TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256",
	0xc07f: "TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384",
	0xc080: "TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256",
	0xc081: "TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384",
	0xc082: "TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256",
	0xc083: "TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384",
	0xc084: "TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256",
	0xc085: "TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384",
	0xc086: "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256",
	0xc087: "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384",
	0xc088: "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256",
	0xc089: "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384",
	0xc08a: "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256",
	0xc08b: "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384",
	0xc08c: "TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256",
	0xc08d: "TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384",
	0xc08e: "TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256",
	0xc08f: "TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384",
	0xc090: "TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256",
	0xc091: "TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384",
	0xc092: "TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256",
	0xc093: "TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384",
	0xc094: "TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256",
	0xc095: "TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384",
	0xc096: "TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256",
	0xc097: "TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384",
	0xc098: "TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256",
	0xc099: "TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384",
	0xc09a: "TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256",
	0xc09b: "TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384",
	0xc09c: "TLS_RSA_WITH_AES_128_CCM",
	0xc09d: "TLS_RSA_WITH_AES_256_CCM",
	0xc09e: "TLS_DHE_RSA_WITH_AES_128_CCM",
	0xc09f: "TLS_DHE_RSA_WITH_AES_256_CCM",
	0xc0a0: "TLS_RSA_WITH_AES_128_CCM_8",
	0xc0a1: "TLS_RSA_WITH_AES_256_CCM_8",
	0xc0a2: "TLS_DHE_RSA_WITH_AES_128_CCM_8",
	0xc0a3: "TLS_DHE_RSA_WITH_AES_256_CCM_8",
	0xc0a4: "TLS_PSK_WITH_AES_128_CCM",
	0xc0a5: "TLS_PSK_WITH_AES_256_CCM",
	0xc0a6: "TLS_DHE_PSK_WITH_AES_128_CCM",
	0xc0a7: "TLS_DHE_PSK_WITH_AES_256_CCM",
	0xc0a8: "TLS_PSK_WITH_AES_128_CCM_8",
	0xc0a9: "TLS_PSK_WITH_AES_256_CCM_8",
	0xc0aa: "TLS_PSK_DHE_WITH_AES_128_CCM_8",
	0xc0ab: "TLS_PSK_DHE_WITH_AES_256_CCM_8",
	0xc0ac: "TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
	0xc0ad: "TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
	0xc0ae: "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8",
	0xc0af: "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8",
	0xc0b0: "TLS_ECCPWD_WITH_AES_128_GCM_SHA256",
	0xc0b1: "TLS_ECCPWD_WITH_AES_256_GCM_SHA384",
	0xc0b2: "TLS_ECCPWD_WITH_AES_128_CCM_SHA256",
	0xc0b3: "TLS_ECCPWD_WITH_AES_256_CCM_SHA384",
	0xc0b4: "TLS_SHA256_SHA256",
	0xc0b5: "TLS_SHA384_SHA384",
	0xc100: "TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC",
	0xc101: "TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC",
	0xc102: "TLS_GOSTR341112_256_WITH_28147_CNT_IMIT",
	0xc103: "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L",
	0xc104: "TLS_GOSTR341112_256_WITH_MAGMA_MGM_L",
	0xc105: "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S",
	0xc106: "TLS_GOSTR341112_256_WITH_MAGMA_MGM_S",
	0xcca8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	0xcca9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
	0xccaa: "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	0xccab: "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256",
	0xccac: "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
	0xccad: "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
	0xccae: "TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256",
	0xd001: "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256",
	0xd002: "TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384",
	0xd003: "TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256",
	0xd005: "TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256",
	// Not found
	0xffff: "Unknown",
}

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
			Client:      cl,
			Server:      sv,
			Service:     serv,
			Count:       1,
			CipherSuite: 0xffff,
			FirstTime:   now,
			LastTime:    now,
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
			if e.CipherSuite == 0xffff {
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
				tlsCount++
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
		if e.CipherSuite == 0xffff {
			e.CipherSuite = getCipherSuite(b)
		}
	}
}

func getCipherSuite(b []byte) uint16 {
	if len(b) < (5+4+2+32+2) || b[0] != 0x16 {
		// Not handshake
		return 0xffff
	}
	if b[5] != 0x02 {
		// Not Server Hello
		return 0xffff
	}
	sidlen := int(b[5+4+2+32])
	pos := sidlen + 5 + 4 + 2 + 32 + 1
	if sidlen < 0 || pos+1 >= len(b) {
		// invalid length
		return 0xffff
	}
	return uint16(b[pos])<<8 + uint16(b[pos+1])
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
