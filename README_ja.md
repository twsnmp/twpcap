# twpcap
TWSNMP FCのためのパケットキャプチャーによるネットワークセンサー

[![Godoc Reference](https://godoc.org/github.com/twsnmp/twpcap?status.svg)](http://godoc.org/github.com/twsnmp/twpcap)
[![Go Report Card](https://goreportcard.com/badge/twsnmp/twpcap)](https://goreportcard.com/report/twsnmp/twpcap)

![](./images/twsla.png)

## 概要

パケットキャプチャーからTWSNMP FCで監視するために必要な情報をsyslogまたはMQTTで送信するためのセンサープログラムです。  
現在のバージョンでは以下の情報を取得できます。

- モニタしたパケット数の統計情報
- ネットワーク上のEthernetパケットの種類別集計
- IPアドレスとMACアドレスの関係(ARP,IPv4,IPv6)
- DHCPサーバーとクライアントの情報
- DNSサーバーとクライアントの問い合わせ情報
- NTPサーバーの情報
- RADIUSサーバーとクライアントの情報
- サーバーとクライアントのTLS通信の情報（TLSバージョン、暗号方式）
- リソースモニタ（CPU、メモリ、負荷、通信速度）

## 状態

v1.0.0をリリースしました。(2021/7/16)  
v1.1.0をリリースしました。(2021/7/26)  
v1.2.0をリリースしました。(2021/8/9)  
v1.2.1をリリースしました。(2021/8/21)  
v2.0.0をリリースしました。(MQTT対応、環境変数対応)

## ビルド

ビルドはmakeで行います。
```
$make
```
以下のターゲットが指定できます。
```
  all        全実行ファイルのビルド（省略可能）
  mac        Mac用の実行ファイルのビルド
  docker     Docker Imageのビルド
  clean      ビルドした実行ファイルの削除
  zip        リリース用のZIPファイルを作成
```

実行すれば、MacOS, Windows, Linux(amd64), Linux(arm)用の実行ファイルが、`dist`のディレクトリに作成されます。

Dockerイメージを作成するためには、
```
$make docker
```
を実行します。twsnmp/twpcapというDockerイメージが作成されます。

## 実行

### 使用方法

```
Usage of ./twpcap:
  -debug
    	debug mode
  -iface string
    	monitor interface
  -interval int
    	syslog send interval(sec) (default 600)
  -list
    	list interface
  -mqtt string
    	mqtt destination list
  -mqttclient string
    	mqtt client id (default "twpcap")
  -mqttpassword string
    	mqtt password
  -mqtttopic string
    	mqtt base topic (default "twpcap")
  -mqttuser string
    	mqtt user name
  -retention int
    	data retention time(sec) (default 3600)
  -syslog string
    	syslog destnation list
```

### 送信先の設定

#### Syslog
syslogの送信先はカンマ区切りで複数指定できます。ポート番号を指定することもできます。
```
-syslog 192.168.1.1,192.168.1.2:5514
```

#### MQTT
MQTTブローカーの送信先を指定します。ユーザー名やパスワードが必要な場合はそれぞれのオプションを使用してください。
```
-mqtt 192.168.1.100:1883 -mqttuser user -mqttpassword pass
```
MQTTのトピックは `-mqtttopic` で指定したベーストピックの下にプロトコル名が付与されます（例: `twpcap/DNS`, `twpcap/TLS` など）。

### パケットキャプチャーするLAN I/Fのリスト

以下のコマンドで表示できます。
```
# ./twpcap -list
```

### 起動方法

モニタするLAN I/F(-iface)と、送信先(-syslog または -mqtt)が必要です。

```
# ./twpcap -iface eth0 -syslog 192.168.1.1
```

環境変数を使用して設定することも可能です。
例: `TWPCAP_IFACE=eth0`, `TWPCAP_SYSLOG=192.168.1.1`

## TWSNMP FCのパッケージ

TWSNMP FCのパッケージにtwpcapが含まれています。  
詳しくは、[noteの記事](https://note.com/twsnmp/n/nc6e49c284afb)を見てください。

## 著作権

[LICENSE](./LICENSE) を参照してください。

```
Copyright 2021-2026 Masayuki Yamai
```
