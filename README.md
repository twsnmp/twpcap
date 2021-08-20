# twpcap
Network sensor by packet capture fo TWSNMP
TWSNMPのためのパケットキャプチャーによるネットワークセンサー

[![Godoc Reference](https://godoc.org/github.com/twsnmp/twpcap?status.svg)](http://godoc.org/github.com/twsnmp/twpcap)
[![Go Report Card](https://goreportcard.com/badge/twsnmp/twpcap)](https://goreportcard.com/report/twsnmp/twpcap)

## Overview

パケットキャプチャーからTWSNMPで監視するために必要な情報をsyslogで送信するためのセンサープログラムです。
現在のバージョンでは以下の情報を取得できます。

- モニタしたパケット数の統計情報
- ネットワーク上のEthernetパケットの種類別集計
- IPアドレスとMACアドレスの関係(ARP,IPv4,IPv6)
- DHCPサーバーとクライアントの情報
- DNSサーバーとクライアントの問い合わせ情報
- NTPサーバーの情報
- RADUISサーバーとクライアントの情報
- サーバーとクライアントのTLS通信の情報（TLSバージョン、暗号方式）

## Status

v1.0.0をリリースしました。(2021/7/16)
（基本的な機能の動作する状態）
v1.1.0をリリースしました。(2021/7/26)
（バグフィック版）
v1.2.0をリリースしました。(2021/8/9)
(バグフィックス、リソースモニタ追加)
v1.2.1をリリースしました。(2021/8/21)
(バグフィックス、モニタ機能に識別情報追加)

## Build

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

```
$make
```
を実行すれば、MacOS,Windows,Linux(amd64),Linux(arm)用の実行ファイルが、`dist`のディレクトリに作成されます。

Dockerイメージを作成するためには、
```
$make docker
```
を実行します。twssnmp/twpcapというDockerイメージが作成されます。

配布用のZIPファイルを作成するためには、
```
$make zip
```
を実行します。ZIPファイルが`dist/`ディレクトリに作成されます。

## Run

### 使用方法

```
Usage of ./twpcap.app:
  -cpuprofile file
    	write cpu profile to file
  -iface string
    	monitor interface
  -interval int
    	syslog send interval(sec) (default 600)
  -list
    	list interface
  -memprofile file
    	write memory profile to file
  -retention int
    	data retention time(sec) (default 3600)
  -syslog string
    	syslog destnation list
```

syslogの送信先はカンマ区切りで複数指定できます。:の続けてポート番号を
指定することもできます。

```
-syslog 192.168.1.1,192.168.1.2:5514
```

### パケットキャプチャーするLAN I/Fのリスト

Mac OS,Windows,Linuxの環境では以下のコマンドで表示できます。（例はLinux場合）

```
#./twpcap -list
2021-07-16T06:21:18.442 version=v1.0.0(278ed5f)
Interface found:

Name:  en0
Description:
addresses:
- IP address:  fe80::4c8:cc67:d4a6:4df0
- Subnet mask:  ffffffffffffffff0000000000000000
- IP address:  240d:2:6306:6700:ec:8a7b:5c14:5e3e
- Subnet mask:  ffffffffffffffff0000000000000000
- IP address:  240d:2:6306:6700:1089:ad12:387c:d110
- Subnet mask:  ffffffffffffffff0000000000000000
- IP address:  192.168.1.250
- Subnet mask:  ffffff00

```

Docker環境では以下のコマンドを実行すれば表示できます。

```
#docker run --rm -d  --name twpcap  --net host twsnmp/twpcap  -list
```

### 起動方法

起動するためには、モニタするLAN I/F(-iface)とsyslogの送信先(-syslog)が必要です。

Mac OS,Windows,Linuxの環境では以下のコマンドで起動できます。（例はLinux場合）

```
#./twpcap -iface eth3 -syslog 192.168.1.1
```

Docker環境では以下のコマンドを実行すれば起動できます。

```
#docker run --rm -d  --name twpcap  --net host twsnmp/twpcap  -iface eth3 -syslog 192.168.1.1
```

## Copyright

see ./LICENSE

```
Copyright 2021 Masayuki Yamai
```
