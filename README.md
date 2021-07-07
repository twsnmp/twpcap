# twpcap
Network sensor by packet capture fo TWSNMP
TWSNMPのためのパケットキャプチャーによるネットワークセンサー

[![Godoc Reference](https://godoc.org/github.com/twsnmp/twpcap?status.svg)](http://godoc.org/github.com/twsnmp/twpcap)
[![Go Report Card](https://goreportcard.com/badge/twsnmp/twpcap)](https://goreportcard.com/report/twsnmp/twpcap)

## Overview

パケットキャプチャーからTWSNMPで監視するために必要な情報をsyslogで送信するためのセンサープログラムです。
以下の情報を取得できるようにする予定です。

- IPアドレスとMACアドレスの関係(ARP,IPv4,IPv6)
- DHCPサーバーとクライアント
- DNSサーバーとDNSクライアント
- DNSの問い合わせ内容
- TLSサーバーとクライアントの通信（TLSバージョンなど）
- TLSサーバーの証明書の情報（期限、発行元など）

## Status

開発を始めたばかりです。

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

Mac OS,Windows,Linuxの環境では以下のコマンドで起動できます。
```
#./twpcap <syslog送信先1> <syslog送信先2>
```

Docker環境では以下のコマンドを実行すれば起動できます。
```
#docker run --rm -d  --name twpcap  --net host twsnmp/twpcap  <syslog送信先1> <syslog送信先2>
```

## Copyright

see ./LICENSE

```
Copyright 2021 Masayuki Yamai
```
