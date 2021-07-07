#!/bin/sh
apt update
apt install -y wget
apt-get install -y flex bison byacc
apt install -y g++-arm-linux-gnueabihf
cd /tmp
wget http://www.tcpdump.org/release/libpcap-1.10.1.tar.gz
tar xzf libpcap-1.10.1.tar.gz
cd libpcap-1.10.1
export CC=arm-linux-gnueabihf-gcc
./configure --prefix=/usr --host=arm-linux --with-pcap=linux
make
make install
cd /twpcap
go mod tidy
CC=arm-linux-gnueabihf-gcc GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=1 go build -o $1/twpcap.arm  -ldflags='-extldflags "-static -s" -w -X main.version=$2 -X main.commit=$3'

