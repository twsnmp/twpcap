#!/bin/sh
apt update
apt install -y wget
apt-get install -y flex bison byacc
apt install -y g++-aarch64-linux-gnu
cd /tmp
wget http://www.tcpdump.org/release/libpcap-1.10.1.tar.gz
tar xzf libpcap-1.10.1.tar.gz
cd libpcap-1.10.1
export CC=aarch64-linux-gnu-gcc
./configure --prefix=/usr --host=arm64-linux --with-pcap=linux
make
make install
cd /twpcap
go mod tidy
CC=aarch64-linux-gnu-gcc GOOS=linux GOARCH=arm64  CGO_ENABLED=1 go build -o $1/twpcap.arm64  -ldflags="-extldflags \"-static -s\" -w -X main.version=$2 -X main.commit=$3"

