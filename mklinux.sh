#!/bin/sh
apt update
apt install -y libpcap-dev
go mod tidy
go build -o $1/twpcap -ldflags='-extldflags "-static -s" -w -X main.version=$2 -X main.commit=$3'

