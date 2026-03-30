#!/bin/bash
set -e

# Update and install dependencies for Debian
apt-get update
apt-get install -y libpcap-dev libdbus-1-dev libusb-1.0-0-dev libnl-3-dev libnl-genl-3-dev libbluetooth-dev \
    libcap-dev liblzma-dev libzstd-dev liblz4-dev libgcrypt20-dev pkg-config

dpkg --add-architecture armhf
dpkg --add-architecture arm64
apt-get update
apt-get install -y \
    libpcap-dev:armhf libdbus-1-dev:armhf libusb-1.0-0-dev:armhf libnl-3-dev:armhf libnl-genl-3-dev:armhf libbluetooth-dev:armhf \
    libcap-dev:armhf liblzma-dev:armhf libzstd-dev:armhf liblz4-dev:armhf libgcrypt20-dev:armhf \
    libpcap-dev:arm64 libdbus-1-dev:arm64 libusb-1.0-0-dev:arm64 libnl-3-dev:arm64 libnl-genl-3-dev:arm64 libbluetooth-dev:arm64 \
    libcap-dev:arm64 liblzma-dev:arm64 libzstd-dev:arm64 liblz4-dev:arm64 libgcrypt20-dev:arm64 \
    gcc-arm-linux-gnueabihf gcc-aarch64-linux-gnu

cd /twpcap
go mod tidy

DIST=$1
VERSION=$2
COMMIT=$3

# Ensure CGO is enabled for libpcap
export CGO_ENABLED=1

# amd64
echo "Building for linux/amd64..."
export GOOS=linux
export GOARCH=amd64
export CC=gcc
export PKG_CONFIG_PATH=/usr/lib/x86_64-linux-gnu/pkgconfig
PCAP_LIBS=$(pkg-config --static --libs libpcap dbus-1)
go build -o "$DIST/twpcap" -ldflags="-s -w -X main.version=$VERSION -X main.commit=$COMMIT -extldflags '-static $PCAP_LIBS -lcap -lpthread -ldl'"

# arm
echo "Building for linux/arm..."
export GOARCH=arm
export GOARM=7
export CC=arm-linux-gnueabihf-gcc
export PKG_CONFIG_PATH=/usr/lib/arm-linux-gnueabihf/pkgconfig
PCAP_LIBS=$(pkg-config --static --libs libpcap dbus-1)
go build -o "$DIST/twpcap.arm" -ldflags="-s -w -X main.version=$VERSION -X main.commit=$COMMIT -extldflags '-static $PCAP_LIBS -lcap -lpthread -ldl'"

# arm64
echo "Building for linux/arm64..."
export GOARCH=arm64
export CC=aarch64-linux-gnu-gcc
export PKG_CONFIG_PATH=/usr/lib/aarch64-linux-gnu/pkgconfig
PCAP_LIBS=$(pkg-config --static --libs libpcap dbus-1)
unset GOARM
go build -o "$DIST/twpcap.arm64" -ldflags="-s -w -X main.version=$VERSION -X main.commit=$COMMIT -extldflags '-static $PCAP_LIBS -lcap -lpthread -ldl'"
