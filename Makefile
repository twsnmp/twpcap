.PHONY: all test clean zip mac docker

### バージョンの定義
VERSION     := "v2.0.0"
COMMIT      := $(shell git rev-parse --short HEAD)
WD          := $(shell pwd)
### コマンドの定義
GO          = go
GO_BUILD    = $(GO) build
GO_TEST     = $(GO) test -v
GO_LDFLAGS  = -ldflags="-s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT)"
ZIP          = zip

### ターゲットパラメータ
DIST = dist
SRC = ./main.go ./pcap.go ./syslog.go ./tls.go ./radius.go ./dhcp.go ./dns.go
TARGETS     = $(DIST)/twpcap.exe $(DIST)/twpcap.darwin.amd64 $(DIST)/twpcap.darwin.arm64 $(DIST)/twpcap $(DIST)/twpcap.arm $(DIST)/twpcap.arm64
GO_PKGROOT  = ./...

### PHONY ターゲットのビルドルール
all: $(TARGETS)
test:
	env GOOS=$(GOOS) $(GO_TEST) $(GO_PKGROOT)
clean:
	rm -rf $(TARGETS) $(DIST)/*.zip .linux_build
mac: $(DIST)/twpcap.darwin.amd64 $(DIST)/twpcap.darwin.arm64
linux: $(DIST)/twpcap
windows: $(DIST)/twpcap.exe
zip: $(TARGETS)
	cd dist && $(ZIP) twpcap_win.zip twpcap.exe
	cd dist && $(ZIP) twpcap_mac.zip twpcap.darwin.*
	cd dist && $(ZIP) twpcap_linux_amd64.zip twpcap
	cd dist && $(ZIP) twpcap_linux_arm.zip twpcap.arm*

docker:  $(DIST)/twpcap Docker/Dockerfile
	cp dist/twpcap Docker/twpcap.amd64
	cd Docker && docker build --build-arg TARGETARCH=amd64 -t twsnmp/twpcap .

docker-multiarch: Docker/Dockerfile dist/twpcap dist/twpcap.arm dist/twpcap.arm64
	cp dist/twpcap Docker/twpcap.amd64
	cp dist/twpcap.arm Docker/twpcap.arm
	cp dist/twpcap.arm64 Docker/twpcap.arm64
	cd Docker && docker buildx build --platform linux/amd64,linux/arm/v7,linux/arm64 -t twsnmp/twpcap:$(VERSION) --push .

### 実行ファイルのビルドルール
$(DIST)/twpcap.exe: $(SRC)
	env GO111MODULE=on GOOS=windows GOARCH=amd64 $(GO_BUILD) $(GO_LDFLAGS) -o $@
$(DIST)/twpcap.darwin.amd64: $(SRC)
	env GO111MODULE=on GOOS=darwin GOARCH=amd64 CGO_ENABLED=1 $(GO_BUILD) $(GO_LDFLAGS) -o $@
$(DIST)/twpcap.darwin.arm64: $(SRC)
	env GO111MODULE=on GOOS=darwin GOARCH=arm64 CGO_ENABLED=1 $(GO_BUILD) $(GO_LDFLAGS) -o $@

$(DIST)/twpcap $(DIST)/twpcap.arm $(DIST)/twpcap.arm64: .linux_build
	@ls $@ > /dev/null 2>&1

.linux_build: $(SRC) mklinux.sh
	docker run --rm -v "$(WD)":/twpcap -w /twpcap golang:1.25 /twpcap/mklinux.sh $(DIST) $(VERSION) $(COMMIT)
	touch .linux_build
