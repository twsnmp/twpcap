.PHONY: all test clean zip mac docker

### バージョンの定義
VERSION     := "v1.5.0"
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
TARGETS     = $(DIST)/twpcap.exe $(DIST)/twpcap.app $(DIST)/twpcap $(DIST)/twpcap.arm $(DIST)/twpcap.arm64
GO_PKGROOT  = ./...

### PHONY ターゲットのビルドルール
all: $(TARGETS)
test:
	env GOOS=$(GOOS) $(GO_TEST) $(GO_PKGROOT)
clean:
	rm -rf $(TARGETS) $(DIST)/*.zip
mac: $(DIST)/twpcap.app
zip: $(TARGETS)
	cd dist && $(ZIP) twpcap_win.zip twpcap.exe
	cd dist && $(ZIP) twpcap_mac.zip twpcap.app
	cd dist && $(ZIP) twpcap_linux_amd64.zip twpcap
	cd dist && $(ZIP) twpcap_linux_arm.zip twpcap.arm*

docker:  $(DIST)/twpcap Docker/Dockerfile
	cp dist/twpcap Docker/
	cd Docker && docker build -t twsnmp/twpcap .

dockerarm: Docker/Dockerfile dist/twpcap.arm dist/twpcap.arm64
	cp dist/twpcap.arm Docker/twpcap
	cd Docker && docker buildx build --platform linux/arm/v7 -t twsnmp/twpcap:armv7_$(VERSION) --push .
	cp dist/twpcap.arm64 Docker/twpcap
	cd Docker && docker buildx build --platform linux/arm64 -t twsnmp/twpcap:arm64_$(VERSION) --push .

### 実行ファイルのビルドルール
$(DIST)/twpcap.exe: $(SRC)
	env GO111MODULE=on GOOS=windows GOARCH=amd64 $(GO_BUILD) $(GO_LDFLAGS) -o $@
$(DIST)/twpcap.app: $(SRC)
	env GO111MODULE=on GOOS=darwin GOARCH=amd64 $(GO_BUILD) $(GO_LDFLAGS) -o $@
$(DIST)/twpcap.arm: $(SRC)
	docker run --rm -v "$(WD)":/twpcap -w /twpcap golang /twpcap/mkarm.sh $(DIST) $(VERSION) $(COMMIT)
$(DIST)/twpcap.arm64: $(SRC)
	docker run --rm -v "$(WD)":/twpcap -w /twpcap golang /twpcap/mkarm64.sh $(DIST) $(VERSION) $(COMMIT)
$(DIST)/twpcap: $(SRC)
	docker run --rm -v "$(WD)":/twpcap -w /twpcap golang /twpcap/mklinux.sh $(DIST) $(VERSION) $(COMMIT)
