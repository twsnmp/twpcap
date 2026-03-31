FROM alpine:latest
RUN apk add --update --no-cache tzdata
ARG TARGETARCH
COPY twpcap.${TARGETARCH} /twpcap
RUN  chmod +x /twpcap
WORKDIR /
ENTRYPOINT [ "/twpcap" ]

