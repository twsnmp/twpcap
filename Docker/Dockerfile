FROM alpine:latest as builder
RUN apk add --update --no-cache tzdata && \
    cp /usr/share/zoneinfo/Asia/Tokyo /etc/localtime && \
    echo "Asia/Tokyo" > /etc/timezone && \
    apk del tzdata
COPY twpcap /
RUN  chmod +x /twpcap

FROM alpine:latest
COPY --from=builder /twpcap /
COPY --from=builder /etc/timezone /etc/
COPY --from=builder /etc/localtime /etc/
WORKDIR /
ENTRYPOINT [ "/twpcap" ]

