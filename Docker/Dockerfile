FROM alpine:latest
RUN apk add --update --no-cache tzdata && \
    cp /usr/share/zoneinfo/Asia/Tokyo /etc/localtime && \
    echo "Asia/Tokyo" > /etc/timezone && \
    apk del tzdata
COPY twpcap /
RUN  chmod +x /twpcap
WORKDIR /
ENTRYPOINT [ "/twpcap" ]
