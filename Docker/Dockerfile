FROM alpine:latest
RUN apk add --update --no-cache tzdata
COPY twpcap /
RUN  chmod +x /twpcap
WORKDIR /
ENTRYPOINT [ "/twpcap" ]

