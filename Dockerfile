FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata
WORKDIR /src

COPY go.mod go.sum ./
COPY internal/compat/anet ./internal/compat/anet
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o /out/olcrtc ./cmd/olcrtc

FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S olcrtc && \
    adduser -S -G olcrtc -h /var/lib/olcrtc olcrtc && \
    mkdir -p /var/lib/olcrtc/data && \
    chown -R olcrtc:olcrtc /var/lib/olcrtc

COPY --from=builder /out/olcrtc /usr/local/bin/olcrtc
COPY script/docker/olcrtc-entrypoint.sh /usr/local/bin/olcrtc-entrypoint.sh
COPY script/docker/olcrtc-healthcheck.sh /usr/local/bin/olcrtc-healthcheck.sh

RUN chmod +x /usr/local/bin/olcrtc /usr/local/bin/olcrtc-entrypoint.sh /usr/local/bin/olcrtc-healthcheck.sh

WORKDIR /var/lib/olcrtc
ENV OLCRTC_MODE=srv \
    OLCRTC_LINK=direct \
    OLCRTC_DNS=1.1.1.1:53 \
    OLCRTC_DATA_DIR=/var/lib/olcrtc/data

ENTRYPOINT ["/usr/local/bin/olcrtc-entrypoint.sh"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/usr/local/bin/olcrtc-healthcheck.sh"]
