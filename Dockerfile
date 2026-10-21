# syntax=docker/dockerfile:1.7
#
# The relay terminates TLS itself (an admission is bound to the TLS
# connection), so whatever runs this image must pass raw TCP to it, never a
# proxy that terminates TLS. See README.md.

FROM golang:1.26-alpine AS build
RUN apk add --no-cache git ca-certificates
WORKDIR /src
ENV CGO_ENABLED=0 GOOS=linux GOTOOLCHAIN=auto
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -trimpath -ldflags="-s -w" -o /out/relay ./cmd/relay

FROM alpine:3.20 AS runtime
RUN apk add --no-cache ca-certificates tzdata su-exec && adduser -D -u 10001 relay
COPY --from=build /out/relay /usr/local/bin/relay
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
# The database and certificates live in /data; mount a volume on it. A
# platform volume is usually owned by root, so the entrypoint starts as root,
# hands /data to the relay user, and drops to that user before the relay runs.
ENV RELAY_DATA_DIR=/data RELAY_LISTEN_ADDR=:8443
EXPOSE 8443 8080
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
