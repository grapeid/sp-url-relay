# syntax=docker/dockerfile:1.7
#
# The relay terminates TLS itself (an admission is bound to the TLS
# connection), so whatever runs this image must pass raw TCP to port 443,
# never a proxy that terminates TLS. See README.md.

FROM golang:1.26-alpine AS build
RUN apk add --no-cache git ca-certificates
WORKDIR /src
ENV CGO_ENABLED=0 GOOS=linux
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -trimpath -ldflags="-s -w" -o /out/relay ./cmd/relay

FROM build AS test
RUN go test ./...

FROM alpine:3.20 AS runtime
RUN apk add --no-cache ca-certificates tzdata && adduser -D -u 10001 relay
COPY --from=build /out/relay /usr/local/bin/relay
# The database and the certificate cache live here; mount a volume on it.
RUN mkdir -p /data && chown relay:relay /data
ENV RELAY_DATA_DIR=/data RELAY_LISTEN_ADDR=:8443
USER relay
EXPOSE 8443 8080
ENTRYPOINT ["/usr/local/bin/relay"]
