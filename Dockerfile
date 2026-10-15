# grapeid-url-relay — Fly.io image.
#
# Written 2026-10-15 to close a gap, not copied from the original: the running
# app declares build.dockerfile = "Dockerfile" and no Dockerfile had ever been
# committed, so the deployed binary could not be rebuilt from this repository.
# The image on Fly is a multi-stage Go build carrying only the binary, so there
# was no copy to recover either.
#
# This reproduces what the deployment expects rather than what the original
# author wrote, which is unknowable: a static binary from ./cmd/relay, serving
# LISTEN_ADDR with its SQLite database on the mounted volume. Verify a build
# from this file behaves identically before deploying it over the running one.
FROM golang:1.24-alpine AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /relay ./cmd/relay

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
WORKDIR /app

# Defaults match the Fly app's own env; fly.toml sets these explicitly too, so
# the image is runnable on its own without depending on them being passed.
ENV LISTEN_ADDR=":5000"
ENV SQLITE_PATH="/data/relay.db"

VOLUME ["/data"]
COPY --from=build /relay /app/relay

EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=5s \
  CMD wget -qO- http://127.0.0.1:5000/health || exit 1

CMD ["/app/relay"]
