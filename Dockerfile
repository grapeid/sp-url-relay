# syntax=docker/dockerfile:1.7
#
# Fly.io image for the M35 url-relay.
#
# Chisel is deliberately absent. scripts/start.sh launched a second chisel
# process on :8080 for the pre-M35 tunnel protocol, but production no longer
# serves that protocol at all (/claim-name returns 404 on relay.grapeid.org)
# and the M35 data plane is the server's own /tunnel WebSocket. Carrying
# chisel forward would also carry its hardcoded `--auth user:secret-token`.

FROM golang:1.25-alpine AS build

RUN apk add --no-cache git ca-certificates

WORKDIR /src
ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOPRIVATE=github.com/grapeid/* \
    GONOSUMDB=github.com/grapeid/* \
    GOSUMDB=off

# github.com/grapeid/sp-common is a private module, so the build needs a token.
# Pass it with:  fly deploy --build-secret gh_token=<PAT with repo:read>
# The credential is confined to this stage and never reaches the final image.
COPY go.mod go.sum ./
RUN --mount=type=secret,id=gh_token \
    git config --global url."https://x-access-token:$(cat /run/secrets/gh_token)@github.com/".insteadOf "https://github.com/" && \
    go mod download && \
    git config --global --remove-section url."https://x-access-token:$(cat /run/secrets/gh_token)@github.com/"

COPY . .
RUN go build -trimpath -ldflags="-s -w" -o /out/relay ./cmd/relay

# Proves the Windows-only TempDir cleanup failures are not real test failures.
FROM build AS test
RUN go test ./...

FROM alpine:3.20 AS runtime
RUN apk add --no-cache ca-certificates tzdata && \
    adduser -D -u 10001 relay

COPY --from=build /out/relay /usr/local/bin/relay

# The volume is mounted here; SQLITE_PATH points into it.
RUN mkdir -p /data && chown relay:relay /data
USER relay

EXPOSE 5000
ENTRYPOINT ["/usr/local/bin/relay"]
