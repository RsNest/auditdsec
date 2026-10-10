# The images of auditdsec. GitHub Actions builds them for linux/amd64 and
# linux/arm64 and publishes them to ghcr.io (see .github/workflows/ci.yml);
# ./install.sh downloads them. Building here is the developer's path
# (./install.sh --build-local, make docker).
#
#   target minimal   the agent: the binary, CA bundle and time zones, nothing else
#   target enforce   the agent plus nft, for deploy/compose.enforce.yml
#   target probe     cmd/auditdsec-probe, the RemoteProbe service for another machine
#
# The Go stage runs on the build machine's own platform and cross-compiles
# (no CPU emulation for the compiler); only `apk add` in the enforce stage
# runs under emulation for a foreign architecture.
FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS build

ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown
ARG TARGETOS=linux
ARG TARGETARCH

# ca-certificates for the HTTPS call to Telegram, tzdata so TZ=Europe/Moscow
# formats timestamps correctly in the final image. Both are architecture-free.
RUN apk add --no-cache ca-certificates tzdata

WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH GOFLAGS=-trimpath go build \
        -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
        -o /out/auditdsec ./cmd/auditdsec && \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH GOFLAGS=-trimpath go build \
        -ldflags "-s -w" -o /out/auditdsec-probe ./cmd/auditdsec-probe

# ---------------------------------------------------------------------------
# The enforcing image. It carries the nft command line, which is the only
# reason it is not built on scratch: applying a ban means running `nft`.
# Use it with deploy/compose.enforce.yml, which grants NET_ADMIN and the host
# network namespace — without those, nft cannot touch host traffic.
FROM alpine:3.21 AS enforce

ARG VERSION=dev
ARG COMMIT=none
LABEL org.opencontainers.image.source="https://github.com/RsNest/auditdsec" \
      org.opencontainers.image.title="auditdsec-enforce" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.licenses="MIT"

RUN apk add --no-cache nftables ca-certificates tzdata

COPY --from=build /out/auditdsec /usr/local/bin/auditdsec

VOLUME ["/var/lib/auditdsec"]

ENV AUDITDSEC_STATE_DIR=/var/lib/auditdsec \
    AUDITDSEC_AUDIT_LOG=/var/log/audit/audit.log \
    AUDITDSEC_LOG_FILE=/var/lib/auditdsec/auditdsec.log

ENTRYPOINT ["/usr/local/bin/auditdsec"]
CMD ["run"]

# ---------------------------------------------------------------------------
# RemoteProbe, to run on a machine other than the server being checked.
FROM scratch AS probe

ARG VERSION=dev
ARG COMMIT=none
LABEL org.opencontainers.image.source="https://github.com/RsNest/auditdsec" \
      org.opencontainers.image.title="auditdsec-probe" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.licenses="MIT"

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/auditdsec-probe /usr/local/bin/auditdsec-probe

USER 65534:65534
ENTRYPOINT ["/usr/local/bin/auditdsec-probe"]

# ---------------------------------------------------------------------------
# The default image: the binary, the CA bundle needed to reach Telegram, and
# the time zone database. Nothing else — no shell, no package manager.
#
# The audit log is root-owned and mode 0600 on every distribution, so the agent
# runs as root but with every capability dropped (see docker-compose.yml). It
# writes nothing outside the state volume. Last, so a plain `docker build`
# without --target builds this one.
FROM scratch AS minimal

ARG VERSION=dev
ARG COMMIT=none
LABEL org.opencontainers.image.source="https://github.com/RsNest/auditdsec" \
      org.opencontainers.image.title="auditdsec" \
      org.opencontainers.image.description="Explains Linux auditd events, alerts to Telegram, optional web panel" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.licenses="MIT"

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=build /out/auditdsec /usr/local/bin/auditdsec

VOLUME ["/var/lib/auditdsec"]

ENV AUDITDSEC_STATE_DIR=/var/lib/auditdsec \
    AUDITDSEC_AUDIT_LOG=/var/log/audit/audit.log \
    AUDITDSEC_LOG_FILE=/var/lib/auditdsec/auditdsec.log

ENTRYPOINT ["/usr/local/bin/auditdsec"]
CMD ["run"]
