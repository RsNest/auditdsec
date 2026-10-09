# Build a static binary. The agent has no Go module dependencies, so nothing is
# downloaded from a module proxy; only the base image and these two packages
# come from the network.
FROM golang:1.24-alpine AS build

ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown

# ca-certificates for the HTTPS call to Telegram, tzdata so TZ=Europe/Moscow
# formats timestamps correctly in the final scratch image.
RUN apk add --no-cache ca-certificates tzdata

WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal

RUN CGO_ENABLED=0 GOFLAGS=-trimpath go build \
        -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
        -o /out/auditdsec ./cmd/auditdsec

# The final image carries the binary, the CA bundle needed to reach Telegram
# over HTTPS, and the time zone database so TZ=Europe/Moscow formats correctly.
FROM scratch

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=build /out/auditdsec /usr/local/bin/auditdsec

# The audit log is root-owned and mode 0600 on every distribution, so the agent
# runs as root but with every capability dropped (see docker-compose.yml). It
# writes nothing outside the state volume.
VOLUME ["/var/lib/auditdsec"]

ENV AUDITDSEC_STATE_DIR=/var/lib/auditdsec \
    AUDITDSEC_AUDIT_LOG=/var/log/audit/audit.log \
    AUDITDSEC_LOG_FILE=/var/lib/auditdsec/auditdsec.log

ENTRYPOINT ["/usr/local/bin/auditdsec"]
CMD ["run"]
