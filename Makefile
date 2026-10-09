# auditdsec — build, test and package.
#
#   make            build the binary into bin/
#   make test       vet + tests
#   make check      formatting, vet, tests (what CI should run)
#   make docker     build the container image
#   make install    install the binary, config and systemd unit on this host

BINARY  := auditdsec
VERSION ?= 0.1.0
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

PREFIX     ?= /usr/local
CONFDIR    ?= /etc/auditdsec
STATEDIR   ?= /var/lib/auditdsec
LOGDIR     ?= /var/log/auditdsec

.PHONY: all build test vet fmt fmt-check check docker clean install uninstall rules

all: build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/$(BINARY)
	@echo "built bin/$(BINARY) $(VERSION) ($(COMMIT))"

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

fmt-check:
	@test -z "$$(gofmt -l .)" || { echo "not gofmt-clean:"; gofmt -l .; exit 1; }

check: fmt-check vet test

docker:
	docker build -f deploy/Dockerfile \
		--build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) --build-arg DATE=$(DATE) \
		-t $(BINARY):$(VERSION) -t $(BINARY):latest .

clean:
	rm -rf bin

# Install the binary form (the fallback when Docker is not used). The audit
# rules are installed separately with `make rules`, because loading them
# restarts auditd.
install: build
	install -m 0755 bin/$(BINARY) $(PREFIX)/bin/$(BINARY)
	install -d -m 0750 $(CONFDIR) $(STATEDIR) $(LOGDIR)
	test -f $(CONFDIR)/auditdsec.yaml || install -m 0640 config.example.yaml $(CONFDIR)/auditdsec.yaml
	install -m 0644 deploy/auditdsec.service /etc/systemd/system/auditdsec.service
	@echo
	@echo "Next: put the token in $(CONFDIR)/auditdsec.env, then"
	@echo "  systemctl daemon-reload && systemctl enable --now auditdsec"

uninstall:
	systemctl disable --now auditdsec 2>/dev/null || true
	rm -f /etc/systemd/system/auditdsec.service $(PREFIX)/bin/$(BINARY)
	@echo "left in place: $(CONFDIR), $(STATEDIR), $(LOGDIR)"

# Install the audit rules and load them.
rules:
	install -m 0640 deploy/auditdsec.rules /etc/audit/rules.d/50-auditdsec.rules
	./deploy/gen-sshkeys-rules.sh >> /etc/audit/rules.d/50-auditdsec.rules
	augenrules --load
	@auditctl -l | head -n 5
