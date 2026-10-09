#!/bin/bash
# Stops the stand-in agent and Caddy started by fakedocker.
E2E="${E2E_STATE:-/tmp/auditdsec-e2e}"
for f in agent.pid caddy.pid; do [ -f "$E2E/$f" ] && kill "$(cat "$E2E/$f")" 2>/dev/null; rm -f "$E2E/$f"; done
sleep 1
exit 0
