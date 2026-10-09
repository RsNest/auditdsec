#!/bin/sh
# Certbot's deploy hook. All of the work is in certtool.py; this stays a shell
# file because that is the name certbot's renewal configuration remembers.
exec python3 /hooks/certtool.py deploy
