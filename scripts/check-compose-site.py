#!/usr/bin/env python3
"""Resolve the real Compose files, without starting containers or using secrets."""
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent


def main():
    clean_env = {
        k: v for k, v in os.environ.items()
        if not k.startswith(("PANEL_", "AUDITDSEC_", "AUDITSEC_", "COMPOSE_"))
    }
    cases = [
        ("domain", {"PANEL_SITE": "panel.example.com"}, "panel.example.com", "https://panel.example.com"),
        ("IP", {"PANEL_SITE": "192.0.2.1", "PANEL_PUBLIC_URL": "https://192.0.2.1:55443"}, "192.0.2.1", "https://192.0.2.1:55443"),
        ("legacy domain", {"PANEL_DOMAIN": "legacy.example.com"}, "legacy.example.com", "https://legacy.example.com"),
        ("current name wins", {"PANEL_SITE": "panel.example.com", "PANEL_DOMAIN": "legacy.example.com"}, "panel.example.com", "https://panel.example.com"),
        ("explicit URL", {"PANEL_SITE": "panel.example.com", "PANEL_PUBLIC_URL": "https://panel.example.com:8443"}, "panel.example.com", "https://panel.example.com:8443"),
        # Empty sites are diagnosed by deploy-check, not by an eager nested
        # required-variable expansion that also rejects valid new settings.
        ("missing site", {}, "", "https://"),
    ]
    with tempfile.TemporaryDirectory(prefix="auditdsec-compose-") as tmp:
        env_file = Path(tmp) / ".env"
        for name, values, site, url in cases:
            fixture_values = {"AUDITDSEC_TG_TOKEN": "123:compose-test", "AUDITDSEC_TG_CHAT_ID": "42", **values}
            env_file.write_text("".join(f"{k}='{v}'\n" for k, v in fixture_values.items()), encoding="utf-8")
            result = subprocess.run(
                ["docker", "compose", "--env-file", str(env_file), "-f", "docker-compose.yml", "-f", "deploy/compose.proxy.yml", "config", "--format", "json"],
                cwd=ROOT, env=clean_env, capture_output=True, text=True,
            )
            if result.returncode:
                raise RuntimeError(f"Compose configuration failed ({name}): {result.stderr}")
            services = json.loads(result.stdout)["services"]
            assert services["caddy"]["environment"]["PANEL_SITE"] == site, name
            assert services["auditdsec"]["environment"]["AUDITDSEC_WEB_PUBLIC_URL"] == url, name
            print(f"ok: Compose address interpolation ({name})")


if __name__ == "__main__":
    main()
