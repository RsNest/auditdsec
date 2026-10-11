# Changing how the panel is reached

After the first installation the address of the panel can be changed in two ways. Both
run **the same code**: the installer. The panel never edits Compose, the proxy or
certificates itself.

| | Repeated `./install.sh` | Settings → Access and HTTPS |
|---|---|---|
| Who applies the change | the installer, in your terminal | the installer, started by the local control service |
| Needs | Docker access on the server | the control service enabled once (below) |
| Checks, backup, rollback | `deploy/installer-access.sh` + `install.sh` | the same, nothing reimplemented |

## 1. Repeated `./install.sh`

On an existing installation the installer shows what is there — mode, address, link,
certificate issuer and expiry, how it renews, whether it runs — and offers:

1. check the current state;
2. connect or change the domain;
3. switch to access by IP address;
4. switch to an SSH tunnel (no public access);
5. change the login and password (reset to the first-login setup; data is kept);
6. update the application;
0. leave.

Saved settings (Telegram, e-mail, credentials, enforcement, the Let's Encrypt environment,
the outside-check provider) are reused, not asked again. Domain ⇄ IP ⇄ tunnel and
domain → another domain are the same change with different parameters.

Without the menu (scripts, the panel): `./install.sh --action check|domain|ip|tunnel|update|credentials
[--site NAME] [--email ADDRESS] [--https-port N|auto] --yes`. `./install.sh --status [--json]`
prints the facts and changes nothing. Exit status `20` (`operation_in_progress`) means another change
is running; a lock file in the installation directory keeps two changes (a person, the panel) apart.

Before applying, the installer prints old → new, that a short interruption is expected, what is kept,
and that the previous configuration is restored if the new address cannot be verified.

## 2. Settings → Access and HTTPS

Shows the current link, mode, domain or IP, the certificate issuer and expiry, renewal and whether the
stack runs (reported by the installer; without the control service only what the agent derives from its own
public URL, and the panel says so). The **Connect a domain** wizard:

1. enter the domain (and e-mail, port `auto` or a number);
2. the panel shows the DNS records to create and the server's addresses;
3. **Check**: public DNS is compared with this server (several resolvers, A and AAAA);
4. the plan: what changes, what is kept, the interruption, the rollback, and the exact installer command;
5. confirm and **Apply**: the change runs as a task with stages (`preflight`, `dns`, `port`, `challenge`, `apply`,
   `verify`, `rollback`); the state survives a page reload, a restart of the panel and a restart of the
   control service (a task cut short is shown as *interrupted*, never as done);
6. only after the installer verified the new address, **Open the panel at the new address**.

If DNS is not ready, **Save draft** keeps the entries (state in the agent) and the check can be repeated later.

What the check means, and does not mean:

- *Checked*: public DNS leads to this server.
- *Not checked from here*: DNS-only (no CDN in front), ports 80/443 and the HTTPS port reachable from the
  internet, whether the certificate authority will issue the certificate, whether the panel is reachable
  at the new address. The installer tests these when applying. **Matching DNS is a precondition, not a
  guarantee** of a certificate or of a reachable panel. TLS issuance and reachability are confirmed only
  after applying, by the installer's verification over a verified certificate.
- Applying a domain needs a successful check of that very domain within the last 30 minutes, and the
  confirmation of the exact plan shown (a plan ID ties them); a changed parameter needs a new confirmation.

After the origin changes the session does not follow: the token lives in the browser's per-origin session
storage and is never put in a URL. Sign in again at the new address with the same login and password.

## The local control service

The web application cannot change Compose or the proxy, and the agent must not get root or the Docker
socket for it. The panel therefore talks to a separate host-side service, `auditdsec-ctl`:

- runs on the server as the user who runs `./install.sh` (that user already has Docker access);
- listens only on a Unix socket in `.ctl/run` (mode 0660, owner = that user) with a bearer token; the agent
  container gets that one directory read-only plus the user's group (`group_add`), nothing else;
- accepts only structured parameters — action (`check|domain|ip|tunnel|update`), domain or address, e-mail,
  HTTPS port, language — validates them (no option-like, whitespace, shell or non-ASCII values; ports and
  addresses parsed) and builds the installer's arguments from a fixed template. There is **no endpoint that
  takes a command, a path or a script**, and the process environment is scrubbed;
- runs one change at a time and records stages and the (masked) end of the output.

Enable once, after the install:

```bash
./install.sh --enable-panel-control
```

It copies the control binary out of the commit-matched image (no Go needed), writes a systemd unit to
`.ctl/auditdsec-ctl.service`, links the panel to the socket and prints the two `sudo` commands to start the
service (the installer never uses sudo itself; as root it enables the service). `--disable-panel-control` removes
the link. **Without the service the panel does not pretend**: it shows that the change is applied on the
server and gives the exact `./install.sh --action …` command.

## Rollback and data

Before a change the running configuration is copied (`.env.pre-change`); the last *verified* one
(`.env.last-good`) is preferred. If the certificate cannot be issued, the proxy does not start or the page check
fails, that configuration is restored, the failed one is kept as `.env.failed`, and the task ends as
*rolled back* with the diagnosed code, cause and fix. Volumes — events, bans, the allowlist, credentials,
certificates — are never removed. The old address cannot be kept in parallel: the same public port is reused and the installer stops the
proxy for its port checks, so there is an interruption. It is announced before applying; if the new
address fails verification the old configuration is started again.

## What has been verified, and how

| Scenario | Real Docker / ACME | Test doubles |
|---|---|---|
| Control binary ships in the image and can be copied out with `docker create`/`cp` | yes (local build of the `minimal` image) | – |
| `docker compose config` with the control overlay (group, env, read-only mount; required variable) | yes (real Compose, no containers started) | – |
| Menu, `--action` handling, status JSON, lock (exit 20), events, backup and rollback source | – | installer functions sourced in a Linux shell (`scripts/check-installer-access.sh`) |
| Control service: validation, one task at a time, stages, failure, rollback result, restart → interrupted, secrets masked, socket client | – | fake installer, real Unix socket |
| Panel API: DNS preflight, plan, confirmation, stale or other-domain check, busy, no control service → command | – | fake DNS and fake control service |
| Panel UI logic | – | script parse and logic checks; **not rendered in a browser** |
| Existing installation → domain; IP → domain; domain → another domain; domain → IP/tunnel; wrong DNS; certificate issuance failure; rollback after a real failure; repeat without changes; data and credentials kept; panel and installer racing for the lock | **not run** against real Docker and ACME | action parameters, rollback source, lock and API/service behaviour are covered by the doubles above |

A full run of these against real Docker and a real ACME server needs the privileged lab
(`scripts/e2e/stage0`, `scripts/e2e/real`) and was not run for this change.
