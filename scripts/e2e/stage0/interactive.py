#!/usr/bin/env python3
"""Drive ./install.sh through a real pseudo-terminal, as a person would.

    scripts/e2e/stage0/interactive.py

Run 1: a new installation. Language comes first, then "where should the
panel open", the address, the RemoteProbe provider, the port (automatic).
Run 2: the same installation again, moving the panel to a port typed by hand.
Needs the stand (lab.sh up) and is run on the same disposable machine.
"""
import os
import pty
import select
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.environ.get("LAB", "/lab")
WORK = os.path.join(LAB, "work")
VPS = open(os.path.join(LAB, "vps-ip")).read().strip()

# The same environment and clean start as scenarios.sh.
env_dump = subprocess.run(["bash", "-c", f"source {HERE}/env.sh; reset; env -0"],
                          capture_output=True, text=True, check=True).stdout
env = dict(item.split("=", 1) for item in env_dump.split("\0") if "=" in item)
# The provider's own certificate is self-signed on the stand; a person would
# give --probe-cacert, which the questions do not ask for.
env["PANEL_PROBE_CACERT"] = os.path.join(LAB, "probe-ca.pem")


def drive(answers, log):
    """answers: list of (prompt, reply); each is answered once, in any order."""
    pid, fd = pty.fork()
    if pid == 0:
        os.chdir(WORK)
        os.execvpe("./install.sh", ["./install.sh", "--no-build"], env)
    buf, answered, order = b"", set(), []
    deadline = time.time() + 600
    while time.time() < deadline:
        r, _, _ = select.select([fd], [], [], 1.0)
        if not r:
            continue
        try:
            data = os.read(fd, 4096)
        except OSError:
            break
        if not data:
            break
        buf += data
        seen = buf.decode("utf-8", "replace")
        for prompt, reply in answers:
            if prompt not in answered and prompt in seen[-300:]:
                answered.add(prompt)
                order.append(prompt)
                time.sleep(0.2)
                os.write(fd, (reply + "\n").encode())
    _, status = os.waitpid(pid, 0)
    text = buf.decode("utf-8", "replace")
    with open(os.path.join(LAB, "out", log), "w") as fh:
        fh.write(text)
    return text, os.WEXITSTATUS(status), order, answered


ok = True


def check(desc, cond):
    global ok
    print(("  PASS  " if cond else "  FAIL  ") + desc)
    ok = ok and cond


print("== interactive: new installation")
first = [
    ("Ваш выбор / Your choice", "2"),
    ("Choose 1 or 2", "2"),
    ("Type this server's public address", VPS),
    ("RemoteProbe URL", "https://127.0.0.1:8443"),
    ("File with its token", os.path.join(LAB, "probe-token")),
    ("Port: 1 automatic, 2 given by you", "1"),
    ("E-mail for certificate expiry warnings", ""),
]
text, rc, order, answered = drive(first, "interactive-1.log")
check("the first question is the language", order[:1] == ["Ваш выбор / Your choice"])
check("the next question is where the panel opens", order[1:2] == ["Choose 1 or 2"])
check("the menu offers a domain and a public IP, no tunnel", "On a domain" in text and "public IP address" in text and "SSH tunnel" not in text)
check("the address came before the port, the port before the e-mail",
      order.index("Type this server's public address") < order.index("Port: 1 automatic, 2 given by you") < order.index("E-mail for certificate expiry warnings"))
check("every question was asked", len(answered) == len(first))
check("published", "The panel is published and waits for first-time setup." in text)
check("the link is the last line, on 443", text.rstrip().splitlines()[-2].strip() == f"Link: https://{VPS}")
check("exit status 0", rc == 0)

print("== interactive: run again, move the panel to a port given by hand")
second = [
    ("Choose 1 or 2", ""),
    ("Type this server's public address", ""),
    ("Keep the panel on port 443?", "n"),
    ("Port: 1 automatic, 2 given by you", "2"),
    ("Port (1-65535)", "27431"),
    ("E-mail for certificate expiry warnings", ""),
]
text, rc, order, answered = drive(second, "interactive-2.log")
check("the saved language is used without asking", "Ваш выбор / Your choice" not in text)
check("no RemoteProbe question: the saved provider is used", "RemoteProbe URL" not in text)
check("the port typed by hand is used", f"Link: https://{VPS}:27431" in text)
check("published", "The panel is published" in text)
check("exit status 0", rc == 0)
sys.exit(0 if ok else 1)
