#!/usr/bin/env python3
"""Drive ./install.sh through a real pseudo-terminal, answering its questions.

    scripts/e2e/real/interactive.py            # address mode on staging

Checks that the menu appears, that the staging question is asked, that the
password is read without echo, and that the run ends with a verified link.
Needs the lab (lab.sh up). Uses the same environment as scenarios.sh.
"""
import os
import pty
import select
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PASSWORD = "an-interactive-test-password-1!"

env_dump = subprocess.run(
    ["bash", "-c", f"source {HERE}/env.sh; reset; env"], capture_output=True, text=True, check=True).stdout
env = dict(line.split("=", 1) for line in env_dump.splitlines() if "=" in line and not line.startswith(" "))
LAB = os.environ.get("LAB", "/tmp/auditdsec-lab")
env["LAB"] = LAB
work = os.path.join(LAB, "work")

# prompt text -> answer. Order does not matter; each is answered once.
answers = [
    ("Choose 1-4", "2"),
    ("This server's public address", "127.0.0.1"),
    ("Carry on anyway?", "y"),
    ("Email for certificate expiry warnings", ""),
    ("Use the staging CA for this run?", "y"),
    ("Panel login name", ""),
    ("Apply bans with nftables?", "n"),
    ("Panel password: ", PASSWORD),
    ("Again: ", PASSWORD),
]

pid, fd = pty.fork()
if pid == 0:
    os.chdir(work)
    os.execvpe("./install.sh", ["./install.sh", "--no-build", "--cacert", os.path.join(LAB, "root-staging.pem")], env)

seen, buf, answered = "", b"", set()
deadline = time.time() + 480
echoed_password = False
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
        if prompt in seen and prompt not in answered:
            # the prompt is the last thing on the screen: answer once
            if seen.rstrip().endswith((":", "]:", "]")) or prompt in seen[-200:]:
                answered.add(prompt)
                time.sleep(0.2)
                os.write(fd, (reply + "\n").encode())
_, status = os.waitpid(pid, 0)
text = buf.decode("utf-8", "replace")
with open(os.path.join(LAB, "interactive.log"), "w") as fh:
    fh.write(text)

def check(desc, ok):
    print(("  PASS  " if ok else "  FAIL  ") + desc)
    return ok

results = [
    check("the menu offered all four choices", all(w in text for w in ("A domain name", "public IP address", "SSH tunnel", "signs itself"))),
    check("the staging question was asked", "Let's Encrypt: dry run first?" in text),
    check("the password was not echoed", PASSWORD not in text),
    check("the run ended with a signed-in, verified summary", "signed in with the chosen password" in text and "STAGING" in text),
    check("the installer exited 0", os.WEXITSTATUS(status) == 0),
    check("every question was answered", len(answered) == len(answers)),
]
sys.exit(0 if all(results) else 1)
