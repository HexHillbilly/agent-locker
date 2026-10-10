"""Classify every exactly-43-character token on the publication branch by its context.

Shape is not proof either way, so this prints the LINE CONTEXT of each match with the token
itself replaced by <VALUE> -- so a real value can never be printed, and a function name is
obvious from the surrounding `def`/`async def`/call syntax.

Reads blob contents straight out of git, so it sees history, not just the worktree.
"""

import re
import subprocess

BRANCH = "release/0.1.5-public"
TOKEN = re.compile(r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])")

blobs = subprocess.run(["git", "rev-list", "--objects", BRANCH], capture_output=True,
                       text=True, check=True).stdout.splitlines()

seen = {}
for line in blobs:
    parts = line.split(" ", 1)
    if len(parts) != 2:
        continue
    sha, path = parts
    out = subprocess.run(["git", "cat-file", "-t", sha], capture_output=True, text=True)
    if out.stdout.strip() != "blob":
        continue
    text = subprocess.run(["git", "cat-file", "blob", sha], capture_output=True).stdout
    try:
        text = text.decode()
    except UnicodeDecodeError:
        continue
    for m in TOKEN.finditer(text):
        value = m.group(0)
        line_start = text.rfind("\n", 0, m.start()) + 1
        line_end = text.find("\n", m.end())
        raw = text[line_start:line_end if line_end != -1 else len(text)]
        redacted = raw.replace(value, "<VALUE>").strip()[:96]
        seen.setdefault(value, set()).add(f"{path}: {redacted}")

print(f"distinct 43-character tokens on {BRANCH}: {len(seen)}")
kinds = {}
for value, contexts in sorted(seen.items()):
    sample = sorted(contexts)[0]
    if re.search(r"(async )?def <VALUE>\(", sample) or "def <VALUE>" in sample:
        kind = "test/function name"
    elif re.search(r"<VALUE>\(", sample) or re.search(r"<VALUE>,", sample):
        kind = "callable reference"
    else:
        kind = "NEEDS REVIEW"
    kinds[kind] = kinds.get(kind, 0) + 1
    print(f"  [{kind}] {sample}")
print()
for kind, count in sorted(kinds.items()):
    print(f"  {count:3d}  {kind}")
if kinds.get("NEEDS REVIEW"):
    print("\nRESULT: at least one token is not obviously benign -- review before publishing")
else:
    print("\nRESULT: every 43-character token is a function name or a reference to one; "
          "none is a credential")
