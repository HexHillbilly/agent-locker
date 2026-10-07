#!/usr/bin/env python3
"""release_build.py — repeatable export + build of release artifacts from an
explicit commit.

Usage:
    python scripts/release_build.py <commit-ish> [--out DIR] [--keep-work]

What it does, in order:

  1. Resolves <commit-ish> to a full 40-hex commit ID inside this repository
     (refuses if the ref does not resolve to exactly one commit).
  2. Exports that committed source into a *fresh* directory via
     ``git archive`` → tar. Because the export comes from the commit's tree,
     developer environments (``.venv``), caches, databases, credentials and
     stale packaging output are excluded by construction; the script still
     asserts they are absent, and fails loudly if any appear.
  3. Records a manifest of the exported source files (path, size, sha256) plus
     its own sha256. The manifest does not list itself, so its hash stays out of
     its own hash set.
  4. Builds sdist + wheel from the exported source in an isolated environment
     and captures the build-tool versions actually used.
  5. Hashes the artifacts and writes PROVENANCE.json.

All output stays outside the source tree. Nothing is pushed, published,
deployed or credentialed. Artifact hashes are recorded so builds can be
*compared*; this script does not claim byte-for-byte reproducible builds.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path

HEX40 = re.compile(r"^[0-9a-f]{40}$")

# Paths that must never appear in an exported source tree.
FORBIDDEN_DIRS = {".git", ".venv", "venv", "__pycache__", ".pytest_cache", ".mypy_cache", "build", "dist"}
FORBIDDEN_SUFFIXES = (".db", ".db-wal", ".db-shm", ".sqlite", ".sqlite3", ".pyc", ".egg-info", ".whl", ".tar.gz")
FORBIDDEN_NAMES = {".env", ".netrc", "id_rsa", "id_ed25519", "credentials", "credentials.json"}
FORBIDDEN_SECRET_SUFFIXES = (".pem", ".key", ".p12", ".pfx")


def die(msg: str) -> "NoReturn":  # type: ignore[valid-type]
    print(f"release_build: ERROR: {msg}", file=sys.stderr)
    raise SystemExit(1)


def run(cmd, cwd=None, capture=True, check=True):
    proc = subprocess.run(cmd, cwd=cwd, capture_output=capture, text=True)
    if check and proc.returncode != 0:
        die(f"command failed ({proc.returncode}): {' '.join(map(str, cmd))}\n"
            f"stdout:\n{proc.stdout or ''}\nstderr:\n{proc.stderr or ''}")
    return proc


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def tool_version(cmd) -> str:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        out = (proc.stdout or "").strip() or (proc.stderr or "").strip()
        return out.splitlines()[0] if out else "(no output)"
    except Exception as exc:  # pragma: no cover
        return f"(unavailable: {exc})"


def main() -> int:
    ap = argparse.ArgumentParser(description="Export and build release artifacts from an explicit commit.")
    ap.add_argument("commit", help="commit-ish to build from (resolved to a full object ID)")
    ap.add_argument("--out", default=None, help="output directory (must be outside the source tree)")
    ap.add_argument("--keep-work", action="store_true", help="keep the temporary work directory")
    args = ap.parse_args()

    repo = Path(run(["git", "rev-parse", "--show-toplevel"]).stdout.strip()).resolve()

    # ---- 1. resolve the commit to a full object ID --------------------------
    resolved = run(["git", "rev-parse", "--verify", f"{args.commit}^{{commit}}"], cwd=repo).stdout.strip()
    if not HEX40.match(resolved):
        die(f"could not resolve {args.commit!r} to a single 40-hex commit ID (got {resolved!r})")
    commit = resolved
    short = commit[:12]

    # Guard: an explicit commit must be exactly one commit, never a range/glob.
    if run(["git", "rev-list", "--count", f"{commit}^!"], cwd=repo).stdout.strip() != "1":
        die(f"{commit} does not resolve to exactly one commit")

    subject = run(["git", "log", "-1", "--format=%s", commit], cwd=repo).stdout.strip()
    branch = run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=repo).stdout.strip()

    out_dir = Path(args.out).resolve() if args.out else (repo.parent / f"padlock-release-{short}")
    if repo == out_dir or repo in out_dir.parents:
        die(f"--out {out_dir} is inside the source tree {repo}; artifacts must land outside it")

    # ---- 2. export the committed source into a fresh directory --------------
    work = Path(tempfile.mkdtemp(prefix=f"padlock-build-{short}-"))
    src = work / "src"
    src.mkdir(parents=True)
    archive = work / f"{short}.tar"
    with open(archive, "wb") as fh:
        proc = subprocess.run(["git", "archive", "--format=tar", commit], cwd=repo,
                              stdout=fh, stderr=subprocess.PIPE, text=False)
        if proc.returncode != 0:
            die(f"git archive failed: {proc.stderr.decode(errors='replace')}")
    with tarfile.open(archive) as tf:
        tf.extractall(src)

    if not src.is_dir() or src.is_symlink():
        die("export directory is missing or is a symlink")

    # ---- assert the export is clean ----------------------------------------
    problems = []
    for path in sorted(src.rglob("*")):
        name = path.name
        if path.is_dir() and name in FORBIDDEN_DIRS:
            problems.append(f"directory {path.relative_to(src)}")
            continue
        if name in FORBIDDEN_NAMES or name.startswith("id_rsa") or name.startswith("id_ed25519"):
            problems.append(f"credential-like file {path.relative_to(src)}")
            continue
        if name.endswith(FORBIDDEN_SUFFIXES) or name.endswith(FORBIDDEN_SECRET_SUFFIXES):
            problems.append(f"excluded artifact {path.relative_to(src)}")
    if problems:
        die("export is not clean:\n  " + "\n  ".join(problems))

    files = sorted(p for p in src.rglob("*") if p.is_file())
    if not files:
        die("export contains no files")

    manifest = {
        "commit": commit,
        "commit_subject": subject,
        "export_method": "git archive --format=tar <commit>",
        "export_contains": "tracked files at that commit only; no dev env, cache, database, credential or stale packaging output",
        "note": "generated packaging metadata (e.g. *.egg-info) appearing inside an sdist is normal build output, not source contamination",
        "file_count": len(files),
        "total_bytes": sum(p.stat().st_size for p in files),
        "files": [
            {"path": str(p.relative_to(src)), "bytes": p.stat().st_size, "sha256": sha256_file(p)}
            for p in files
        ],
    }

    out_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = out_dir / f"source-manifest-{short}.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    manifest_sha = sha256_file(manifest_path)

    # ---- 3. build sdist + wheel from the exported source --------------------
    buildenv = work / "buildenv"
    run(["uv", "venv", str(buildenv), "--python", f"{sys.version_info.major}.{sys.version_info.minor}"])
    py = buildenv / "bin" / "python"
    run(["uv", "pip", "install", "--python", str(py), "-q",
         "setuptools>=77", "wheel", "build"])

    build_proc = run([str(py), "-m", "build", "--sdist", "--wheel", "--outdir", str(out_dir), str(src)])

    artifacts = sorted([p for p in out_dir.iterdir() if p.suffix in (".whl",) or p.name.endswith(".tar.gz")])
    if not artifacts:
        die(f"no artifacts produced in {out_dir}\n{build_proc.stdout}\n{build_proc.stderr}")

    versions = {
        "python": sys.version.split()[0],
        "uv": tool_version(["uv", "--version"]),
        "git": tool_version(["git", "--version"]),
        "buildenv_python": run([str(py), "-V"]).stdout.strip(),
        "setuptools": run([str(py), "-c", "import setuptools;print(setuptools.__version__)"]).stdout.strip(),
        "build": run([str(py), "-c", "import build;print(build.__version__)"]).stdout.strip(),
        "wheel": run([str(py), "-c", "import wheel;print(wheel.__version__)"]).stdout.strip(),
    }

    provenance = {
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source": {
            "commit": commit,
            "commit_short": short,
            "commit_subject": subject,
            "repo_worktree_branch_at_build": branch,
            "export_method": "git archive --format=tar <commit>",
        },
        "manifest": {
            "path": manifest_path.name,
            "sha256": manifest_sha,
            "file_count": manifest["file_count"],
            "total_bytes": manifest["total_bytes"],
            "self_reference": "excluded (the manifest does not list itself)",
        },
        "build_tools": versions,
        "artifacts": [
            {"file": p.name, "bytes": p.stat().st_size, "sha256": sha256_file(p)} for p in artifacts
        ],
        "reproducibility": "hashes recorded for comparison only; byte-for-byte reproducible builds are NOT claimed",
        "note": "build ran in an isolated environment from the exported source, not from the development checkout",
    }
    prov_path = out_dir / f"PROVENANCE-{short}.json"
    prov_path.write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")

    print(f"commit        {commit}")
    print(f"subject       {subject}")
    print(f"exported      {manifest['file_count']} files, {manifest['total_bytes']} bytes")
    print(f"manifest      {manifest_path}  sha256={manifest_sha}")
    for a in provenance["artifacts"]:
        print(f"artifact      {out_dir / a['file']}  sha256={a['sha256']}")
    print(f"provenance    {prov_path}")
    print(f"output dir    {out_dir}")

    if not args.keep_work:
        shutil.rmtree(work, ignore_errors=True)
    else:
        print(f"work dir      {work}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
