#!/usr/bin/env python3
"""Runs `bedrock slim` over every image in corpus/corpus.toml.

PASS means the run exited 0 and the pruned image verified. Writes
results.json and results.md to --out. Needs Linux with ptrace (run as root
in CI), a Bedrock binary, and network access to pull the images.
Standard library only (Python 3.11+ for tomllib).
"""
import argparse
import json
import pathlib
import subprocess
import sys
import time
import tomllib


def run_entry(bedrock, root, out, e, timeout):
    work = out / e["name"]
    work.mkdir(parents=True, exist_ok=True)
    image_dir, report = work / "image", work / "report.json"
    if image_dir.exists():
        subprocess.run(["rm", "-rf", str(image_dir)], check=True)
    cmd = [bedrock, "slim", e["image"], "-o", str(image_dir), "--report", str(report)]
    if "http" in e:
        cmd += ["--workload-http", str(root / e["http"]), "--ready-port", str(e["ready_port"])]
    else:
        cmd += ["--workload-duration", e["duration"]]
    if e.get("cmd"):
        cmd += ["--"] + e["cmd"]
    started = time.time()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        code, err = p.returncode, p.stderr.strip().splitlines()
    except subprocess.TimeoutExpired:
        code, err = 124, ["timed out"]
    row = {"name": e["name"], "image": e["image"], "exit": code,
           "seconds": round(time.time() - started, 1), "note": err[-1][:160] if err and code else ""}
    if report.exists():
        r = json.loads(report.read_text())
        i, o = r["input"], r.get("output") or {}
        f = lambda s: sum(s.values()) if s else 0
        row.update(
            size_before=i["size_bytes"], size_after=o.get("size_bytes"),
            size_pct=(r.get("delta") or {}).get("size_pct"),
            packages_before=i["packages"], packages_after=o.get("packages"),
            findings_before=f(i.get("findings_by_severity")),
            findings_after=f(o.get("findings_by_severity")),
            verify=(r.get("verify") or {}).get("status"),
            reached_files=(r.get("trace") or {}).get("reached_files"),
            total_files=(r.get("trace") or {}).get("total_files"),
        )
    row["status"] = "PASS" if code == 0 and row.get("verify") == "pass" else "FAIL"
    return row


def table(rows):
    mb = lambda n: "n/a" if n is None else f"{n / 1048576:.1f}"
    lines = ["| Entry | Image | Result | Size MB | Change | Packages | Findings | Files reached | Notes |",
             "|---|---|---|---:|---:|---:|---:|---:|---|"]
    for r in rows:
        pct = "n/a" if r.get("size_pct") is None else f"{r['size_pct']:+.1f}%"
        files = f"{r['reached_files']}/{r['total_files']}" if r.get("reached_files") is not None else "n/a"
        lines.append(
            f"| {r['name']} | `{r['image']}` | **{r['status']}** | {mb(r.get('size_before'))} to {mb(r.get('size_after'))} | {pct} | "
            f"{r.get('packages_before', 'n/a')} to {r.get('packages_after', 'n/a')} | "
            f"{r.get('findings_before', 'n/a')} to {r.get('findings_after', 'n/a')} | {files} | {r['note']} |")
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bedrock", default="target/release/bedrock")
    ap.add_argument("--corpus", default="corpus/corpus.toml")
    ap.add_argument("--out", default="corpus-out")
    ap.add_argument("--only", help="comma-separated entry names")
    ap.add_argument("--timeout", type=int, default=900, help="seconds per image")
    ap.add_argument("--min-pass", type=int, default=0, help="exit 1 if fewer entries pass")
    a = ap.parse_args()

    corpus = pathlib.Path(a.corpus)
    entries = tomllib.loads(corpus.read_text())["image"]
    if a.only:
        wanted = set(a.only.split(","))
        entries = [e for e in entries if e["name"] in wanted]
    out = pathlib.Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    rows = []
    for e in entries:
        print(f"== {e['name']} ({e['image']})", flush=True)
        row = run_entry(a.bedrock, corpus.parent, out, e, a.timeout)
        print(f"   {row['status']} in {row['seconds']}s {row['note']}", flush=True)
        rows.append(row)
    (out / "results.json").write_text(json.dumps(rows, indent=2))
    md = table(rows)
    (out / "results.md").write_text(md)
    passed = sum(r["status"] == "PASS" for r in rows)
    print(f"\n{passed}/{len(rows)} PASS\n\n{md}")
    sys.exit(0 if passed >= a.min_pass else 1)


if __name__ == "__main__":
    main()
