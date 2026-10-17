#!/usr/bin/env python3
"""Exercise real CLI SIGINT cancellation and record sanitized structured traces."""

import argparse
import hashlib
import json
import select
import signal
import subprocess
import tempfile
import time
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve()
    with tempfile.TemporaryDirectory(prefix="sediment-trace-") as directory:
        root = Path(directory)
        source = root / "private-synthetic-input.bin"
        # Large enough to interrupt after the actual compression phase begins.
        with source.open("wb") as stream:
            block = bytes(range(256)) * 4096
            for _ in range(128):
                stream.write(block)
        archive = root / "private-synthetic-output.zip"
        process = subprocess.Popen(
            [str(binary), "--trace", "--json", "create", str(archive), str(source)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        events, pending, sent = [], b"", False
        deadline = time.monotonic() + 30
        try:
            while time.monotonic() < deadline and not sent:
                readable, _, _ = select.select([process.stderr], [], [], 0.2)
                if not readable:
                    if process.poll() is not None:
                        break
                    continue
                # read1 avoids waiting for a full buffer while the process is live.
                chunk = process.stderr.read1(65536)
                if not chunk:
                    break
                pending += chunk
                while b"\n" in pending:
                    line, pending = pending.split(b"\n", 1)
                    event = json.loads(line)
                    events.append(event)
                    if event.get("fields", {}).get("phase") == "Compressing":
                        process.send_signal(signal.SIGINT)
                        sent = True
            stdout, remaining = process.communicate(timeout=10)
        except BaseException:
            process.kill()
            process.communicate()
            raise
        for line in (pending + remaining).splitlines():
            events.append(json.loads(line))
        if not sent or process.returncode != 130 or stdout or archive.exists():
            raise RuntimeError("Cancellation did not preserve the CLI/output contract")
        if sorted(p.name for p in root.iterdir()) != [source.name]:
            raise RuntimeError("Cancellation left staging files behind")
        serialized = json.dumps(events)
        if "private-synthetic" in serialized or str(root) in serialized:
            raise RuntimeError("Trace disclosed fixture names")
        report = {
            "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "signal": "SIGINT after Compressing phase",
            "exit_code": process.returncode,
            "published_output": False,
            "staging_leftovers": False,
            "events": events,
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n")
        print(
            "SIGINT: exit 130, no output published, no staging files, no paths in trace"
        )


if __name__ == "__main__":
    main()
