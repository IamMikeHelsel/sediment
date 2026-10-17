#!/usr/bin/env python3
"""Deterministic, host-specific archive benchmark; timings are observations, not gates."""

import argparse
import hashlib
import json
import platform
import random
import statistics
import subprocess
import tarfile
import tempfile
import time
import zipfile
from pathlib import Path


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tree(root):
    return {
        p.relative_to(root).as_posix(): digest(p)
        for p in sorted(root.rglob("*"))
        if p.is_file()
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--compare", type=Path)
    parser.add_argument("--repeats", type=int, default=3)
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("--repeats must be positive")
    binary = args.binary.resolve()
    results = {}
    with tempfile.TemporaryDirectory(prefix="sediment-benchmark-") as temporary:
        root = Path(temporary)
        source = root / "collection"
        source.mkdir()
        rng = random.Random(20261017)
        for i in range(1000):
            folder = source / f"group-{i // 100:02}"
            folder.mkdir(exist_ok=True)
            (folder / f"file-{i:04}.txt").write_bytes(
                (f"sediment fixture {i:04}\n" * 20).encode()
            )
        (source / "mixed.bin").write_bytes(
            rng.randbytes(8 * 1024 * 1024)
            + b"sediment archive fixture\n" * (8 * 1024 * 1024 // 25)
            + b"\0" * (8 * 1024 * 1024 % 25)
        )
        # Exactly 16 MiB: half pseudorandom, half repetitive.
        mixed = source / "mixed.bin"
        content = mixed.read_bytes()
        mixed.write_bytes((content + b"\0" * (16 * 1024 * 1024))[: 16 * 1024 * 1024])
        expected = {"collection/" + name: sha for name, sha in tree(source).items()}
        zip_path, tar_path = root / "input.zip", root / "input.tar.gz"
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as archive:
            for p in sorted(source.rglob("*")):
                archive.write(p, p.relative_to(root))
        with tarfile.open(tar_path, "w:gz") as archive:
            archive.add(source, arcname="collection")

        def run(key, argv, validate=lambda: None):
            samples = []
            for repeat in range(args.repeats):
                command = argv(repeat)
                started = time.perf_counter()
                subprocess.run(
                    [str(binary), *map(str, command)],
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                )
                samples.append(time.perf_counter() - started)
                validate(repeat)
            results[key] = {
                "seconds": samples,
                "median_seconds": statistics.median(samples),
                "correctness": "passed",
            }

        for kind, archive in [("zip", zip_path), ("tar_gz", tar_path)]:
            run(kind + "_list", lambda _: ["list", archive], lambda _: None)
            run(kind + "_test", lambda _: ["test", archive], lambda _: None)

            def validate_extract(i, prefix=kind):
                actual = tree(root / f"{prefix}-out-{i}")
                if actual != expected:
                    raise RuntimeError(
                        "Extracted tree does not match source SHA-256 manifest"
                    )

            run(
                kind + "_extract",
                lambda i, a=archive, k=kind: ["extract", a, root / f"{k}-out-{i}"],
                validate_extract,
            )

        def validate_created(i):
            with zipfile.ZipFile(root / f"created-{i}.zip") as archive:
                if archive.testzip() is not None:
                    raise RuntimeError("Created ZIP failed independent CRC validation")
                actual = {
                    name: hashlib.sha256(archive.read(name)).hexdigest()
                    for name in archive.namelist()
                    if not name.endswith("/")
                }
            if actual != expected:
                raise RuntimeError("Created ZIP contents differ from source manifest")

        run(
            "zip_create",
            lambda i: ["create", root / f"created-{i}.zip", source],
            validate_created,
        )
        report = {
            "schema": 1,
            "platform": platform.platform(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "binary_sha256": digest(binary),
            "binary_version": subprocess.check_output(
                [str(binary), "--version"], text=True
            ).strip(),
            "repeats": args.repeats,
            "workload": {
                "small_files": 1000,
                "mixed_bytes": 16 * 1024 * 1024,
                "seed": 20261017,
                "files": len(expected),
                "manifest_sha256": hashlib.sha256(
                    json.dumps(expected, sort_keys=True).encode()
                ).hexdigest(),
            },
            "results": results,
            "limitations": "Generated fixture data is warm; executable cache may be cold on first sample. Sequential runs, process startup included. No hardware-independent timing gate. Archive byte hashes are not compared because metadata varies; extracted payload SHA-256 hashes are compared.",
        }
        if args.compare:
            baseline = json.loads(args.compare.read_text())
            if baseline["workload"] != report["workload"]:
                raise RuntimeError("Baseline workload differs")
            report["comparison"] = {
                key: {
                    "baseline_median_seconds": baseline["results"][key][
                        "median_seconds"
                    ],
                    "ratio_after_over_before": row["median_seconds"]
                    / baseline["results"][key]["median_seconds"],
                }
                for key, row in results.items()
            }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n")
        print(
            json.dumps(
                {key: round(row["median_seconds"], 4) for key, row in results.items()},
                indent=2,
            )
        )


if __name__ == "__main__":
    main()
