#!/usr/bin/env python3
"""Collect license texts from the locked Cargo registry; keep upstream supplements separate."""

import json
import subprocess
from pathlib import Path


def main():
    root = Path(__file__).resolve().parent.parent
    metadata = json.loads(
        subprocess.check_output(
            ["cargo", "metadata", "--locked", "--format-version", "1"], cwd=root
        )
    )
    sections = [
        "# Third-party dependency notices\n",
        "Generated from Cargo.lock and local crate license files. Includes all resolved platforms, some of which are not linked into the macOS app. License expressions retain upstream choices. Additional exact-commit upstream notices are in [docs/UPSTREAM_LICENSES.md](docs/UPSTREAM_LICENSES.md). Missing local license files are identified rather than silently omitted.\n",
    ]
    missing = []
    for package in sorted(
        metadata["packages"], key=lambda item: (item["name"], item["version"])
    ):
        if package["source"] is None:
            continue
        base = Path(package["manifest_path"]).parent
        paths = set()
        if package.get("license_file"):
            paths.add(base / package["license_file"])
        for path in base.rglob("*"):
            name = path.name.lower()
            if (
                path.is_file()
                and path.suffix.lower()
                not in (".rs", ".c", ".h", ".html", ".svg", ".png")
                and (
                    name.startswith(("license", "licence", "copying", "copyright"))
                    or name in ("ofl.txt", "ufl.txt")
                )
            ):
                paths.add(path)
        sections.extend(
            [
                f"## {package['name']} {package['version']}\n",
                f"License: {package.get('license') or 'See upstream license file'}\n",
                f"Source: {package.get('repository') or package['source']}\n",
            ]
        )
        for path in sorted(paths):
            if not path.is_file():
                continue
            sections.extend(
                [
                    f"### {path.relative_to(base)}\n",
                    "```text\n" + path.read_text(errors="replace") + "\n```\n",
                ]
            )
        if not paths:
            missing.append(f"{package['name']} {package['version']}")
            sections.append(
                "No standalone license file in the published crate. See the supplemental upstream notices and the source repository.\n"
            )
    (root / "THIRD_PARTY_NOTICES.md").write_text("\n".join(sections))
    print(
        f"Collected {len(metadata['packages'])} packages; {len(missing)} omit standalone license files (including supplemental families/platform-only dependencies)."
    )


if __name__ == "__main__":
    main()
