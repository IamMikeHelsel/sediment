#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""List-file fixtures for tests/cli_compat_cli.rs (7-Zip `@listfile`, `-scs`).

Python stdlib only; the encodings come from Python's codecs (the oracle for
UTF-8 / UTF-16LE / UTF-16BE). Output is deterministic.

Usage (from the repo root): python3 -I tests/gen/cli_compat.py
Writes tests/fixtures/cli_compat/lists/:
  names.utf8.lst          UTF-8, no BOM, LF
  names.utf8bom.lst       UTF-8 with BOM, CRLF
  names.utf16le.lst       UTF-16LE with BOM, CRLF
  names.utf16le-nobom.lst UTF-16LE without BOM (needs -scsUTF-16LE)
  names.utf16be.lst       UTF-16BE with BOM (needs -scsUTF-16BE)
  bad.utf8.lst            invalid UTF-8
  nul.lst                 contains U+0000
All valid lists name the same members of tests/fixtures/cli_wire/tree.
"""
import os
import sys

sys.dont_write_bytecode = True
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "fixtures", "cli_compat", "lists")
NAMES = ["hello.txt", "  docs/café.txt\t", "", "data/*.bin"]


def write(name, data):
    with open(os.path.join(OUT, name), "wb") as f:
        f.write(data)


def main():
    os.makedirs(OUT, exist_ok=True)
    lf = "\n".join(NAMES) + "\n"
    crlf = "\r\n".join(NAMES) + "\r\n"
    write("names.utf8.lst", lf.encode("utf-8"))
    write("names.utf8bom.lst", crlf.encode("utf-8-sig"))
    write("names.utf16le.lst", b"\xff\xfe" + crlf.encode("utf-16-le"))
    write("names.utf16le-nobom.lst", crlf.encode("utf-16-le"))
    write("names.utf16be.lst", b"\xfe\xff" + crlf.encode("utf-16-be"))
    write("bad.utf8.lst", b"hello.txt\n\xff\xfe\xfd\n")
    write("nul.lst", b"hello.txt\x00\n")


main()
