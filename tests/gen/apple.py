#!/usr/bin/env python3
"""Generate Apple-format fixtures (LZFSE/LZVN frames, LZFSE zip, UDIF DMGs).

Oracles: Apple's libcompression (COMPRESSION_LZFSE via ctypes, stdlib) for
LZFSE/LZVN frames, Python zipfile for the zip container, and `hdiutil`
(macOS) for the DMG images. Run on macOS:  python3 tests/gen/apple.py
Writes tests/fixtures/apple/. Decoded payloads are recorded as size + SHA-256 manifests
so the Rust tests compare byte-for-byte without storing the raw data.
"""
import ctypes, hashlib, io, json, os, pathlib, random, shutil, struct, subprocess, sys, tempfile, zipfile, zlib

OUT = pathlib.Path(__file__).resolve().parent.parent / 'fixtures' / 'apple'
COMPRESSION_LZFSE = 0x801

def lzfse(data):
    lib = ctypes.CDLL('libcompression.dylib')
    f = lib.compression_encode_buffer
    f.restype = ctypes.c_size_t
    f.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_int]
    out = ctypes.create_string_buffer(len(data) * 2 + 4096)
    n = f(out, len(out), data, len(data), None, COMPRESSION_LZFSE)
    if n == 0 and data:
        raise RuntimeError('lzfse encode failed')
    return out.raw[:n]

def text(n, seed):
    r = random.Random(seed)
    words = [''.join(r.choice('abcdefghijklmnopqrstuvwxyz') for _ in range(r.randint(2, 9))) for _ in range(300)]
    s = []
    total = 0
    while total < n:
        w = r.choice(words) + r.choice(' \n ,.')
        s.append(w)
        total += len(w)
    return ''.join(s).encode()[:n]

def goodput_tree():
    """Must match tree() in /tmp/sed-plan/impl/goodput.py."""
    return {'a.txt': b'hello sediment\n' * 50, 'bin/data.bin': bytes(range(256)) * 40,
            'empty': b'', 'deep/x/y/z.txt': b'nested\n', 'café.txt': 'unicode ok\n'.encode()}

def lzfse_zip(files, path):
    """Zip whose non-empty entries use method 99 with an LZFSE payload (no AES extra)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_STORED) as z:
        for n, d in files.items():
            z.writestr(n, d)
    # Rebuild with LZFSE payloads.
    src = zipfile.ZipFile(io.BytesIO(buf.getvalue()))
    out = bytearray()
    central = bytearray()
    for info in src.infolist():
        data = src.read(info)
        comp = lzfse(data) if data else b''
        method = 99 if data else 0
        name = info.filename.encode('utf-8')
        flags = 0x800
        off = len(out)
        out += struct.pack('<IHHHHHIIIHH', 0x04034b50, 20, flags, method, 0, 0x21, zlib.crc32(data), len(comp), len(data), len(name), 0) + name + comp
        central += struct.pack('<IHHHHHHIIIHHHHHII', 0x02014b50, 0x31e, 20, flags, method, 0, 0x21, zlib.crc32(data), len(comp), len(data), len(name), 0, 0, 0, 0, 0o100644 << 16, off) + name
    cd = len(out)
    out += central
    n = len(src.infolist())
    out += struct.pack('<IHHHHIIH', 0x06054b50, 0, 0, n, n, len(central), cd, 0)
    path.write_bytes(bytes(out))

def make_dmg(files, path, fmt, extra=()):
    with tempfile.TemporaryDirectory() as t:
        src = pathlib.Path(t) / 'src'
        for n, d in files.items():
            p = src / n
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(d)
        if path.exists():
            path.unlink()
        subprocess.run(['hdiutil', 'create', '-quiet', '-srcfolder', str(src), '-fs', 'HFS+', '-volname', 'SED',
                        '-format', fmt, *extra, str(path)], check=True)

def main():
    OUT.mkdir(parents=True, exist_ok=True)
    cases = {
        'empty': b'',
        'one': b'x',
        'small_text': text(300, 1),
        'lzvn_text': text(3500, 2),
        'lzfse_text': text(30000, 3),
        'lzvn_1k': text(1000, 8),
        'lzvn_rep': (b'abcabcabd' * 300)[:2700] + bytes(range(200)) * 3,
        'lzvn_long': b'Q' * 1500 + text(2000, 9) + b'Z' * 500,
        'lzfse_bin': bytes((i * 7 + (i >> 5)) & 0xff for i in range(20000)) + text(9000, 4),
        'random': random.Random(5).randbytes(5000),
        'multi_block': text(100000, 6) + b'\0' * 30000,
    }
    manifest = {}
    for name, data in cases.items():
        comp = lzfse(data)
        (OUT / f'{name}.lzfse').write_bytes(comp)
        manifest[name] = {'size': len(data), 'sha256': hashlib.sha256(data).hexdigest(), 'magic': comp[:4].decode('latin1')}
    (OUT / 'lzfse_manifest.json').write_text(json.dumps(manifest, indent=1, sort_keys=True) + '\n')
    files = goodput_tree()
    lzfse_zip(files, OUT / 'goodput_lzfse.zip')
    make_dmg(files, OUT / 'goodput_udzo.dmg', 'UDZO')
    big = dict(files)
    big['big/text.txt'] = text(20000, 7) + b'\0' * 40000
    for fmt in ('ULFO', 'UDBZ', 'ULMO'):
        make_dmg(big, OUT / f'tree_{fmt.lower()}.dmg', fmt)
    tree_manifest = {n: hashlib.sha256(d).hexdigest() for n, d in big.items()}
    (OUT / 'tree_manifest.json').write_text(json.dumps(tree_manifest, indent=1, sort_keys=True, ensure_ascii=False) + '\n')

if __name__ == '__main__':
    main()
