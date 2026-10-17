#!/usr/bin/env python3
"""Generate sediment's original geometric strata icon; requires Pillow and macOS iconutil."""

from pathlib import Path
import subprocess
import tempfile
from PIL import Image, ImageDraw

root = Path(__file__).resolve().parent.parent
assets = root / "assets"
assets.mkdir(exist_ok=True)
image = Image.new("RGBA", (1024, 1024))
draw = ImageDraw.Draw(image)
draw.rounded_rectangle(
    (80, 80, 944, 944),
    radius=192,
    fill=(247, 246, 240),
    outline=(220, 224, 214),
    width=4,
)
for y in (330, 500, 670):
    draw.line(
        [(258, y), (512, y + 100), (766, y)],
        fill=(36, 103, 87),
        width=44,
        joint="curve",
    )
    for x, yy in [(258, y), (512, y + 100), (766, y)]:
        draw.ellipse((x - 22, yy - 22, x + 22, yy + 22), fill=(36, 103, 87))
image.save(assets / "sediment.png")
image.resize((64, 64), Image.Resampling.LANCZOS).tobytes()
(assets / "icon-64.rgba").write_bytes(
    image.resize((64, 64), Image.Resampling.LANCZOS).tobytes()
)
with tempfile.TemporaryDirectory() as temp:
    iconset = Path(temp) / "sediment.iconset"
    iconset.mkdir()
    for size in (16, 32, 128, 256, 512):
        for scale in (1, 2):
            suffix = "@2x" if scale == 2 else ""
            image.resize((size * scale, size * scale), Image.Resampling.LANCZOS).save(
                iconset / f"icon_{size}x{size}{suffix}.png"
            )
    subprocess.run(
        ["iconutil", "-c", "icns", str(iconset), "-o", str(assets / "sediment.icns")],
        check=True,
    )
