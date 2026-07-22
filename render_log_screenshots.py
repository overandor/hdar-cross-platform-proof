#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


def main() -> int:
    parser = argparse.ArgumentParser(description="Render a text log as headless PNG screenshots")
    parser.add_argument("--input", required=True, help="Log file to render")
    parser.add_argument("--out-dir", required=True, help="Output directory for PNG files")
    parser.add_argument("--prefix", default="log", help="Output filename prefix")
    parser.add_argument("--lines-per-image", type=int, default=56)
    args = parser.parse_args()

    raw_lines = Path(args.input).read_text(errors="replace").splitlines() or ["(empty log)"]
    lines = [
        re.sub(r"e2b_[A-Za-z0-9]+|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+", "[REDACTED]", line)
        for line in raw_lines
    ]
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    try:
        font = ImageFont.truetype("/System/Library/Fonts/Menlo.ttc", 16)
    except OSError:
        font = ImageFont.load_default()

    width = 1800
    line_height = 24
    margin = 28
    page_count = 0
    for start in range(0, len(lines), args.lines_per_image):
        page = lines[start : start + args.lines_per_image]
        height = margin * 2 + line_height * (len(page) + 2)
        image = Image.new("RGB", (width, height), "#0d1117")
        draw = ImageDraw.Draw(image)
        draw.text((margin, margin), f"{Path(args.input).name} — lines {start + 1}-{start + len(page)}", font=font, fill="#58a6ff")
        for index, line in enumerate(page, start=1):
            text = f"{start + index:04d}  {line}"[:210]
            draw.text((margin, margin + line_height * (index + 1)), text, font=font, fill="#c9d1d9")
        page_count += 1
        image.save(out_dir / f"{args.prefix}_{page_count:03d}.png")

    print(f"Rendered {page_count} screenshot(s) from {args.input}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
