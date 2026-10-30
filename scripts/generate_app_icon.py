"""
Generates production Windows icon (.ico) and PNG icon for KOTH Command.
Outputs to: desktop/build/icon.ico and desktop/build/icon.png
"""

import math
from pathlib import Path
from PIL import Image, ImageDraw

ROOT_DIR = Path(__file__).resolve().parent.parent
BUILD_DIR = ROOT_DIR / "desktop" / "build"
BUILD_DIR.mkdir(parents=True, exist_ok=True)

def create_koth_icon(size=256):
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Margins
    margin = size * 0.08
    cx, cy = size / 2, size / 2

    # Draw Shield shape
    # Shield points: top-left, top-right, bottom-middle curve
    w = size - 2 * margin
    h = size - 2 * margin
    x0, y0 = margin, margin
    x1, y1 = margin + w, margin + h

    shield_pts = [
        (x0 + w * 0.1, y0),
        (x1 - w * 0.1, y0),
        (x1, y0 + h * 0.35),
        (x1 - w * 0.15, y0 + h * 0.75),
        (cx, y1),
        (x0 + w * 0.15, y0 + h * 0.75),
        (x0, y0 + h * 0.35),
    ]

    # Draw outer shadow / glow
    draw.polygon(shield_pts, fill=(23, 37, 54, 255))

    # Inner shield inset
    inset = size * 0.04
    inner_pts = [
        (shield_pts[0][0] + inset * 0.5, shield_pts[0][1] + inset),
        (shield_pts[1][0] - inset * 0.5, shield_pts[1][1] + inset),
        (shield_pts[2][0] - inset, shield_pts[2][1] + inset * 0.2),
        (shield_pts[3][0] - inset, shield_pts[3][1] - inset * 0.5),
        (cx, shield_pts[4][1] - inset * 1.2),
        (shield_pts[5][0] + inset, shield_pts[5][1] - inset * 0.5),
        (shield_pts[6][0] + inset, shield_pts[6][1] + inset * 0.2),
    ]
    draw.polygon(inner_pts, fill=(40, 120, 200, 255))

    # Draw a stylized mountain / hill inside
    hill_pts = [
        (cx, cy - size * 0.12),
        (cx + size * 0.24, cy + size * 0.22),
        (cx - size * 0.24, cy + size * 0.22),
    ]
    draw.polygon(hill_pts, fill=(234, 243, 255, 255))

    # Inner crown / beacon on the hill
    beacon_center = (cx, cy - size * 0.16)
    r = size * 0.045
    draw.ellipse(
        [beacon_center[0] - r, beacon_center[1] - r, beacon_center[0] + r, beacon_center[1] + r],
        fill=(107, 173, 235, 255),
        outline=(255, 255, 255, 255),
        width=int(size * 0.015),
    )

    return img

def main():
    png_path = BUILD_DIR / "icon.png"
    ico_path = BUILD_DIR / "icon.ico"

    img_256 = create_koth_icon(256)
    img_256.save(png_path, format="PNG")

    # Generate multi-size ICO
    sizes = [(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)]
    ico_images = [img_256.resize(s, Image.Resampling.LANCZOS) for s in sizes]
    ico_images[0].save(ico_path, format="ICO", sizes=sizes)

    print(f"[+] Generated {png_path} and {ico_path}")

if __name__ == "__main__":
    main()

