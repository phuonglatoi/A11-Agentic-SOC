from __future__ import annotations

import argparse
import sys
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("pdf")
    parser.add_argument("output_dir")
    parser.add_argument("--dpi", type=int, default=150)
    parser.add_argument("--sheet_pages", type=int, default=5)
    args = parser.parse_args()

    sys.path.insert(0, str(Path("work/pydeps").resolve()))
    import fitz  # type: ignore
    from PIL import Image, ImageDraw, ImageFont

    pdf_path = Path(args.pdf).resolve()
    out_dir = Path(args.output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"pymupdf={getattr(fitz, '__file__', 'unknown')}")
    document = fitz.open(str(pdf_path))

    page_paths: list[Path] = []
    zoom = args.dpi / 72
    matrix = fitz.Matrix(zoom, zoom)
    for index, page in enumerate(document):
        pixmap = page.get_pixmap(matrix=matrix, alpha=False)
        page_path = out_dir / f"page-{index + 1:03d}.png"
        pixmap.save(page_path)
        page_paths.append(page_path)

    label_font = ImageFont.truetype(r"C:\Windows\Fonts\arialbd.ttf", 28)
    for start in range(0, len(page_paths), args.sheet_pages):
        subset = page_paths[start : start + args.sheet_pages]
        images = [Image.open(path).convert("RGB") for path in subset]
        target_width = 1240
        resized = []
        for page_number, image in enumerate(images, start=start + 1):
            ratio = target_width / image.width
            page_image = image.resize(
                (target_width, int(image.height * ratio)),
                Image.Resampling.LANCZOS,
            )
            canvas = Image.new("RGB", (target_width, page_image.height + 48), "white")
            draw = ImageDraw.Draw(canvas)
            draw.text((18, 8), f"Trang PDF {page_number}", font=label_font, fill="#A11D33")
            canvas.paste(page_image, (0, 48))
            resized.append(canvas)
        sheet_height = sum(image.height for image in resized) + 24 * (len(resized) - 1)
        sheet = Image.new("RGB", (target_width, sheet_height), "#CBD5E1")
        y = 0
        for image in resized:
            sheet.paste(image, (0, y))
            y += image.height + 24
        end = start + len(subset)
        sheet.save(out_dir / f"sheet-{start + 1:03d}-{end:03d}.jpg", quality=90)

    print(f"pages={len(page_paths)}")
    print(out_dir)


if __name__ == "__main__":
    main()
