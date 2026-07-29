from __future__ import annotations

import sys
from pathlib import Path


DEPENDENCIES = Path("qa_deps")
sys.path.insert(0, str(DEPENDENCIES))

import fitz  # type: ignore  # noqa: E402
from PIL import Image, ImageDraw, ImageFont  # noqa: E402


def main() -> None:
    print(
        "fitz=",
        getattr(fitz, "__file__", None),
        getattr(fitz, "__path__", None),
        "sys.path[:3]=",
        sys.path[:3],
    )
    pdf_path = Path(
        ".work/report/local_first_render_v5/"
        "Bao_cao_TTTN_A11_Agentic_SOC_Local_First.pdf"
    )
    output_dir = Path(".work/report/local_first_render_v5/pages")
    output_dir.mkdir(parents=True, exist_ok=True)

    document = fitz.open(pdf_path)
    matrix = fitz.Matrix(150 / 72, 150 / 72)
    page_paths: list[Path] = []
    for index, page in enumerate(document):
        pixmap = page.get_pixmap(matrix=matrix, alpha=False)
        page_path = output_dir / f"page-{index + 1:03d}.png"
        pixmap.save(page_path)
        page_paths.append(page_path)

    label_font = ImageFont.truetype(r"C:\Windows\Fonts\arialbd.ttf", 28)
    for start in range(0, len(page_paths), 5):
        subset = page_paths[start : start + 5]
        resized: list[Image.Image] = []
        for page_number, page_path in enumerate(subset, start=start + 1):
            source = Image.open(page_path).convert("RGB")
            ratio = 1240 / source.width
            page_image = source.resize(
                (1240, int(source.height * ratio)),
                Image.Resampling.LANCZOS,
            )
            canvas = Image.new(
                "RGB",
                (1240, page_image.height + 48),
                "white",
            )
            draw = ImageDraw.Draw(canvas)
            draw.text(
                (18, 8),
                f"Trang PDF {page_number}",
                font=label_font,
                fill="#A11D33",
            )
            canvas.paste(page_image, (0, 48))
            resized.append(canvas)
        height = sum(item.height for item in resized) + 24 * (len(resized) - 1)
        sheet = Image.new("RGB", (1240, height), "#CBD5E1")
        y = 0
        for item in resized:
            sheet.paste(item, (0, y))
            y += item.height + 24
        sheet.save(
            output_dir / f"sheet-{start + 1:03d}-{start + len(subset):03d}.jpg",
            quality=90,
        )
    print(f"pages={len(page_paths)}")
    print(output_dir.resolve())


if __name__ == "__main__":
    main()
