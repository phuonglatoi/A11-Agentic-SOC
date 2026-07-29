from docx import Document


doc = Document(r"outputs\Bao_cao_TTTN_A11_Agentic_SOC.docx")
for index in range(220, 266):
    paragraph = doc.paragraphs[index]
    drawings = len(paragraph._p.xpath(".//w:drawing"))
    extents = [
        (element.get("cx"), element.get("cy"))
        for element in paragraph._p.xpath(".//wp:extent")
    ]
    print(
        f"{index:03d} [{paragraph.style.name}] "
        f"{paragraph.text[:300]!r} drawings={drawings} extents={extents}"
    )
