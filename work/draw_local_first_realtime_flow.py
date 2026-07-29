from __future__ import annotations

import math
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


OUT = Path(
    "report_assets/diagrams/so_do_2_3_luong_real_time_local_first.png"
)
WIDTH, HEIGHT = 1800, 2300

NAVY = "#123653"
INK = "#193047"
MUTED = "#557086"
BLUE = "#2375B8"
CYAN = "#2D9AB7"
GREEN = "#278B68"
AMBER = "#D48616"
RED = "#C24656"
SLATE = "#667A8C"
WHITE = "#FFFFFF"
CANVAS = "#F4F7FA"
PANEL = "#FFFFFF"
BORDER = "#B9CAD6"
LIGHT_BLUE = "#EAF4FB"
LIGHT_GREEN = "#E9F6F0"
LIGHT_AMBER = "#FFF4E2"
LIGHT_RED = "#FDECEF"
LIGHT_SLATE = "#EFF3F6"

FONT_REGULAR = r"C:\Windows\Fonts\arial.ttf"
FONT_BOLD = r"C:\Windows\Fonts\arialbd.ttf"


def font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(FONT_BOLD if bold else FONT_REGULAR, size)


def wrap_text(
    draw: ImageDraw.ImageDraw,
    text: str,
    text_font: ImageFont.FreeTypeFont,
    max_width: int,
) -> list[str]:
    lines: list[str] = []
    for raw_line in text.split("\n"):
        if not raw_line:
            lines.append("")
            continue
        words = raw_line.split()
        current = ""
        for word in words:
            candidate = word if not current else f"{current} {word}"
            if draw.textbbox((0, 0), candidate, font=text_font)[2] <= max_width:
                current = candidate
            else:
                if current:
                    lines.append(current)
                current = word
        if current:
            lines.append(current)
    return lines


def draw_wrapped(
    draw: ImageDraw.ImageDraw,
    xy: tuple[int, int],
    text: str,
    text_font: ImageFont.FreeTypeFont,
    fill: str,
    max_width: int,
    spacing: int = 6,
) -> None:
    x, y = xy
    line_height = draw.textbbox((0, 0), "Ag", font=text_font)[3] + spacing
    for line in wrap_text(draw, text, text_font, max_width):
        draw.text((x, y), line, font=text_font, fill=fill)
        y += line_height


def rounded_box(
    draw: ImageDraw.ImageDraw,
    rect: tuple[int, int, int, int],
    title: str,
    body: str,
    accent: str,
    *,
    fill: str = PANEL,
    title_size: int = 28,
    body_size: int = 23,
) -> None:
    x1, y1, x2, y2 = rect
    draw.rounded_rectangle(rect, radius=18, fill=fill, outline=BORDER, width=3)
    draw.rounded_rectangle((x1, y1, x1 + 13, y2), radius=9, fill=accent)
    draw.text((x1 + 31, y1 + 18), title, font=font(title_size, True), fill=INK)
    draw_wrapped(
        draw,
        (x1 + 31, y1 + 60),
        body,
        font(body_size),
        MUTED,
        x2 - x1 - 58,
    )


def arrow(
    draw: ImageDraw.ImageDraw,
    start: tuple[int, int],
    end: tuple[int, int],
    color: str = BLUE,
    *,
    width: int = 7,
    label: str | None = None,
    label_offset: int = -40,
) -> None:
    draw.line((start, end), fill=color, width=width)
    angle = math.atan2(end[1] - start[1], end[0] - start[0])
    head, wing = 18, 10
    p2 = (
        end[0] - head * math.cos(angle) + wing * math.sin(angle),
        end[1] - head * math.sin(angle) - wing * math.cos(angle),
    )
    p3 = (
        end[0] - head * math.cos(angle) - wing * math.sin(angle),
        end[1] - head * math.sin(angle) + wing * math.cos(angle),
    )
    draw.polygon((end, p2, p3), fill=color)
    if label:
        label_font = font(19, True)
        bbox = draw.textbbox((0, 0), label, font=label_font)
        w = bbox[2] - bbox[0] + 24
        h = bbox[3] - bbox[1] + 14
        cx = (start[0] + end[0]) // 2
        cy = (start[1] + end[1]) // 2 + label_offset
        draw.rounded_rectangle(
            (cx - w // 2, cy - h // 2, cx + w // 2, cy + h // 2),
            radius=9,
            fill=WHITE,
            outline=BORDER,
            width=2,
        )
        draw.text(
            (cx - (bbox[2] - bbox[0]) // 2, cy - (bbox[3] - bbox[1]) // 2 - 2),
            label,
            font=label_font,
            fill=color,
        )


def dashed_arrow(
    draw: ImageDraw.ImageDraw,
    start: tuple[int, int],
    end: tuple[int, int],
    color: str = SLATE,
    *,
    width: int = 5,
    dash: int = 16,
    gap: int = 11,
) -> None:
    x1, y1 = start
    x2, y2 = end
    distance = math.hypot(x2 - x1, y2 - y1)
    if distance == 0:
        return
    ux, uy = (x2 - x1) / distance, (y2 - y1) / distance
    pos = 0.0
    while pos < distance - 18:
        seg_end = min(pos + dash, distance - 18)
        draw.line(
            (
                x1 + ux * pos,
                y1 + uy * pos,
                x1 + ux * seg_end,
                y1 + uy * seg_end,
            ),
            fill=color,
            width=width,
        )
        pos += dash + gap
    angle = math.atan2(y2 - y1, x2 - x1)
    head, wing = 17, 9
    p2 = (
        x2 - head * math.cos(angle) + wing * math.sin(angle),
        y2 - head * math.sin(angle) - wing * math.cos(angle),
    )
    p3 = (
        x2 - head * math.cos(angle) - wing * math.sin(angle),
        y2 - head * math.sin(angle) + wing * math.cos(angle),
    )
    draw.polygon(((x2, y2), p2, p3), fill=color)


def section_panel(
    draw: ImageDraw.ImageDraw,
    y1: int,
    y2: int,
    number: str,
    title: str,
    accent: str,
) -> None:
    draw.rounded_rectangle(
        (35, y1, WIDTH - 35, y2),
        radius=24,
        fill=PANEL,
        outline="#D6E1E8",
        width=3,
    )
    draw.ellipse((58, y1 + 18, 112, y1 + 72), fill=accent)
    number_font = font(27, True)
    bbox = draw.textbbox((0, 0), number, font=number_font)
    draw.text(
        (
            85 - (bbox[2] - bbox[0]) // 2,
            y1 + 45 - (bbox[3] - bbox[1]) // 2 - 4,
        ),
        number,
        font=number_font,
        fill=WHITE,
    )
    draw.text((130, y1 + 22), title, font=font(31, True), fill=accent)
    draw.line((130, y1 + 70, WIDTH - 65, y1 + 70), fill="#DCE6EC", width=2)


def main() -> None:
    image = Image.new("RGB", (WIDTH, HEIGHT), CANVAS)
    draw = ImageDraw.Draw(image)

    draw.rectangle((0, 0, WIDTH, 150), fill=NAVY)
    draw.text(
        (55, 26),
        "LUỒNG XỬ LÝ SỰ KIỆN REAL-TIME LOCAL-FIRST CỦA A11 SOC",
        font=font(43, True),
        fill=WHITE,
    )
    draw.text(
        (58, 88),
        "Log đi trực tiếp vào Ubuntu SOC; Splunk chỉ là nhánh quan sát và đối chiếu tùy chọn",
        font=font(27),
        fill="#D7E8F5",
    )

    # 01 - Attack and protected assets.
    section_panel(draw, 175, 510, "01", "TẤN CÔNG VÀ PHÂN VÙNG MẠNG LAB", RED)
    topology = [
        (
            (65, 265, 430, 485),
            "KALI ATTACKER",
            "192.168.228.128/24\nWAN lab 192.168.228.0/24\nNmap TCP SYN • DIRB HTTP",
            RED,
            LIGHT_RED,
        ),
        (
            (515, 265, 895, 485),
            "OPNSENSE",
            "WAN 192.168.228.142/24\nLAN 192.168.1.1/24\nFirewall • NAT • Suricata",
            AMBER,
            LIGHT_AMBER,
        ),
        (
            (980, 265, 1345, 485),
            "WEB TARGET",
            "192.168.1.100/24\nApache TCP/80\naccess.log + EVE JSON",
            BLUE,
            LIGHT_BLUE,
        ),
        (
            (1430, 265, 1735, 485),
            "WINDOWS",
            "192.168.1.101/24\nSecurity Event\n4625 • 4688 • 1102",
            CYAN,
            LIGHT_BLUE,
        ),
    ]
    for rect, title, body, accent, fill in topology:
        rounded_box(
            draw,
            rect,
            title,
            body,
            accent,
            fill=fill,
            title_size=26,
            body_size=22,
        )
    arrow(draw, (435, 370), (505, 370), RED, width=5, label="TCP/HTTP")
    arrow(draw, (900, 370), (970, 370), AMBER, width=5, label="DNAT :80")

    # 02 - Direct local telemetry and optional Splunk observation.
    section_panel(draw, 535, 955, "02", "THU NHẬN TELEMETRY TRỰC TIẾP VỀ UBUNTU SOC", BLUE)
    sources = [
        (
            (65, 625, 385, 770),
            "OPNSENSE",
            "filterlog\nSyslog UDP/5514",
            AMBER,
        ),
        (
            (430, 625, 785, 770),
            "APACHE / SURICATA",
            "access.log + eve.json\nShipper → REST/HEC :8000",
            CYAN,
        ),
        (
            (830, 625, 1165, 770),
            "WINDOWS EVENT",
            "Collector/JSON\nREST/HEC TCP/8000",
            BLUE,
        ),
    ]
    for rect, title, body, accent in sources:
        rounded_box(
            draw,
            rect,
            title,
            body,
            accent,
            title_size=25,
            body_size=21,
        )
        center_x = (rect[0] + rect[2]) // 2
        arrow(draw, (center_x, rect[3] + 5), (center_x, 820), accent, width=5)

    draw.rounded_rectangle(
        (115, 820, 1190, 915), radius=17, fill=NAVY, outline=NAVY
    )
    draw.text(
        (145, 838),
        "UBUNTU A11 SOC 192.168.1.10  •  API/HEC 8000  •  SYSLOG 5514",
        font=font(25, True),
        fill=WHITE,
    )
    draw.text(
        (175, 873),
        "Container api + PostgreSQL + Dashboard + Ollama tùy chọn",
        font=font(22),
        fill="#D7E8F5",
    )

    rounded_box(
        draw,
        (1290, 625, 1735, 855),
        "SPLUNK — QUAN SÁT TÙY CHỌN",
        "Nhận bản sao raw log\nTìm kiếm • biểu đồ • đối chiếu\nKhông nằm trong critical path\nKhông cấp dữ liệu bắt buộc cho A11",
        SLATE,
        fill=LIGHT_SLATE,
        title_size=24,
        body_size=21,
    )
    dashed_arrow(draw, (1170, 700), (1280, 700), SLATE)
    draw.text(
        (1185, 658),
        "MIRROR",
        font=font(18, True),
        fill=SLATE,
    )
    draw.text(
        (1295, 878),
        "Nét đứt = nhánh phụ; A11 vẫn chạy khi Splunk tắt",
        font=font(18, True),
        fill=SLATE,
    )

    # 03 - Real-time SOCPipeline.
    section_panel(
        draw,
        980,
        1320,
        "03",
        "SOCPIPELINE — XỬ LÝ REAL-TIME TRÊN UBUNTU",
        CYAN,
    )
    pipeline = [
        ("AUTH", "API key / HEC token\nSyslog ACL", BLUE),
        ("PARSE", "Apache • EVE\nWindows • Syslog", CYAN),
        ("NORMALIZE", "Common schema\nIP • port • protocol", CYAN),
        ("DEDUP", "SHA-256\nfingerprint", SLATE),
        ("CORRELATE", "Cửa sổ 300 s\ncount + last_seen", GREEN),
        ("PERSIST", "Raw event\nAlert + Audit", SLATE),
    ]
    x_positions = [55, 345, 635, 925, 1215, 1505]
    rects: list[tuple[int, int, int, int]] = []
    for index, (title, body, accent) in enumerate(pipeline):
        rect = (x_positions[index], 1070, x_positions[index] + 235, 1245)
        rects.append(rect)
        rounded_box(
            draw,
            rect,
            title,
            body,
            accent,
            title_size=23,
            body_size=20,
        )
        if index:
            arrow(
                draw,
                (rects[index - 1][2] + 4, 1155),
                (rect[0] - 9, 1155),
                BLUE,
                width=5,
            )
    draw.rounded_rectangle(
        (400, 1260, 1400, 1305), radius=13, fill=LIGHT_GREEN, outline="#AAD6C3", width=2
    )
    ready_text = (
        "ĐẦU RA BƯỚC 3: CORRELATED ALERT CONTEXT  →  alert_id • event_count • normalized_event • evidence_ref"
    )
    ready_bbox = draw.textbbox((0, 0), ready_text, font=font(18, True))
    draw.text(
        ((WIDTH - (ready_bbox[2] - ready_bbox[0])) // 2, 1273),
        ready_text,
        font=font(18, True),
        fill=GREEN,
    )

    # 04 - Agentic AI.
    section_panel(draw, 1345, 1655, "04", "AGENTIC AI VÀ RA QUYẾT ĐỊNH", GREEN)
    agent_boxes = [
        (
            (65, 1435, 365, 1595),
            "ENRICHMENT",
            "Asset • IOC\nIP context",
            GREEN,
        ),
        (
            (440, 1435, 740, 1595),
            "TRIAGE",
            "Severity • confidence\nMITRE ATT&CK",
            GREEN,
        ),
        (
            (815, 1435, 1115, 1595),
            "RAG",
            "Playbook cục bộ\nKhuyến nghị",
            BLUE,
        ),
        (
            (1190, 1435, 1490, 1595),
            "LOCAL LLM",
            "Ollama tùy chọn\nStructured JSON",
            SLATE,
        ),
        (
            (1565, 1435, 1735, 1595),
            "DECIDE",
            "Severity\n≥ HIGH?",
            AMBER,
        ),
    ]
    for index, (rect, title, body, accent) in enumerate(agent_boxes):
        rounded_box(
            draw,
            rect,
            title,
            body,
            accent,
            title_size=24,
            body_size=20,
        )
        if index:
            previous = agent_boxes[index - 1][0]
            arrow(
                draw,
                (previous[2] + 5, 1515),
                (rect[0] - 10, 1515),
                GREEN,
                width=5,
            )

    # 05 - Outcomes.
    section_panel(draw, 1680, 2245, "05", "KẾT QUẢ, PHẢN ỨNG VÀ BÁO CÁO", NAVY)
    draw.rounded_rectangle(
        (65, 1770, 1735, 1870),
        radius=17,
        fill=LIGHT_GREEN,
        outline="#AAD6C3",
        width=3,
    )
    draw.text((90, 1788), "LOW / MEDIUM", font=font(25, True), fill=GREEN)
    draw.text(
        (360, 1788),
        "Lưu + giám sát  →  EventBus/SSE  →  Dashboard Events, Alerts và Metrics",
        font=font(25),
        fill=INK,
    )
    draw.text(
        (360, 1825),
        "Mỗi raw event vẫn được giữ; dedup chỉ ngăn bùng nổ số lượng Alert.",
        font=font(21),
        fill=MUTED,
    )

    outcomes = [
        (
            (65, 1920, 350, 2070),
            "ALERT + INCIDENT",
            "High/Critical\ntimeline + evidence",
            RED,
        ),
        (
            (410, 1920, 695, 2070),
            "REPORT AGENT",
            "IOC • MITRE • impact\nsummary + actions",
            AMBER,
        ),
        (
            (755, 1920, 1040, 2070),
            "RESPONSE",
            "notify • block_ip\nisolate_host",
            RED,
        ),
        (
            (1100, 1920, 1390, 2070),
            "APPROVAL GATE",
            "Safety validation\nAnalyst approve/reject",
            AMBER,
        ),
        (
            (1450, 1920, 1735, 2070),
            "N8N / EXECUTOR",
            "n8n webhook\nOPNsense alias + audit",
            SLATE,
        ),
    ]
    for index, (rect, title, body, accent) in enumerate(outcomes):
        rounded_box(
            draw,
            rect,
            title,
            body,
            accent,
            title_size=23,
            body_size=20,
        )
        if index:
            previous = outcomes[index - 1][0]
            arrow(
                draw,
                (previous[2] + 5, 1995),
                (rect[0] - 10, 1995),
                RED,
                width=5,
            )

    draw.rounded_rectangle((190, 2110, 1610, 2188), radius=16, fill=NAVY)
    final_text = (
        "BÁO CÁO HOÀN CHỈNH  •  timeline  •  IP/port/protocol  •  evidence  •  RAG  •  n8n/response"
    )
    final_bbox = draw.textbbox((0, 0), final_text, font=font(21, True))
    draw.text(
        ((WIDTH - (final_bbox[2] - final_bbox[0])) // 2, 2135),
        final_text,
        font=font(21, True),
        fill=WHITE,
    )

    draw.text(
        (55, 2260),
        "Critical path: nguồn log → A11 Ubuntu → SOCPipeline → Agentic AI/RAG → Incident/Report → n8n hoặc OPNsense. Splunk chỉ quan sát.",
        font=font(21, True),
        fill=MUTED,
    )

    OUT.parent.mkdir(parents=True, exist_ok=True)
    image.save(OUT, optimize=True)
    print(OUT.resolve())


if __name__ == "__main__":
    main()
