"""Generate Master Architectural Flow Diagram for A11 Agentic SOC.

Outputs a 3840x2400 ultra-high-resolution comprehensive diagram
combining all network zones, data collection branches, 300s correlation,
multi-agent AI core, HITL gate, dual-branch SOAR, and real-time dashboard.
"""
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
FONTS = ROOT / 'work' / 'a11_motion_deck' / 'fonts'
OUTPUTS = ROOT / 'outputs'
OUTPUTS.mkdir(exist_ok=True)

# Color Palette (Cyber Dark Noir)
BG = (6, 8, 12)            # Deep black-navy canvas
CARD_BG = (13, 16, 23)     # Slate card body
CARD_BORDER = (30, 41, 59) # Slate card border
CARD_HEADER_BG = (18, 24, 35)

# Accent Colors
CYAN = (56, 189, 248)      # Network, telemetry, ingestion, SSE
AMBER = (245, 158, 11)     # Correlation, SHA-256, alerts, ML
GREEN = (16, 185, 129)     # RAG, assets, benign filters, pass
RED = (239, 68, 68)        # Attacks, malicious payloads, firewall block, HITL
PURPLE = (168, 85, 247)    # Ollama LLM, n8n workflow, AI reasoning
BLUE = (59, 130, 246)      # Primary structural accents
INK = (248, 250, 252)      # High-contrast title text
TEXT_COL = (226, 232, 240) # Body text
MUTED = (148, 163, 184)    # Secondary / note text
DIM = (100, 116, 139)      # Muted labels / borders
CODE_BG = (9, 11, 16)      # Editor background

# Fonts
def get_font(name: str, size: int):
    p = FONTS / name
    if p.exists():
        return ImageFont.truetype(str(p), size)
    return ImageFont.load_default()

F_TITLE = get_font('SpaceGrotesk_700Bold.ttf', 44)
F_SUBTITLE = get_font('BeVietnamPro_700Bold.ttf', 24)
F_BADGE = get_font('JetBrainsMono_700Bold.ttf', 16)
F_COL_HEAD = get_font('SpaceGrotesk_700Bold.ttf', 24)
F_COL_SUB = get_font('BeVietnamPro_700Bold.ttf', 17)
F_CARD_TITLE = get_font('SpaceGrotesk_700Bold.ttf', 20)
F_CARD_SUB = get_font('BeVietnamPro_700Bold.ttf', 15)
F_BODY = get_font('BeVietnamPro_400Regular.ttf', 16)
F_BODY_BOLD = get_font('BeVietnamPro_700Bold.ttf', 16)
F_MONO = get_font('JetBrainsMono_400Regular.ttf', 15)
F_MONO_BOLD = get_font('JetBrainsMono_700Bold.ttf', 15)
F_MONO_SM = get_font('JetBrainsMono_400Regular.ttf', 13)
F_CODE = get_font('JetBrainsMono_400Regular.ttf', 14)
F_CODE_BOLD = get_font('JetBrainsMono_700Bold.ttf', 14)
F_FOOTER_TITLE = get_font('SpaceGrotesk_700Bold.ttf', 20)
F_FOOTER_BODY = get_font('BeVietnamPro_400Regular.ttf', 15)


def rbox(d: ImageDraw.ImageDraw, xy, r=12, fill=None, outline=None, width=1):
    d.rounded_rectangle(xy, radius=r, fill=fill, outline=outline, width=width)


def draw_badge(d: ImageDraw.ImageDraw, x, y, text, col, bg=(15, 23, 42)):
    bbox = d.textbbox((0, 0), text, font=F_BADGE)
    tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
    w = tw + 24
    h = 32
    rbox(d, [x, y, x + w, y + h], r=8, fill=bg, outline=col, width=2)
    d.text((x + 12, y + 6), text, font=F_BADGE, fill=col)
    return x + w + 12


def draw_arrow_h(d: ImageDraw.ImageDraw, x1, y1, x2, y2, col=CYAN, width=3, text=None):
    d.line([(x1, y1), (x2, y2)], fill=col, width=width)
    ah = 10
    d.polygon([(x2, y2), (x2 - ah, y2 - 7), (x2 - ah, y2 + 7)], fill=col)
    if text:
        bbox = d.textbbox((0, 0), text, font=F_MONO_SM)
        tw = bbox[2] - bbox[0]
        mx = (x1 + x2) // 2 - tw // 2
        rbox(d, [mx - 6, y1 - 22, mx + tw + 6, y1 - 2], r=4, fill=CODE_BG, outline=col, width=1)
        d.text((mx, y1 - 20), text, font=F_MONO_SM, fill=col)


def draw_code_snippet(d: ImageDraw.ImageDraw, x, y, w, h, title, code_lines, accent_col=CYAN):
    rbox(d, [x, y, x + w, y + h], r=8, fill=CODE_BG, outline=accent_col, width=1)
    # Header bar
    d.rectangle([x + 1, y + 1, x + w - 1, y + 26], fill=(18, 23, 32))
    d.ellipse([x + 10, y + 8, x + 19, y + 17], fill=(239, 68, 68))
    d.ellipse([x + 25, y + 8, x + 34, y + 17], fill=(245, 158, 11))
    d.ellipse([x + 40, y + 8, x + 49, y + 17], fill=(16, 185, 129))
    d.text((x + 58, y + 5), title, font=F_MONO_SM, fill=accent_col)

    cy = y + 33
    for line in code_lines:
        if isinstance(line, tuple):
            prefix, text, col = line
            d.text((x + 10, cy), prefix, font=F_CODE_BOLD, fill=DIM)
            d.text((x + 48, cy), text, font=F_CODE, fill=col)
        else:
            d.text((x + 10, cy), line, font=F_CODE, fill=MUTED)
        cy += 21


def build_master_diagram():
    w, h = 3840, 2400
    im = Image.new('RGB', (w, h), BG)
    d = ImageDraw.Draw(im)

    # Subtle grid background lines
    for gx in range(0, w, 80):
        d.line([(gx, 0), (gx, h)], fill=(12, 16, 22), width=1)
    for gy in range(0, h, 80):
        d.line([(0, gy), (w, gy)], fill=(12, 16, 22), width=1)

    # =========================================================================
    # 1. TOP HEADER & METADATA BAR (Y: 35 to 185)
    # =========================================================================
    rbox(d, [40, 30, w - 40, 185], r=16, fill=(11, 14, 20), outline=(30, 41, 59), width=2)
    d.rectangle([42, 30, w - 42, 36], fill=AMBER)

    d.text((65, 48), 'HỆ THỐNG GIÁM SÁT AN NINH MẠNG TỰ CHỦ CỤC BỘ — A11 AGENTIC SOC', font=F_TITLE, fill=INK)
    d.text((65, 105), 'SƠ ĐỒ LUỒNG TOÀN CẢNH ĐẦU CUỐI: TỪ GÓI TIN THÔ ĐẾN TƯƠNG QUAN ĐA TÁC NHÂN AI & PHẢN ỨNG SOAR CÓ PHÊ DUYỆT (HITL)', font=F_SUBTITLE, fill=MUTED)

    # Metadata Badges
    bx = 65
    by = 142
    bx = draw_badge(d, bx, by, '100% ON-PREMISE LOCAL', GREEN)
    bx = draw_badge(d, bx, by, 'MẠNG 3 PHÂN VÙNG VMWARE', CYAN)
    bx = draw_badge(d, bx, by, 'THU THẬP KÉP: UDP/5514 + REST', CYAN)
    bx = draw_badge(d, bx, by, 'TƯƠNG QUAN 300S (SHA-256)', AMBER)
    bx = draw_badge(d, bx, by, '6 AGENT AI + RAG CỤC BỘ', PURPLE)
    bx = draw_badge(d, bx, by, 'RÀO CHẮN HITL & SOAR N8N', RED)
    bx = draw_badge(d, bx, by, '50/50 PYTEST PASS (1.63S)', GREEN)
    draw_badge(d, bx, by, 'TRIẾT LÝ: TỰ ĐỘNG PHÂN TÍCH, CON NGƯỜI QUYẾT ĐỊNH', AMBER)

    # =========================================================================
    # 5 COLUMNS LAYOUT (Y: 205 to 2260)
    # =========================================================================
    col_w = 724
    col_gap = 20
    x_c1 = 45
    x_c2 = x_c1 + col_w + col_gap
    x_c3 = x_c2 + col_w + col_gap
    x_c4 = x_c3 + col_w + col_gap
    x_c5 = x_c4 + col_w + col_gap

    y_top = 205
    y_bot = 2260
    col_h = y_bot - y_top

    # Helper: Draw Column Container
    def draw_column_shell(x, title, subtitle, accent_col, tag):
        rbox(d, [x, y_top, x + col_w, y_bot], r=16, fill=(9, 12, 17), outline=CARD_BORDER, width=2)
        rbox(d, [x + 2, y_top + 2, x + col_w - 2, y_top + 76], r=14, fill=(15, 20, 29))
        d.rectangle([x + 2, y_top + 70, x + col_w - 2, y_top + 76], fill=accent_col)
        # Tag Badge
        t_box = d.textbbox((0, 0), tag, font=F_BADGE)
        tw = t_box[2] - t_box[0]
        rbox(d, [x + col_w - tw - 30, y_top + 14, x + col_w - 14, y_top + 46], r=6, fill=CODE_BG, outline=accent_col, width=1)
        d.text((x + col_w - tw - 22, y_top + 20), tag, font=F_BADGE, fill=accent_col)

        d.text((x + 20, y_top + 14), title, font=F_COL_HEAD, fill=INK)
        d.text((x + 20, y_top + 44), subtitle, font=F_COL_SUB, fill=MUTED)

    # =========================================================================
    # COLUMN 1: HẠ TẦNG MẠNG 3 VÙNG & NGUỒN PHÁT TẤN CÔNG (WAN -> OPNsense -> LAN)
    # =========================================================================
    draw_column_shell(x_c1, '1. HẠ TẦNG & TẤN CÔNG', 'WAN (Kali) -> OPNsense Biên -> LAN SOC', RED, 'PHÂN VÙNG')

    # Card 1.1: Máy Kali Linux (WAN)
    c1_y1 = y_top + 90
    c1_h1 = 610
    rbox(d, [x_c1 + 15, c1_y1, x_c1 + col_w - 15, c1_y1 + c1_h1], r=12, fill=CARD_BG, outline=RED, width=2)
    d.text((x_c1 + 30, c1_y1 + 16), 'MÁY TẤN CÔNG: KALI LINUX (WAN)', font=F_CARD_TITLE, fill=RED)
    d.text((x_c1 + 30, c1_y1 + 42), 'Địa chỉ IP: 192.168.108.128/24 (Vùng ngoài WAN)', font=F_MONO, fill=MUTED)

    d.text((x_c1 + 30, c1_y1 + 72), 'MA TRẬN 15 KỊCH BẢN TẤN CÔNG KIỂM THỬ THỰC CHIẾN:', font=F_BODY_BOLD, fill=INK)
    scenarios = [
        ('1. DO THÁM MẠNG (RECONNAISSANCE)', RED, [
            '• Kịch bản 1: Quét TCP SYN (-sS, 1000 ports) -> MITRE T1046 (bắt qua L241 triage.py)',
            '• Kịch bản 2: Quét cổng UDP dịch vụ (-sU 53, 161, 500)',
            '• Kịch bản 3: Kích hoạt luật cảnh báo Suricata IDS (Emerging Threats rules)',
        ]),
        ('2. KHAI THÁC ỨNG DỤNG WEB (OWASP TOP 10)', AMBER, [
            "• Kịch bản 4: SQL Injection (' OR 1=1--, UNION SELECT) -> MITRE T1190",
            '• Kịch bản 5: Path Traversal (../../../../etc/passwd) -> Bắt qua SUSPICIOUS_PATH',
            '• Kịch bản 6: Rò rỉ môi trường nguy hiểm (/.env, /config.json)',
            '• Kịch bản 7: Dò quét bảng điều khiển phpMyAdmin (/phpmyadmin)',
            '• Kịch bản 8: Chèn mã kịch bản XSS (<script>alert(1)</script>)',
            '• Kịch bản 9: Thực thi lệnh hệ điều hành (; id; uname -a)',
        ]),
        ('3. TỪ CHỐI DỊCH VỤ & LÀM NGẬP (DENIAL OF SERVICE)', RED, [
            '• Kịch bản 10: Tấn công chậm Slowloris (làm cạn kiệt worker pool)',
            '• Kịch bản 11: Làm ngập HTTP Flood (100+ req/s) -> MITRE T1498',
            '• Kịch bản 12: Làm ngập kết nối TCP SYN Flood (hping3 -S -p 80 --flood)',
        ]),
        ('4. DÒ MẬT KHẨU & BLACKLIST (CREDENTIAL ACCESS)', PURPLE, [
            '• Kịch bản 13: Dò mật khẩu SSH qua Hydra (>= 10 fails) -> MITRE T1110',
            '• Kịch bản 14: Dò mật khẩu FTP Brute-force (Port 21, fail rate cao)',
            '• Kịch bản 15: Truy cập từ địa chỉ IP độc hại trong Blacklist IOC (iocs.json)',
        ]),
    ]
    sy = c1_y1 + 100
    for group_title, col, items in scenarios:
        d.text((x_c1 + 30, sy), group_title, font=F_MONO_BOLD, fill=col)
        sy += 22
        for it in items:
            d.text((x_c1 + 40, sy), it, font=F_BODY, fill=TEXT_COL)
            sy += 21
        sy += 5

    # Card 1.2: Tường lửa OPNsense
    c1_y2 = c1_y1 + c1_h1 + 18
    c1_h2 = 560
    rbox(d, [x_c1 + 15, c1_y2, x_c1 + col_w - 15, c1_y2 + c1_h2], r=12, fill=CARD_BG, outline=CYAN, width=2)
    d.text((x_c1 + 30, c1_y2 + 16), 'TƯỜNG LỬA BIÊN OPNSENSE (2-NIC)', font=F_CARD_TITLE, fill=CYAN)
    d.text((x_c1 + 30, c1_y2 + 42), 'WAN: 192.168.108.133  |  LAN: 10.10.10.1 (Gateway)', font=F_MONO_BOLD, fill=INK)

    opn_bullets = [
        ('• PF Firewall Engine:', 'Chặn mặc định toàn bộ chiều vào từ WAN (Default Deny Policy).', TEXT_COL),
        ('• NAT Port Forward:', 'Chỉ chuyển tiếp cổng 80 WAN về máy chủ Web Ubuntu 10.10.10.10:80.', TEXT_COL),
        ('• Suricata IDS Engine:', 'Giám sát và so khớp chữ ký đe dọa L3/L4/L7 theo thời gian thực.', TEXT_COL),
        ('• Bảng động SOC_BLOCKLIST:', 'Bí danh PF Table nạp địa chỉ IP độc hại để ngắt kết nối tại biên.', AMBER),
        ('• Remote Syslog Daemon:', 'Bắn toàn bộ bản ghi filterlog thô qua UDP :5514 về máy chủ SOC.', CYAN),
    ]
    oy = c1_y2 + 72
    for h_txt, b_txt, c_val in opn_bullets:
        d.text((x_c1 + 30, oy), h_txt, font=F_BODY_BOLD, fill=c_val)
        d.text((x_c1 + 40, oy + 21), b_txt, font=F_BODY, fill=MUTED)
        oy += 47

    draw_code_snippet(d, x_c1 + 30, c1_y2 + 325, col_w - 60, 215, 'OPNsense Remote Syslog XML & Filterlog Sample', [
        ('1', '<syslog>', MUTED),
        ('2', '  <target>10.10.10.10:5514</target> <!-- soc-app Datagram -->', CYAN),
        ('3', '  <filterlog>1</filterlog> <!-- packet filter logs -->', AMBER),
        ('4', '</syslog>', MUTED),
        ('CSV', 'filterlog: 1,,,1000000103,em0,match,block,in,4,0x0,,64,0,0,DF,6,tcp,', RED),
        ('CSV', '           60,192.168.108.128,10.10.10.10,54210,80,0,S,1024,,mss;', TEXT_COL),
        ('RES', '==> action="block", proto="TCP", src="192.168.108.128", dst_port=80', GREEN),
    ], CYAN)

    # Card 1.3: Máy chủ mục tiêu Ubuntu SOC & Docker Containers
    c1_y3 = c1_y2 + c1_h2 + 18
    c1_h3 = col_h - (c1_h1 + c1_h2 + 36 + 90)
    rbox(d, [x_c1 + 15, c1_y3, x_c1 + col_w - 15, c1_y3 + c1_h3], r=12, fill=CARD_BG, outline=GREEN, width=2)
    d.text((x_c1 + 30, c1_y3 + 16), 'MÁY CHỦ UBUNTU SOC & WEB TARGET', font=F_CARD_TITLE, fill=GREEN)
    d.text((x_c1 + 30, c1_y3 + 42), 'Địa chỉ IP: 10.10.10.10 (Phân vùng Protected LAN)', font=F_MONO, fill=MUTED)

    ub_items = [
        ('Apache2 Web Server', 'Nạn nhân bị tấn công Web L7, ghi log /var/log/apache2/access.log.'),
        ('Dịch vụ Shipper nền', 'a11-apache-shipper tail file log và chuyển tiếp an toàn qua REST API.'),
        ('Cụm 4 Container Docker', 'soc-app (:8000/:5514), ollama (:11434), n8n (:5678), mailpit (:8025).'),
        ('Phân vùng mạng cô lập', 'Chỉ OPNsense và Admin được phép truy cập cổng điều hành hệ thống.'),
    ]
    uy = c1_y3 + 72
    for ut, ud in ub_items:
        d.text((x_c1 + 30, uy), f'• {ut}:', font=F_BODY_BOLD, fill=INK)
        d.text((x_c1 + 40, uy + 20), ud, font=F_BODY, fill=MUTED)
        uy += 44

    draw_code_snippet(d, x_c1 + 30, c1_y3 + 265, col_w - 60, c1_h3 - 280, 'docker-compose.yml (On-Premise Service Stack)', [
        ('services:', 'soc-app: ports: ["8000:8000", "5514:5514/udp"]', CYAN),
        ('services:', 'ollama:  ports: ["11434:11434"] (Qwen2.5:7b On-Premise)', PURPLE),
        ('services:', 'n8n:     ports: ["5678:5678"] (SOAR Webhook Workflow)', AMBER),
        ('services:', 'mailpit: ports: ["8025:8025", "1025:1025"] (Alert Mail)', GREEN),
        ('env:', '      API_KEY=secret_key, OPNSENSE_URL=https://10.10.10.1', TEXT_COL),
    ], GREEN)

    # =========================================================================
    # COLUMN 2: THU THẬP ĐA NGUỒN & CHUẨN HÓA DỮ LIỆU (L1 & L2)
    # =========================================================================
    draw_column_shell(x_c2, '2. THU THẬP & CHUẨN HÓA', 'OPNsense UDP :5514 vs Apache REST API', CYAN, 'LỚP 1 & 2')

    # Card 2.1: Nhánh 1 (L3/L4 Network Syslog)
    c2_y1 = y_top + 90
    c2_h1 = 610
    rbox(d, [x_c2 + 15, c2_y1, x_c2 + col_w - 15, c2_y1 + c2_h1], r=12, fill=CARD_BG, outline=CYAN, width=2)
    d.text((x_c2 + 30, c2_y1 + 16), 'NHÁNH 1 (L3/L4): OPNSENSE SYSLOG UDP', font=F_CARD_TITLE, fill=CYAN)
    d.text((x_c2 + 30, c2_y1 + 42), 'Giao thức: UDP / Cổng: 5514 (Phi kết nối, tốc độ cao)', font=F_MONO, fill=MUTED)

    n1_texts = [
        '1. Thu nhận Socket Datagram:',
        '   Lớp SyslogProtocol (app/integrations/syslog.py) mở socket',
        '   UDP không phong tỏa, nạp log thô vào asyncio.Queue.',
        '2. Hàm bóc tách _opnsense_filterlog() (app/parsers.py:L185):',
        '   Tách 17 trường CSV từ chuỗi filterlog của Packet Filter:',
        '   [rule_nr, tracker, iface, reason, action, dir, ip_ver, tos,',
        '    ecn, ttl, id, offset, flags, proto, src_ip, dst_ip, ports...]',
        '3. Nhận diện sự kiện tầng mạng:',
        '   action="block" -> gán nhãn opnsense.firewall_block',
        '   action="pass"  -> gán nhãn opnsense.firewall_pass',
        '   Bắt chính xác Nmap Port Scan & DoS tầng mạng L3/L4.',
    ]
    ny = c2_y1 + 72
    for line in n1_texts:
        if line.startswith(('1.', '2.', '3.')):
            d.text((x_c2 + 30, ny), line, font=F_BODY_BOLD, fill=INK)
        else:
            d.text((x_c2 + 30, ny), line, font=F_BODY, fill=MUTED)
        ny += 22

    draw_code_snippet(d, x_c2 + 30, c2_y1 + 355, col_w - 60, 235, 'app/parsers.py:L185-L215 (_opnsense_filterlog)', [
        ('185', 'def _opnsense_filterlog(line: str) -> RawLogEvent:', CYAN),
        ('186', '    parts = [p.strip() for p in line.split(",")]', MUTED),
        ('187', '    action = parts[6].lower() # "block" hoặc "pass"', TEXT_COL),
        ('195', '    proto = parts[16].upper() # TCP / UDP / ICMP', TEXT_COL),
        ('196', '    src_ip, dst_ip = parts[18], parts[19]', AMBER),
        ('205', '    return RawLogEvent(source="opnsense",', TEXT_COL),
        ('206', '        event_type=f"opnsense.firewall_{action}",', RED),
        ('207', '        src_ip=src_ip, dest_ip=dst_ip, action=action,', GREEN),
        ('208', '        dest_port=int(parts[21]) if len(parts) > 21 else 0)', GREEN),
    ], CYAN)

    # Card 2.2: Nhánh 2 (L7 Web Access Log)
    c2_y2 = c2_y1 + c2_h1 + 18
    c2_h2 = 610
    rbox(d, [x_c2 + 15, c2_y2, x_c2 + col_w - 15, c2_y2 + c2_h2], r=12, fill=CARD_BG, outline=AMBER, width=2)
    d.text((x_c2 + 30, c2_y2 + 16), 'NHÁNH 2 (L7): APACHE SHIPPER & REST API', font=F_CARD_TITLE, fill=AMBER)
    d.text((x_c2 + 30, c2_y2 + 42), 'Giao thức: HTTP POST :8000/api/v1/ingest (X-API-Key)', font=F_MONO, fill=MUTED)

    n2_texts = [
        '1. Dịch vụ nền a11-apache-shipper (scripts/ship_apache_access.py):',
        '   Tail liên tục /var/log/apache2/access.log, xử lý xoay file',
        '   logrotate tự động, đóng gói gửi từng dòng log qua REST API.',
        '2. Xác thực an toàn tại app/main.py:L175:',
        '   Kiểm tra khóa API bí mật X-API-Key ngăn giả mạo nguồn gửi.',
        '3. Hàm bóc tách _apache() & SUSPICIOUS_PATH (parsers.py:L30, L150):',
        '   Rà quét URI với Regex: ../ | .env | union select | <script>',
        '   Nếu khớp -> gắn ngay nhãn web.suspicious_request (T1190).',
        '   Bắt sớm mã độc SQLi, Traversal, XSS trước khi vào DB.',
    ]
    ay = c2_y2 + 72
    for line in n2_texts:
        if line.startswith(('1.', '2.', '3.')):
            d.text((x_c2 + 30, ay), line, font=F_BODY_BOLD, fill=INK)
        else:
            d.text((x_c2 + 30, ay), line, font=F_BODY, fill=MUTED)
        ay += 22

    draw_code_snippet(d, x_c2 + 30, c2_y2 + 355, col_w - 60, 235, 'app/parsers.py:L30, L150 (SUSPICIOUS_PATH & _apache)', [
        ('30', 'SUSPICIOUS_PATH = re.compile(', RED),
        ('31', '    r"(\\.\\./|/\\.env|union.*select|<script|cmd=)", re.I)', RED),
        ('150', 'def _apache(line: str) -> RawLogEvent:', AMBER),
        ('153', '    m = APACHE_LOG_REGEX.match(line)', MUTED),
        ('160', '    is_susp = bool(SUSPICIOUS_PATH.search(uri))', RED),
        ('162', '    etype = "web.suspicious_request" if is_susp \\', AMBER),
        ('163', '            else "web.access"', TEXT_COL),
        ('165', '    return RawLogEvent(event_type=etype, uri=uri, ...)', GREEN),
    ], AMBER)

    # Card 2.3: Bộ Parser phụ trợ & Lược đồ chuẩn hóa
    c2_y3 = c2_y2 + c2_h2 + 18
    c2_h3 = col_h - (c2_h1 + c2_h2 + 36 + 90)
    rbox(d, [x_c2 + 15, c2_y3, x_c2 + col_w - 15, c2_y3 + c2_h3], r=12, fill=CARD_BG, outline=BLUE, width=2)
    d.text((x_c2 + 30, c2_y3 + 16), 'LƯỢC ĐỒ CHUẨN HÓA SỰ KIỆN UNIFIED SCHEMA', font=F_CARD_TITLE, fill=BLUE)
    d.text((x_c2 + 30, c2_y3 + 42), 'Hội tụ 6 nguồn: OPNsense, Apache, Auth/SSH, Suricata, Syslog, ModSec', font=F_MONO, fill=MUTED)

    draw_code_snippet(d, x_c2 + 30, c2_y3 + 70, col_w - 60, c2_h3 - 85, 'NormalizedEvent Data Class (app/parsers.py)', [
        ('dataclass', 'class RawLogEvent / NormalizedEvent:', BLUE),
        ('field', '  id: str              # Unique UUIDv4 định danh sự kiện', TEXT_COL),
        ('field', '  timestamp: datetime  # ISO-8601 UTC timestamp', TEXT_COL),
        ('field', '  source: str         # "opnsense" | "apache" | "auth" | "suricata"', TEXT_COL),
        ('field', '  event_type: str     # "web.suspicious_request", "opnsense.firewall_block"', AMBER),
        ('field', '  src_ip: str         # IP kẻ tấn công (192.168.108.128)', RED),
        ('field', '  dest_ip: str        # IP máy chủ mục tiêu (10.10.10.10)', GREEN),
        ('field', '  dest_port: int      # Cổng đích (80 HTTP, 22 SSH, 5514 Syslog)', CYAN),
        ('field', '  proto: str          # Giao thức mạng ("TCP" | "UDP" | "ICMP")', TEXT_COL),
        ('field', '  action: str         # Quyết định ("block" | "pass" | "allow")', TEXT_COL),
        ('field', '  raw_text: str       # Chuỗi nhật ký thô nguyên bản không thay đổi', MUTED),
    ], BLUE)

    # =========================================================================
    # COLUMN 3: TƯƠNG QUAN 300S, LÀM GIÀU & LỌC NHIỄU (L3 & L4 PREP)
    # =========================================================================
    draw_column_shell(x_c3, '3. TƯƠNG QUAN & LỌC NHIỄU', 'Sliding Window 300s & Giảm Báo Động Giả', AMBER, 'LỚP 3')

    # Card 3.1: Khóa băm SHA-256 Fingerprint
    c3_y1 = y_top + 90
    c3_h1 = 440
    rbox(d, [x_c3 + 15, c3_y1, x_c3 + col_w - 15, c3_y1 + c3_h1], r=12, fill=CARD_BG, outline=AMBER, width=2)
    d.text((x_c3 + 30, c3_y1 + 16), 'KHÓA BĂM FINGERPRINT (SHA-256)', font=F_CARD_TITLE, fill=AMBER)
    d.text((x_c3 + 30, c3_y1 + 42), 'Hàm fingerprint() tại app/parsers.py:L406', font=F_MONO, fill=MUTED)

    d.text((x_c3 + 30, c3_y1 + 72), 'Ghép 6 trường dữ liệu cốt lõi tạo mã băm cố định 64 ký tự:', font=F_BODY_BOLD, fill=INK)
    f_bullets = [
        '1. src_ip: Địa chỉ IP nguồn phát sinh lưu lượng (Attacker)',
        '2. dest_ip: Địa chỉ IP máy đích nội bộ cần bảo vệ',
        '3. dest_port: Cổng dịch vụ đích (80, 443, 22...)',
        '4. proto: Giao thức mạng (TCP, UDP, ICMP)',
        '5. event_type: Nhãn loại sự kiện đã chuẩn hóa',
        '6. rule_id / path: Mã luật tường lửa hoặc mẫu URI rà soát',
    ]
    fy = c3_y1 + 98
    for fb in f_bullets:
        d.text((x_c3 + 40, fy), fb, font=F_BODY, fill=TEXT_COL)
        fy += 23

    draw_code_snippet(d, x_c3 + 30, c3_y1 + 255, col_w - 60, 165, 'app/parsers.py:L406-L415 (fingerprint)', [
        ('406', 'def fingerprint(event: RawLogEvent) -> str:', AMBER),
        ('407', '    key = f"{event.src_ip}|{event.dest_ip}|" \\', TEXT_COL),
        ('408', '          f"{event.dest_port}|{event.proto}|" \\', TEXT_COL),
        ('409', '          f"{event.event_type}|{event.rule_id}"', TEXT_COL),
        ('410', '    return hashlib.sha256(key.encode()).hexdigest()', CYAN),
        ('OUT', '==> Ví dụ: "a3f89b...e21" đại diện duy nhất cho vector', GREEN),
    ], AMBER)

    # Card 3.2: Gom nhóm cửa sổ trượt 300 giây
    c3_y2 = c3_y1 + c3_h1 + 18
    c3_h2 = 520
    rbox(d, [x_c3 + 15, c3_y2, x_c3 + col_w - 15, c3_y2 + c3_h2], r=12, fill=CARD_BG, outline=CYAN, width=2)
    d.text((x_c3 + 30, c3_y2 + 16), 'GOM NHÓM CỬA SỔ TRƯỢT 300 GIÂY', font=F_CARD_TITLE, fill=CYAN)
    d.text((x_c3 + 30, c3_y2 + 42), 'Thuật toán triệt tiêu bão cảnh báo (app/pipeline.py:L82-96)', font=F_MONO, fill=MUTED)

    d.text((x_c3 + 30, c3_y2 + 72), 'NGUYÊN LÝ VẬN HÀNH SLIDING WINDOW:', font=F_BODY_BOLD, fill=INK)
    w_bullets = [
        '• Khi tin tặc bắn hàng trăm gói tin trong thời gian ngắn (quét cổng / DoS):',
        '  Hệ thống tra cứu fingerprint trong bảng Alert của 300 giây qua.',
        '• NẾU TÌM THẤY ALERT KHỚP FINGERPRINT:',
        '  - Không tạo thêm Alert mới (ngăn tràn ngập màn hình SOC)!',
        '  - Tăng biến đếm: existing_alert.event_count += 1.',
        '  - Cập nhật thời gian last_seen = datetime.utcnow().',
        '• NẾU KHÔNG TÌM THẤY (SỰ KIỆN MỚI):',
        '  - Khởi tạo Alert mới với event_count = 1.',
        '• KẾT QUẢ ĐẠT ĐƯỢC: Nén >95% bản ghi trùng, giữ trọn vẹn ngữ cảnh!',
    ]
    wy = c3_y2 + 98
    for wb in w_bullets:
        col = AMBER if 'NẾU' in wb or 'KẾT QUẢ' in wb else (TEXT_COL if wb.startswith('  -') else INK)
        d.text((x_c3 + 40, wy), wb, font=F_BODY_BOLD if wb.startswith('•') else F_BODY, fill=col)
        wy += 23

    draw_code_snippet(d, x_c3 + 30, c3_y2 + 335, col_w - 60, 165, 'app/pipeline.py:L82-L96 (Correlation query)', [
        ('82', 'cutoff = datetime.utcnow() - timedelta(seconds=300)', CYAN),
        ('83', 'existing = await db.execute(', MUTED),
        ('84', '    select(Alert).where(Alert.fingerprint == fp,', TEXT_COL),
        ('85', '                        Alert.created_at >= cutoff))', TEXT_COL),
        ('88', 'if existing:', AMBER),
        ('89', '    existing.event_count += 1; existing.last_seen = now', GREEN),
    ], CYAN)

    # Card 3.3: Làm giàu tài sản & Đối chiếu IOC
    c3_y3 = c3_y2 + c3_h2 + 18
    c3_h3 = 480
    rbox(d, [x_c3 + 15, c3_y3, x_c3 + col_w - 15, c3_y3 + c3_h3], r=12, fill=CARD_BG, outline=GREEN, width=2)
    d.text((x_c3 + 30, c3_y3 + 16), 'LÀM GIÀU TÀI SẢN & ĐỐI CHIẾU IOC', font=F_CARD_TITLE, fill=GREEN)
    d.text((x_c3 + 30, c3_y3 + 42), 'EnrichmentAgent (app/agents/enrichment.py:L33)', font=F_MONO, fill=MUTED)

    en_bullets = [
        ('Tra cứu danh bạ tài sản assets.json:', 'Xác định mức độ quan trọng máy đích (Ubuntu SOC = Critical Server, mức ảnh hưởng tối đa).'),
        ('Đối chiếu danh sách đen iocs.json:', 'Kiểm tra IP nguồn có nằm trong danh sách mối đe dọa toàn cầu (Threat Intel feeds).'),
        ('Bổ sung nhãn MITRE ATT&CK:', 'Tự động gắn mã Tactic và Technique tương ứng với loại sự kiện (T1190, T1046, T1498...).'),
    ]
    ey = c3_y3 + 72
    for et, ed in en_bullets:
        d.text((x_c3 + 30, ey), f'• {et}', font=F_BODY_BOLD, fill=INK)
        d.text((x_c3 + 40, ey + 21), ed, font=F_BODY, fill=MUTED)
        ey += 46

    draw_code_snippet(d, x_c3 + 30, c3_y3 + 230, col_w - 60, 230, 'app/agents/enrichment.py:L40-L65 (enrich)', [
        ('40', 'async def enrich(self, event: NormalizedEvent):', GREEN),
        ('42', '    asset = self.asset_inventory.get(event.dest_ip)', TEXT_COL),
        ('43', '    event.asset_criticality = asset.get("criticality", "low")', TEXT_COL),
        ('48', '    if event.src_ip in self.ioc_blacklist:', RED),
        ('49', '        event.is_known_threat = True', RED),
        ('50', '        event.tags.append("ioc_match")', AMBER),
        ('52', '    event.mitre = self.lookup_mitre(event.event_type)', CYAN),
    ], GREEN)

    # Card 3.4: Bộ lọc nhiễu hạ tầng nội bộ
    c3_y4 = c3_y3 + c3_h3 + 18
    c3_h4 = col_h - (c3_h1 + c3_h2 + c3_h3 + 36 + 90)
    rbox(d, [x_c3 + 15, c3_y4, x_c3 + col_w - 15, c3_y4 + c3_h4], r=12, fill=CARD_BG, outline=DIM, width=2)
    d.text((x_c3 + 30, c3_y4 + 16), 'LỌC NHIỄU DỊCH VỤ MẠNG HỢP LỆ (ANTI-FP)', font=F_CARD_TITLE, fill=INK)
    d.text((x_c3 + 30, c3_y4 + 42), 'Biến cờ firewall_ml_eligible (app/agents/triage.py:L162)', font=F_MONO, fill=MUTED)

    fml_bullets = [
        '• Loại bỏ hoàn toàn lưu lượng dịch vụ DNS (Port 53), DHCP (67/68), NTP (123).',
        '• Đảm bảo hệ thống không bao giờ báo động giả trên các gói tin phân giải tên miền hay đồng bộ thời gian của hạ tầng mạng nội bộ.',
    ]
    fmy = c3_y4 + 72
    for fb in fml_bullets:
        d.text((x_c3 + 30, fmy), fb, font=F_BODY, fill=MUTED)
        fmy += 24

    draw_code_snippet(d, x_c3 + 30, c3_y4 + 130, col_w - 60, c3_h4 - 145, 'app/agents/triage.py:L162 (firewall_ml_eligible)', [
        ('162', 'def firewall_ml_eligible(event: NormalizedEvent) -> bool:', CYAN),
        ('163', '    # Bỏ qua cổng hạ tầng DNS, DHCP, NTP nội bộ', MUTED),
        ('164', '    if event.dest_port in (53, 67, 68, 123):', AMBER),
        ('165', '        return False # Triệt tiêu 100% báo động giả!', RED),
        ('166', '    return True # Đủ điều kiện đưa vào học máy', GREEN),
    ], CYAN)

    # =========================================================================
    # COLUMN 4: TRÁI TIM ĐA TÁC NHÂN AI & RAG CỤC BỘ (L4 AI CORE)
    # =========================================================================
    draw_column_shell(x_c4, '4. ĐA TÁC NHÂN AI & RAG', 'Học máy MultinomialNB, Triage, RAG & Local LLM', PURPLE, 'LỚP 4')

    # Card 4.1: Nhạc trưởng SOCPipeline
    c4_y1 = y_top + 90
    c4_h1 = 300
    rbox(d, [x_c4 + 15, c4_y1, x_c4 + col_w - 15, c4_y1 + c4_h1], r=12, fill=CARD_BG, outline=PURPLE, width=2)
    d.text((x_c4 + 30, c4_y1 + 16), 'NHẠC TRƯỞNG ĐIỀU PHỐI: SOCPIPELINE.PROCESS()', font=F_CARD_TITLE, fill=PURPLE)
    d.text((x_c4 + 30, c4_y1 + 42), 'Tệp app/pipeline.py dòng 71–114 (Vòng đời xử lý sự kiện)', font=F_MONO, fill=MUTED)

    d.text((x_c4 + 30, c4_y1 + 72), 'Trình tự thực thi tuần tự bất đồng bộ qua 6 Agent:', font=F_BODY_BOLD, fill=INK)
    pipe_steps = [
        'Raw Event -> Parser.parse() -> Correlation (300s) -> EnrichmentAgent.enrich()',
        '-> MLDetectionAgent.predict() -> TriageAgent.evaluate() -> LocalKnowledgeBase.search()',
        '-> LocalLLMAgent.investigate() -> _ensure_incident() -> ResponseExecutor.execute()',
    ]
    py = c4_y1 + 98
    for ps in pipe_steps:
        d.text((x_c4 + 40, py), ps, font=F_MONO_SM, fill=AMBER)
        py += 23

    draw_code_snippet(d, x_c4 + 30, c4_y1 + 175, col_w - 60, 110, 'pipeline.py:L71 (Async Orchestration)', [
        ('71', 'async def process(self, raw_line: str) -> Optional[Alert]:', PURPLE),
        ('72', '    event = self.parser.parse(raw_line)', MUTED),
        ('75', '    alert = await self._correlate_or_create(event)', CYAN),
        ('80', '    alert = await self.enrichment.enrich(alert)', GREEN),
    ], PURPLE)

    # Card 4.2: Tác nhân Học máy Naive Bayes
    c4_y2 = c4_y1 + c4_h1 + 18
    c4_h2 = 470
    rbox(d, [x_c4 + 15, c4_y2, x_c4 + col_w - 15, c4_y2 + c4_h2], r=12, fill=CARD_BG, outline=CYAN, width=2)
    d.text((x_c4 + 30, c4_y2 + 16), 'AGENT 1: HỌC MÁY MULTINOMIAL NAIVE BAYES', font=F_CARD_TITLE, fill=CYAN)
    d.text((x_c4 + 30, c4_y2 + 42), 'MLDetectionAgent (app/agents/ml_detector.py) · 0.515 ms/ev', font=F_MONO, fill=MUTED)

    ml_points = [
        ('Hiệu năng suy luận siêu tốc:', 'Chỉ mất 0.515 ms trên 100% CPU (~1.942 sự kiện/giây), không cần GPU đắt đỏ.'),
        ('Độ chính xác kiểm nghiệm:', 'Accuracy: 93.33%  |  Precision: 100%  |  Recall: 85.71%  |  F1-Score: 92.31%.'),
        ('Trích xuất đặc trưng Bigram:', 'Hàm tokenize() tách từ đơn và cặp từ liền kề (union_select, etc_passwd, cmd_exe).'),
        ('Nhúng tần suất vào đặc trưng:', 'Hàm event_to_text() thêm flag "event_volume:high" khi count >= 50 (bắt DoS/Flood).'),
    ]
    mly = c4_y2 + 72
    for mt, md_txt in ml_points:
        d.text((x_c4 + 30, mly), f'• {mt}', font=F_BODY_BOLD, fill=INK)
        d.text((x_c4 + 40, mly + 21), md_txt, font=F_BODY, fill=MUTED)
        mly += 46

    draw_code_snippet(d, x_c4 + 30, c4_y2 + 280, col_w - 60, 175, 'app/agents/ml_detector.py:L28, L71 (event_to_text & bigram)', [
        ('28', 'def event_to_text(event: NormalizedEvent) -> str:', CYAN),
        ('32', '    vol = "high" if event.event_count >= 50 else "normal"', AMBER),
        ('35', '    return f"{event.raw_text} event_volume:{vol}"', TEXT_COL),
        ('71', 'def tokenize(text: str) -> list[str]:', CYAN),
        ('73', '    bigrams = [f"{w1}_{w2}" for w1, w2 in zip(words, words[1:])]', GREEN),
        ('74', '    return words + bigrams # Kết hợp cả từ đơn và từ kép', TEXT_COL),
    ], CYAN)

    # Card 4.3: Tác nhân Phân loại rủi ro Triage
    c4_y3 = c4_y2 + c4_h2 + 18
    c4_h3 = 530
    rbox(d, [x_c4 + 15, c4_y3, x_c4 + col_w - 15, c4_y3 + c4_h3], r=12, fill=CARD_BG, outline=RED, width=2)
    d.text((x_c4 + 30, c4_y3 + 16), 'AGENT 2: PHÂN LOẠI TRIAGE CHUẨN MITRE', font=F_CARD_TITLE, fill=RED)
    d.text((x_c4 + 30, c4_y3 + 42), 'TriageAgent (app/agents/triage.py:L67-L445) · Quyết định mức HIGH', font=F_MONO, fill=MUTED)

    d.text((x_c4 + 30, c4_y3 + 72), 'CHỨNG MINH 5 NHÁNH CODE NÂNG MỨC CẢNH BÁO CAO (HIGH):', font=F_BODY_BOLD, fill=INK)
    tr_rules = [
        ('Nhánh 1 (L67): Web Suspicious lặp >= 5 lần', 'Nâng mức HIGH, gán MITRE T1190 (Exploit Public-Facing App).'),
        ('Nhánh 2 (L201): Kết nối Web Port 80/443 >= 50', 'Nâng mức HIGH, gán MITRE T1498 (Network Denial of Service).'),
        ('Nhánh 3 (L241): Gói TCP bị OPNsense chặn >= 20', 'Lab >= 5 lần -> Nâng mức HIGH, gán MITRE T1046 (Network Service Scan).'),
        ('Nhánh 4 (L365): Đăng nhập sai mật khẩu >= 10 lần', 'Nâng mức HIGH, gán MITRE T1110 (Brute Force Credential Access).'),
        ('Nhánh 5 (L428): Khớp danh sách đen chỉ báo IOC', 'Nâng mức HIGH, kích hoạt quy trình mở Incident khẩn cấp.'),
    ]
    try_ = c4_y3 + 98
    for rt, rd in tr_rules:
        d.text((x_c4 + 30, try_), f'• {rt}:', font=F_BODY_BOLD, fill=AMBER)
        d.text((x_c4 + 40, try_ + 21), rd, font=F_BODY, fill=MUTED)
        try_ += 44

    draw_code_snippet(d, x_c4 + 30, c4_y3 + 345, col_w - 60, 170, 'app/agents/triage.py:L67, L201, L241 (High Severity Branches)', [
        ('67', 'if is_suspicious_web and alert.event_count >= 5:', RED),
        ('68', '    return TriageResult(severity="HIGH", mitre="T1190")', AMBER),
        ('201', 'elif is_web_flood and alert.event_count >= 50:', RED),
        ('202', '    return TriageResult(severity="HIGH", mitre="T1498")', AMBER),
        ('241', 'elif is_blocked_scan and alert.event_count >= 20: # Lab >= 5', RED),
        ('242', '    return TriageResult(severity="HIGH", mitre="T1046")', AMBER),
    ], RED)

    # Card 4.4: Kho tri thức RAG & LLM Cục bộ
    c4_y4 = c4_y3 + c4_h3 + 18
    c4_h4 = col_h - (c4_h1 + c4_h2 + c4_h3 + 36 + 90)
    rbox(d, [x_c4 + 15, c4_y4, x_c4 + col_w - 15, c4_y4 + c4_h4], r=12, fill=CARD_BG, outline=GREEN, width=2)
    d.text((x_c4 + 30, c4_y4 + 16), 'AGENT 3 & 4: KHO RAG & OLLAMA QWEN2.5', font=F_CARD_TITLE, fill=GREEN)
    d.text((x_c4 + 30, c4_y4 + 42), 'LocalKnowledgeBase (rag.py:L46) & LocalLLMAgent (llm.py:L40)', font=F_MONO, fill=MUTED)

    rag_items = [
        ('10 Playbook Markdown Cục bộ:', 'Lưu trữ sẵn quy trình ứng phó chuẩn SOP (SQLi, DoS, Nmap Scan, Brute-force...).'),
        ('Truy xuất không ảo giác:', 'Hàm search() tính điểm trùng lặp từ khóa + thưởng tiêu đề (+0.03), rút 3 tài liệu sát nhất.'),
        ('Mô hình Ollama Qwen2.5:7b:', 'Sinh báo cáo On-Premise: nguyên nhân gốc rễ, tác động và khuyến nghị hành động.'),
        ('Chế độ Fallback xác định:', 'Khi LLM bận/tắt, hàm _fallback() sinh báo cáo mẫu trong 1 ms, không làm nghẽn pipeline!'),
    ]
    rgy = c4_y4 + 72
    for rt, rd in rag_items:
        d.text((x_c4 + 30, rgy), f'• {rt}', font=F_BODY_BOLD, fill=INK)
        d.text((x_c4 + 40, rgy + 20), rd, font=F_BODY, fill=MUTED)
        rgy += 42

    draw_code_snippet(d, x_c4 + 30, c4_y4 + 250, col_w - 60, c4_h4 - 265, 'app/agents/rag.py:L46 (LocalKnowledgeBase.search)', [
        ('46', 'def search(self, query: str, top_k=3) -> list[Playbook]:', GREEN),
        ('48', '    q_tokens = set(tokenize(query.lower()))', MUTED),
        ('50', '    scored = [(pb, len(q_tokens & pb.tokens) + pb.bonus) for pb in self.books]', TEXT_COL),
        ('55', '    return [pb for pb, s in sorted(scored, reverse=True)[:top_k]]', CYAN),
    ], GREEN)

    # =========================================================================
    # COLUMN 5: CHỐT CHẶN HITL, SOAR N8N, LƯU TRỮ & DASHBOARD (L5 & L6)
    # =========================================================================
    draw_column_shell(x_c5, '5. HITL, SOAR & GIÁM SÁT', 'Phê duyệt An toàn, n8n, Mailpit & Realtime SSE', AMBER, 'LỚP 5 & 6')

    # Card 5.1: Chốt chặn an toàn HITL
    c5_y1 = y_top + 90
    c5_h1 = 510
    rbox(d, [x_c5 + 15, c5_y1, x_c5 + col_w - 15, c5_y1 + c5_h1], r=12, fill=CARD_BG, outline=RED, width=2)
    d.text((x_c5 + 30, c5_y1 + 16), 'CHỐT CHẶN AN TOÀN HITL (HUMAN-IN-THE-LOOP)', font=F_CARD_TITLE, fill=RED)
    d.text((x_c5 + 30, c5_y1 + 42), 'Kiểm soát quyền lực AI (app/agents/response.py:L7 & pipeline.py:L250)', font=F_MONO, fill=MUTED)

    d.text((x_c5 + 30, c5_y1 + 72), 'VÌ SAO AI KHÔNG BAO GIỜ ĐƯỢC TỰ Ý KHÓA MẠNG?', font=F_BODY_BOLD, fill=INK)
    hitl_points = [
        '1. Ngưỡng mở hồ sơ sự cố (_ensure_incident):',
        '   Chỉ những cảnh báo đạt mức độ HIGH hoặc CRITICAL mới được',
        '   tự động tạo Incident và đề xuất hành động ngăn chặn.',
        '2. Rào chắn bảo vệ địa chỉ IP (is_safe_block_target):',
        '   Kiểm tra thuộc tính ip.is_global. CẤM TUYỆT ĐỐI việc chặn',
        '   dải IP Private RFC 1918 (10.x, 192.168.x) và Loopback (127.0.0.1)!',
        '   Tránh triệt để kịch bản tin tặc giả mạo IP khiến AI tự ngắt mạng.',
        '3. Cờ phê duyệt bắt buộc (approval_required = True):',
        '   Mọi hành động phong tỏa mạng đều ở trạng thái PENDING cho',
        '   đến khi quản trị viên con người bấm nút "APPROVE" trên Web UI.',
    ]
    hy = c5_y1 + 98
    for hp in hitl_points:
        col = RED if 'CẤM TUYỆT ĐỐI' in hp else (INK if hp.startswith(('1.', '2.', '3.')) else MUTED)
        d.text((x_c5 + 30, hy), hp, font=F_BODY_BOLD if hp.startswith(('1.', '2.', '3.')) else F_BODY, fill=col)
        hy += 22

    draw_code_snippet(d, x_c5 + 30, c5_y1 + 320, col_w - 60, 175, 'app/agents/response.py:L7-L14 (is_safe_block_target)', [
        ('7', 'def is_safe_block_target(target_ip: str) -> bool:', RED),
        ('8', '    ip = ipaddress.ip_address(target_ip)', TEXT_COL),
        ('9', '    if not ip.is_global or ip.is_private or ip.is_loopback:', RED),
        ('10', '        return False # CẤM CHẶN IP NỘI BỘ VÀ LOOPBACK!', RED),
        ('11', '    return True # Chỉ cho phép chặn IP Public bên ngoài', GREEN),
    ], RED)

    # Card 5.2: Tự động hóa SOAR 2 nhánh
    c5_y2 = c5_y1 + c5_h1 + 18
    c5_h2 = 530
    rbox(d, [x_c5 + 15, c5_y2, x_c5 + col_w - 15, c5_y2 + c5_h2], r=12, fill=CARD_BG, outline=AMBER, width=2)
    d.text((x_c5 + 30, c5_y2 + 16), 'ĐIỀU PHỐI PHẢN ỨNG SOAR 2 NHÁNH', font=F_CARD_TITLE, fill=AMBER)
    d.text((x_c5 + 30, c5_y2 + 42), 'ResponseExecutor (app/integrations/response_executor.py:L16)', font=F_MONO, fill=MUTED)

    soar_steps = [
        ('NHÁNH 1 · THÔNG BÁO TỰ ĐỘNG (NOTIFY_SOC):', AMBER, [
            '• Bắn Webhook mang payload JSON sự cố sang container n8n (:5678).',
            '• Workflow n8n định dạng mẫu báo cáo HTML chuyên nghiệp.',
            '• Chuyển phát tức thời đến hộp thư Mailpit (:8025) phục vụ kiểm toán.',
        ]),
        ('NHÁNH 2 · PHONG TỎA BIÊN CÓ PHÊ DUYỆT (BLOCK_IP):', RED, [
            '• Khi Admin bấm APPROVE -> Gọi hàm execute() trong ResponseExecutor.',
            '• Gọi trực tiếp REST API của tường lửa OPNsense.',
            '• Nạp IP kẻ tấn công (192.168.108.128) vào bảng SOC_BLOCKLIST.',
            '• Tường lửa lập tức DROP mọi gói tin từ Kali tại card WAN!',
        ]),
    ]
    sry = c5_y2 + 72
    for st, sc, s_items in soar_steps:
        d.text((x_c5 + 30, sry), st, font=F_BODY_BOLD, fill=sc)
        sry += 23
        for si in s_items:
            d.text((x_c5 + 40, sry), si, font=F_BODY, fill=TEXT_COL)
            sry += 21
        sry += 6

    draw_code_snippet(d, x_c5 + 30, c5_y2 + 340, col_w - 60, 175, 'response_executor.py:L45-L65 (OPNsense API block)', [
        ('45', 'async def _block_ip_opnsense(self, ip: str):', RED),
        ('46', '    url = f"{self.opnsense_url}/api/firewall/alias/addItem/SOC_BLOCKLIST"', TEXT_COL),
        ('47', '    payload = {"address": ip, "description": "Blocked by A11 SOC"}', AMBER),
        ('48', '    resp = await self.http_client.post(url, json=payload, auth=...)', CYAN),
        ('50', '    await self.http_client.post(f"{self.opnsense_url}/api/firewall/alias/reconfigure")', GREEN),
    ], RED)

    # Card 5.3: CSDL SQLite & Kiểm toán bất biến
    c5_y3 = c5_y2 + c5_h2 + 18
    c5_h3 = 440
    rbox(d, [x_c5 + 15, c5_y3, x_c5 + col_w - 15, c5_y3 + c5_h3], r=12, fill=CARD_BG, outline=CYAN, width=2)
    d.text((x_c5 + 30, c5_y3 + 16), 'CSDL SQLITE 5 BẢNG & AUDIT TRAIL', font=F_CARD_TITLE, fill=CYAN)
    d.text((x_c5 + 30, c5_y3 + 42), 'Lưu trữ toàn vẹn tại app/pipeline.py:L198', font=F_MONO, fill=MUTED)

    db_tables = [
        ('events:', 'Lưu trữ toàn bộ các bản ghi nhật ký thô và sự kiện đã chuẩn hóa.'),
        ('alerts:', 'Bản ghi cảnh báo sau khi gom nhóm tương quan trong cửa sổ 300s.'),
        ('incidents:', 'Hồ sơ sự cố nghiêm trọng (HIGH/CRITICAL) kèm phân tích MITRE.'),
        ('actions:', 'Nhật ký các hành động phản ứng (notify, block_ip) và trạng thái duyệt.'),
        ('audit_events:', 'Bảng kiểm toán bất biến: ghi vết mọi quyết định AI và thao tác Admin.'),
    ]
    dby = c5_y3 + 72
    for dt, dd in db_tables:
        d.text((x_c5 + 30, dby), f'• {dt}', font=F_MONO_BOLD, fill=AMBER)
        d.text((x_c5 + 160, dby), dd, font=F_BODY, fill=MUTED)
        dby += 26

    draw_code_snippet(d, x_c5 + 30, c5_y3 + 225, col_w - 60, 195, 'pipeline.py:L198 (AuditEvent Immutable Logging)', [
        ('198', 'audit = AuditEvent(action="approve_block", actor=user_id,', CYAN),
        ('199', '                   target_ip=incident.attacker_ip,', TEXT_COL),
        ('200', '                   timestamp=datetime.utcnow(), details=...)', TEXT_COL),
        ('201', 'db.add(audit); await db.commit() # Bất biến, không thể xóa sửa', GREEN),
    ], CYAN)

    # Card 5.4: Dashboard Realtime SSE & Splunk HEC
    c5_y4 = c5_y3 + c5_h3 + 18
    c5_h4 = col_h - (c5_h1 + c5_h2 + c5_h3 + 36 + 90)
    rbox(d, [x_c5 + 15, c5_y4, x_c5 + col_w - 15, c5_y4 + c5_h4], r=12, fill=CARD_BG, outline=GREEN, width=2)
    d.text((x_c5 + 30, c5_y4 + 16), 'DASHBOARD REALTIME SSE & SPLUNK', font=F_CARD_TITLE, fill=GREEN)
    d.text((x_c5 + 30, c5_y4 + 42), 'Server-Sent Events (:8000/events/stream) & Splunk HEC (:8088)', font=F_MONO, fill=MUTED)

    sse_texts = [
        '• Server-Sent Events (SSE): Luồng sự kiện đẩy trực tiếp lên 5 phân hệ Dashboard Web.',
        '  (Overview, Alerts, Incidents, Threat Map, System Health) với độ trễ dưới 10 mili-giây.',
        '• Chuyển tiếp Splunk HEC: Đồng bộ bản sao một chiều sang nền tảng SIEM doanh nghiệp.',
    ]
    sy_ = c5_y4 + 72
    for st in sse_texts:
        d.text((x_c5 + 30, sy_), st, font=F_BODY, fill=TEXT_COL)
        sy_ += 23

    draw_code_snippet(d, x_c5 + 30, c5_y4 + 150, col_w - 60, c5_h4 - 165, 'app/pipeline.py:L232 (Realtime SSE Publishing)', [
        ('232', 'await self.bus.publish({"type": "incident_created",', GREEN),
        ('233', '                        "incident": incident.to_dict()})', GREEN),
        ('234', '# Trình duyệt Web Dashboard nhận event tức thời không cần F5!', CYAN),
    ], GREEN)

    # =========================================================================
    # CONNECTING ARROWS ACROSS COLUMNS (DATA FLOW PIPELINE)
    # =========================================================================
    # Arrow 1: OPNsense -> Col 2 Nhánh 1 (UDP :5514)
    draw_arrow_h(d, x_c1 + col_w - 15, c1_y2 + 200, x_c2 + 15, c2_y1 + 180, CYAN, 4, 'UDP :5514 (Syslog)')

    # Arrow 2: Ubuntu Apache -> Col 2 Nhánh 2 (REST API POST)
    draw_arrow_h(d, x_c1 + col_w - 15, c1_y3 + 120, x_c2 + 15, c2_y2 + 180, AMBER, 4, 'POST /api/v1/ingest')

    # Arrow 3: Col 2 Parsers -> Col 3 Fingerprint (NormalizedEvent)
    draw_arrow_h(d, x_c2 + col_w - 15, c2_y1 + 300, x_c3 + 15, c3_y1 + 150, CYAN, 4, 'NormalizedEvent')
    draw_arrow_h(d, x_c2 + col_w - 15, c2_y2 + 300, x_c3 + 15, c3_y1 + 220, AMBER, 4, 'NormalizedEvent')

    # Arrow 4: Col 3 Correlation -> Col 4 AI Pipeline (Correlated Alert)
    draw_arrow_h(d, x_c3 + col_w - 15, c3_y2 + 250, x_c4 + 15, c4_y1 + 120, AMBER, 4, 'Correlated Alert (300s)')

    # Arrow 5: Col 4 AI Decision -> Col 5 HITL Gate (HIGH/CRITICAL Alert)
    draw_arrow_h(d, x_c4 + col_w - 15, c4_y3 + 180, x_c5 + 15, c5_y1 + 180, RED, 4, 'Triage: HIGH (MITRE)')

    # Arrow 6: Col 5 Approve -> SOAR Execution
    d.line([(x_c5 + col_w // 2, c5_y1 + c5_h1), (x_c5 + col_w // 2, c5_y2)], fill=AMBER, width=4)
    d.polygon([(x_c5 + col_w // 2, c5_y2), (x_c5 + col_w // 2 - 7, c5_y2 - 10), (x_c5 + col_w // 2 + 7, c5_y2 - 10)], fill=AMBER)

    # =========================================================================
    # CLOSED-LOOP FEEDBACK ARROW: SOAR BLOCK -> OPNSENSE SOC_BLOCKLIST
    # =========================================================================
    fb_y = y_bot - 12
    fb_x_start = x_c5 + 40
    fb_y_start = c5_y2 + 480

    points = [
        (fb_x_start, fb_y_start),
        (fb_x_start, fb_y),
        (x_c1 + col_w - 40, fb_y),
        (x_c1 + col_w - 40, c1_y2 + c1_h2 - 40),
    ]
    d.line(points, fill=RED, width=5)
    up_x = x_c1 + col_w - 40
    up_y = c1_y2 + c1_h2 - 40
    d.polygon([(up_x, up_y), (up_x - 8, up_y + 14), (up_x + 8, up_y + 14)], fill=RED)

    # Label on the feedback line
    fb_label = 'PHẢN HỒI ĐÓNG VÒNG: GỌI REST API OPNSENSE NẠP IP VÀO SOC_BLOCKLIST ĐỂ KHÓA TẤN CÔNG TẠI BIÊN MẠNG'
    bbox_fb = d.textbbox((0, 0), fb_label, font=F_BADGE)
    tw_fb = bbox_fb[2] - bbox_fb[0]
    rbox(d, [w // 2 - tw_fb // 2 - 20, fb_y - 20, w // 2 + tw_fb // 2 + 20, fb_y + 18], r=8, fill=(35, 10, 15), outline=RED, width=2)
    d.text((w // 2 - tw_fb // 2, fb_y - 14), fb_label, font=F_BADGE, fill=RED)

    # =========================================================================
    # BOTTOM FOOTER BAR: 4 CORE VALUE PILLARS (Y: 2275 to 2375)
    # =========================================================================
    rbox(d, [40, 2275, w - 40, 2375], r=14, fill=(11, 14, 20), outline=CARD_BORDER, width=2)
    d.rectangle([42, 2275, w - 42, 2280], fill=CYAN)

    pillars = [
        ('1. BẢO MẬT TUYỆT ĐỐI 100% ON-PREMISE', 'Vận hành hoàn toàn trong mạng LAN nội bộ; không gửi byte dữ liệu nhạy cảm nào ra dịch vụ AI đám mây bên ngoài.', CYAN),
        ('2. KIỂM SOÁT AN TOÀN HUMAN-IN-THE-LOOP', 'AI tự động phân tích và khuyến nghị; con người giữ quyền duyệt cuối; rào chắn cấm tuyệt đối tự khóa IP nội bộ.', AMBER),
        ('3. HIỆU NĂNG TỐC ĐỘ CAO TRÊN CPU', 'Học máy Naive Bayes chỉ mất 0.515 ms/sự kiện; thông lượng toàn hệ thống đạt 114.46 sự kiện/giây; gom nhóm 300s triệt tiêu bão log.', GREEN),
        ('4. KIỂM CHỨNG TOÀN DIỆN & SẴN SÀNG', 'Đạt 50/50 Pytest PASS (1.63s); phát hiện và xử lý chính xác 14/15 kịch bản tấn công thực chiến từ Kali Linux.', PURPLE),
    ]
    p_w = (w - 120) // 4
    for i, (p_title, p_desc, p_col) in enumerate(pillars):
        px = 65 + i * (p_w + 12)
        d.text((px, 2292), p_title, font=F_FOOTER_TITLE, fill=p_col)
        words = p_desc.split()
        lines = []
        cur = []
        for wd in words:
            cur.append(wd)
            if len(' '.join(cur)) > 52:
                lines.append(' '.join(cur[:-1]))
                cur = [wd]
        if cur:
            lines.append(' '.join(cur))
        for l_idx, line in enumerate(lines[:2]):
            d.text((px, 2324 + l_idx * 22), line, font=F_FOOTER_BODY, fill=MUTED)

    # Save outputs
    out_file = OUTPUTS / 'A11_Agentic_SOC_Master_Flow_Diagram.png'
    im.save(out_file, quality=95)
    print(f'Saved master diagram to {out_file} (Dimensions: {w}x{h})')

    dl_path = Path(r'C:\Users\Admin\Downloads\A11_Agentic_SOC_Master_Flow_Diagram.png')
    im.save(dl_path, quality=95)
    print(f'Copied master diagram to {dl_path}')

    asset_path = ROOT / 'work' / 'a11_motion_deck' / 'assets' / 'master_flow_diagram.png'
    im.save(asset_path, quality=95)
    print(f'Copied master diagram to {asset_path}')


if __name__ == '__main__':
    build_master_diagram()

