# A11 Agentic SOC Automation

## 2026 update: Dataset + ML Detection Agent

The project now includes a local **ML Detection Agent** trained from sanitized
seed events and designed to be retrained with **DataSense: CIC IIoT dataset
2025**. This dataset is the recommended latest benchmark for the A11 lab because
it covers HTTP Flood/DoS/DDoS, Recon/Nmap, Web SQL Injection/XSS, brute force,
MITM/spoofing and Mirai-like malware scenarios.

Runtime flow:

```text
OPNsense / Apache / Suricata / Windows log
  -> normalize
  -> enrichment
  -> ML Detection Agent
  -> deterministic triage + RAG playbook
  -> alert / incident / report / response action
  -> analyst approval
  -> n8n webhook or OPNsense adapter
```

Train the bundled demo model:

```bash
python3 scripts/train_attack_classifier.py \
  --input datasets/a11_seed_labeled_events.jsonl \
  --output models/attack_classifier.json
```

Train with an official DataSense/CIC CSV after downloading it:

```bash
python3 scripts/train_attack_classifier.py \
  --input datasets/a11_seed_labeled_events.jsonl \
  --csv /path/to/DataSense_or_CIC_dataset.csv \
  --sample-per-class 5000 \
  --output models/attack_classifier.json
```

Hệ thống SOC real-time chạy cục bộ, được hiện thực hóa từ hai tài liệu TTTN:
OPNsense/Apache/Splunk làm nguồn telemetry và Agentic AI làm lớp tự động hóa
triage, enrichment, RAG, incident, report và response có phê duyệt.

## Thành phần đã có

- Nhận log qua REST, Splunk-compatible HEC và syslog UDP 5514. Khi chạy bằng
  Docker, host UDP 514 cũng được forward vào collector để tương thích OPNsense
  / pfSense cũ.
- Chuẩn hóa Apache access log, Suricata EVE JSON, Windows Security Event và
  sự kiện JSON tổng quát.
- Gom nhóm/correlation theo fingerprint trong cửa sổ 5 phút.
- Giữ từng raw event/normalized event làm bằng chứng, dù nhiều event đã được gom
  vào cùng một alert.
- Alert Triage Agent đánh mức `Low / Medium / High / Critical`, độ tin cậy,
  MITRE ATT&CK và khuyến nghị.
- Enrichment Agent tra asset inventory, IOC cục bộ và thuộc tính IP.
- RAG Agent tra playbook trong thư mục `knowledge/`, không gửi dữ liệu ra cloud.
- Ollama tùy chọn cho phân tích bổ sung; hệ thống vẫn hoạt động khi LLM tắt/lỗi.
- Tự động tạo incident và báo cáo Markdown cho alert High/Critical.
- Response Agent tạo đề xuất notify, block IP hoặc isolate host.
- Approval gate: block/cô lập không bao giờ tự chạy khi chưa có quyết định của
  analyst; mọi bước được ghi audit log.
- Dashboard SSE real-time, không phụ thuộc CDN nên hoạt động offline.
- OPNsense adapter, generic webhook adapter, Splunk search poller và n8n profile.

## Kiến trúc

```text
Apache / Suricata / Windows / Splunk / Syslog
                       │
          REST + HEC + UDP collector
                       │
        Normalize → Correlate → Triage
                       │
         IOC/Asset → RAG → Local Ollama
                       │
             Alert → Incident → Report
                       │
       Response proposal → Approval gate
                       │
       dry-run / webhook / OPNsense alias
                       │
          Audit log + SSE live dashboard
```

## Chạy nhanh bằng Docker

1. Tạo cấu hình:

   ```powershell
   Copy-Item .env.example .env
   ```

2. Đổi tối thiểu `SOC_API_KEY`, `SOC_ADMIN_TOKEN` và `POSTGRES_PASSWORD` trong
   `.env`.

3. Khởi động:

   ```powershell
   docker compose up -d --build
   ```

4. Mở `http://127.0.0.1:8000`, nhập `SOC_ADMIN_TOKEN`.

5. Nhấn **Run lab scenario** để sinh Apache, Suricata và Windows events an toàn.

Mặc định `RESPONSE_MODE=dry_run`: khi analyst bấm Approve, hệ thống kiểm tra và
ghi audit nhưng không thay đổi firewall/endpoint thật.

## Chạy trực tiếp để phát triển

Python 3.11+:

```powershell
python -m pip install -r requirements-dev.txt
Copy-Item .env.example .env
.\scripts\start_local.ps1
```

Với cấu hình mặc định trong script, token dashboard là
`change-me-admin-token`, API ingest key là `change-me-ingest-key`. Chỉ dùng hai
giá trị này trong máy lab.

## Gửi log vào hệ thống

### API chung

```powershell
$headers = @{ "X-API-Key" = "your-ingest-key" }
$body = @{
  source = "apache"
  event = '203.0.113.66 - - [28/Jul/2026:15:31:11 +0000] "GET /.env HTTP/1.1" 404 512 "-" "dirb/2.22"'
} | ConvertTo-Json
Invoke-RestMethod http://127.0.0.1:8000/api/v1/ingest -Method Post -Headers $headers -ContentType application/json -Body $body
```

### HEC tương thích Splunk

```bash
curl http://127.0.0.1:8000/services/collector/event \
  -H "Authorization: Splunk your-ingest-key" \
  -H "Content-Type: application/json" \
  -d '{"sourcetype":"suricata:eve","event":{"event_type":"alert","src_ip":"203.0.113.66","dest_ip":"192.168.1.100","dest_port":80,"alert":{"severity":2,"signature":"ET SCAN Nmap","category":"Attempted Information Leak"}}}'
```

HEC nhận được cả nhiều JSON object nối tiếp nhau như Splunk HEC.

### Syslog từ OPNsense

Trong OPNsense, cấu hình remote logging đến IP Ubuntu chạy SOC. Với bản mới có
thể đặt UDP port `5514`; với OPNsense 19.1 hoặc giao diện không có ô port, để
mặc định UDP `514`. Docker Compose đã publish cả host `514/udp` và `5514/udp`
vào collector nội bộ. Nếu dùng Docker/VMware, bảo đảm VMnet và firewall Ubuntu
cho phép đúng IP nguồn, không mở các port này ra Internet.

Kiểm tra nhanh trên Ubuntu:

```bash
sudo tcpdump -ni any 'udp port 514 or udp port 5514'
docker compose logs -f api
```

Khi A11 SOC nhận được syslog, log API sẽ có dòng dạng
`Received syslog datagram from ...`.

### Splunk Cloud

Có hai mô hình:

1. **Khuyến nghị cho lab:** Universal Forwarder vẫn gửi Apache lên Splunk Cloud,
   đồng thời một shipper/agent cục bộ gửi cùng log vào HEC của A11 SOC. Không cần
   mở A11 SOC ra Internet.
2. **Poll Splunk REST:** điền `SPLUNK_URL`, `SPLUNK_TOKEN`, `SPLUNK_SEARCH`, rồi:

   ```powershell
   docker compose --profile splunk up -d splunk-poller
   ```

   Splunk Cloud có thể yêu cầu Support bật REST API, và free trial có thể không
   có quyền này. Poller dùng endpoint v2
   `/services/search/v2/jobs/export`, tránh endpoint v1 đã deprecated.

## Bật Local LLM

```powershell
docker compose --profile ai up -d ollama
docker compose exec ollama ollama pull qwen2.5:7b
```

Sau đó đặt `OLLAMA_ENABLED=true` và khởi động lại `api`. Ollama chỉ được dùng để
tạo đánh giá bổ sung; severity nền, approval gate và safety validation vẫn do
logic xác định để tránh LLM tự ý thực thi.

## Kết nối OPNsense an toàn

1. Trên OPNsense tạo alias loại **Host**, **Network** hoặc **External** tên
   `SOC_BLOCKLIST`.
2. Tạo firewall rule dùng alias này ở đúng interface và kiểm thử thủ công.
3. Tạo API key có quyền tối thiểu cần thiết.
4. Điền `OPNSENSE_URL`, `OPNSENSE_KEY`, `OPNSENSE_SECRET`.
5. Giữ `RESPONSE_MODE=dry_run` để kiểm thử approval/audit trước.
6. Khi đã xác nhận rule, đặt `RESPONSE_MODE=opnsense`.

Adapter sử dụng API chính thức
`POST /api/firewall/alias_util/add/{alias}` với body `{"address":"IP"}`. Hệ
thống từ chối block IP private, loopback, multicast, unspecified hoặc IP sai cú
pháp.

## Profiles bổ sung

- `docker compose --profile automation up -d n8n`: workflow automation local
  tại `127.0.0.1:5678`.
- `docker compose --profile ai up -d`: Ollama local.
- `docker compose --profile splunk up -d`: Splunk REST poller.

Các profile không cần thiết cho pipeline lõi. Webhook của n8n có thể được đặt
vào `NOTIFICATION_WEBHOOK_URL` hoặc `RESPONSE_WEBHOOK_URL`.

## API vận hành

| Endpoint | Mục đích | Xác thực |
|---|---|---|
| `POST /api/v1/ingest` | Nhận một/nhiều event | `X-API-Key` |
| `POST /services/collector/event` | Splunk HEC JSON | `Authorization: Splunk` |
| `POST /services/collector/raw` | HEC raw | `Authorization: Splunk` |
| `GET /api/v1/alerts` | Hàng đợi alert | Bearer admin |
| `GET /api/v1/alerts/{id}/events` | Bằng chứng gốc của alert | Bearer admin |
| `GET /api/v1/incidents` | Incident và report | Bearer admin |
| `GET /api/v1/actions` | Approval queue | Bearer admin |
| `POST /api/v1/actions/{id}/decision` | Approve/reject | Bearer admin |
| `GET /api/v1/audit` | Audit trail | Bearer admin |
| `POST /api/v1/stream-ticket` | Cấp vé SSE ngắn hạn | Bearer admin |
| `GET /api/v1/stream` | SSE real-time | Vé stream riêng, không lộ admin token |

OpenAPI: `http://127.0.0.1:8000/docs`.

## Kiểm thử

```powershell
pytest
```

Test bao phủ parser, triage, RAG và luồng end-to-end:
ingest → alert → incident → pending block → analyst approval → dry-run → audit.

## Hardening trước production

- Đổi toàn bộ secret mặc định và dùng secret manager/Docker secrets.
- Đặt dashboard sau Tailscale hoặc reverse proxy có TLS/SSO; không NAT trực tiếp
  port 8000 ra Internet.
- Chỉ bind HTTP vào `127.0.0.1` nếu không có reverse proxy.
- Giới hạn IP gửi syslog/HEC ở firewall máy Ubuntu.
- Dùng certificate hợp lệ cho OPNsense và giữ `OPNSENSE_VERIFY_TLS=true`.
- Backup PostgreSQL và bảo vệ audit log khỏi sửa/xóa bởi tài khoản ứng dụng.
- Thay asset/IOC mẫu trong `data/` bằng dữ liệu của lab thật.
- Kiểm thử OPNsense adapter trên alias/rule lab trước khi bật production.

## Tài liệu kỹ thuật tham chiếu

- [OPNsense Firewall API](https://docs.opnsense.org/development/api/core/firewall.html)
- [OPNsense alias API example](https://docs.opnsense.org/manual/aliases.html)
- [Ollama structured output](https://docs.ollama.com/capabilities/structured-outputs)
- [Splunk HEC examples](https://docs.splunk.com/Documentation/Splunk/9.4.2/Data/HECExamples)
- [Splunk v2 search export endpoint](https://help.splunk.com/en/splunk-cloud-platform/leverage-rest-apis/rest-api-reference/10.0.2503/search-endpoints/search-endpoint-descriptions)

## Giới hạn có chủ đích

Đây là hệ thống SOC hoàn chỉnh ở mức lab/đồ án và pilot nội bộ, không phải sản
phẩm EDR/SIEM thương mại. Endpoint isolation thực tế cần adapter của EDR đang
dùng; hiện action này được tạo, phê duyệt và audit nhưng chỉ chạy qua dry-run
hoặc generic webhook. GeoIP/threat-intel Internet không được gọi mặc định để giữ
dữ liệu và vận hành hoàn toàn cục bộ.
