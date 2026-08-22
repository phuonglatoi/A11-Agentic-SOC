# Đo số liệu thật khi demo A11 Agentic SOC

Tài liệu này phân biệt hai phép đánh giá. Không dùng dữ liệu do nút **Run lab
scenario** sinh ra để công bố hiệu năng.

1. **Benchmark có nhãn** đo chất lượng mô hình ML: confusion matrix, TPR, FPR,
   precision, recall và F1 được tính trực tiếp từ nhãn thật và kết quả dự đoán.
2. **Live end-to-end trial** đo đường chạy thật: Kali -> OPNsense DNAT -> Apache
   access.log -> shipper -> A11 -> incident/action -> n8n -> Mailpit. Mỗi lần
   chạy được ghi bằng marker riêng, Alert ID và timestamp thật.

## 1. Kiểm tra dịch vụ trước khi đo

Trên Ubuntu:

```bash
cd ~/A11-Agentic-SOC
docker compose ps
curl -fsS http://127.0.0.1:8000/health | python3 -m json.tool
bash scripts/test_n8n_webhooks.sh
```

Giữ shipper Apache hoạt động trong một terminal riêng nếu chưa chạy như service:

```bash
python3 scripts/ship_apache_access.py \
  --file /var/log/apache2/access.log \
  --url http://127.0.0.1:8000/api/v1/ingest \
  --api-key "$SOC_API_KEY"
```

Nếu biến chưa được export, nạp riêng giá trị từ `.env`; không quay video hoặc
in token lên màn hình.

## 2. Benchmark mô hình bằng số liệu được tính lúc chạy

```bash
python3 scripts/benchmark_attack_classifier.py \
  --input datasets/a11_benchmark_labeled_events.jsonl \
  --model models/attack_classifier.json \
  --output demo_results/model_benchmark.json
```

Terminal sẽ in số mẫu, confusion TP/FN/FP/TN, TPR và FPR. File JSON có
`generated_at`, đường dẫn dataset, thông tin model và các mẫu dự đoán sai. Không
chép một phần trăm cũ vào báo cáo; lấy giá trị của đúng lần chạy này.

Có thể đặt tiêu chí chấp nhận nhưng tiêu chí không thay đổi kết quả đo:

```bash
python3 scripts/benchmark_attack_classifier.py \
  --min-tpr 0.80 --max-fpr 0.10 \
  --output demo_results/model_benchmark.json
```

Chương trình trả mã lỗi nếu kết quả thật không đạt ngưỡng. Nếu dataset không có
mẫu benign thì FPR là `null`, không tự coi là 0%.

### Benchmark đúng 500 event

File benchmark đi kèm repository hiện chỉ có 30 event. Muốn đo 500 event, cung
cấp CSV/JSONL kiểm thử độc lập có ít nhất 500 dòng rồi chạy:

```bash
python3 scripts/benchmark_attack_classifier.py \
  --csv /duong-dan/held_out_test_events.csv \
  --sample-size 500 \
  --seed 2026 \
  --model models/attack_classifier.json \
  --output demo_results/model_benchmark_500.json
```

Chế độ này lấy mẫu phân tầng theo label, không hoàn lại và ghi vào JSON:
`available_samples`, `selected_samples`, `available_by_label`,
`selected_by_label`, `seed`. Nếu file chỉ có 499 event, chương trình dừng thay vì
nhân bản dòng để đủ số lượng. Không dùng lại các dòng đã tham gia train model.

## 3. Đo một request lành tính end-to-end

Trên Ubuntu chạy trước:

```bash
python3 scripts/measure_live_http_trial.py \
  --expected benign \
  --target-url http://192.168.228.142
```

Script tạo marker, chụp số incident/action/audit/email ban đầu và in một lệnh
`curl`. Sao chép đúng lệnh đó sang Kali. Khi access.log được ship vào A11, script
ghi lại:

- Alert ID, source IP, severity, confidence và attack type;
- độ trễ từ lúc bắt đầu chờ đến lúc A11 quan sát event;
- incident/action liên quan đúng Alert ID;
- n8n audit và email mới trong Mailpit;
- kết quả `TN` nếu request không bị nâng thành HIGH/CRITICAL và không kích hoạt
  incident/response; `FP` nếu bị cảnh báo nhầm.

Nếu marker không tới A11, kết quả là `NO_EVIDENCE` và không được đưa vào TPR/FPR.
Đây thường là lỗi Apache shipper, NAT hoặc access.log, không phải true negative.

## 4. Đo request tấn công có kiểm soát

Trên Ubuntu:

```bash
python3 scripts/measure_live_http_trial.py \
  --expected attack \
  --target-url http://192.168.228.142
```

Chạy lệnh được script in ra trên Kali. Lệnh dùng chuỗi SQL-injection probe trong
lab sở hữu của sinh viên, không khai thác hệ thống bên ngoài. Kết quả là `TP` nếu
A11 nâng severity lên HIGH/CRITICAL, hoặc `FN` nếu không nâng. Incident, action
`notify_soc`, audit n8n và email Mailpit được ghi độc lập để chứng minh SOAR có
hoạt động hay không.

## 5. Tính TPR/FPR từ nhiều live trial

Sau khi đã chạy cả mẫu attack và benign:

```bash
python3 scripts/summarize_live_trials.py \
  --input demo_results/live_trials.jsonl \
  --output demo_results/live_summary.json
```

Công thức được dùng:

- `TPR = TP / (TP + FN)`;
- `FPR = FP / (FP + TN)`;
- `Precision = TP / (TP + FP)`;
- `Specificity = TN / (TN + FP)`.

Nên chạy tối thiểu nhiều lần cho từng loại và ghi rõ cỡ mẫu. Ba kịch bản đơn lẻ
chỉ chứng minh luồng end-to-end, chưa đủ để suy rộng hiệu năng ngoài môi trường
lab. Hai file trong `demo_results/` là bằng chứng chạy thật và được `.gitignore`
để tránh đẩy log/IP/token vận hành lên Git.
