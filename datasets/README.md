# A11 SOC attack training datasets

This directory keeps small, sanitized training data for the thesis lab. The
full public benchmark datasets are intentionally not committed because they are
large and should be downloaded from their official pages with proper citation.

## Recommended latest public dataset for this project

Use **DataSense: CIC IIoT dataset 2025** as the primary external dataset for the
A11 Agentic SOC ML Detection Agent. It is the best fit for this lab because it
contains log/network attack categories that map directly to the OPNsense,
Apache and Kali scenarios:

- Benign traffic
- DDoS / DoS: HTTP Flood, TCP SYN Flood, UDP Flood, ICMP Flood, Slowloris, MQTT
  Publish Flood
- Recon: Port Scan, OS Scan, Ping Sweep, Vulnerability Scan
- Web: SQL Injection, Blind SQL Injection, XSS, Command Injection, Backdoor
  Upload
- Brute force: SSH and Telnet brute force
- MITM: ARP spoofing, impersonation, IP spoofing
- Malware: Mirai SYN/UDP flood

Official page:

```text
https://www.unb.ca/cic/datasets/iiot-dataset-2025.html
```

The repository also supports CSVs from CICIoMT2024 or other CICFlowMeter-like
datasets as long as a label column is present.

## Files in this directory

- `a11_seed_labeled_events.jsonl`: compact seed data used to build the bundled
  demo model. Each line is one labeled security event.

## Train the bundled model

```bash
python3 scripts/train_attack_classifier.py \
  --input datasets/a11_seed_labeled_events.jsonl \
  --output models/attack_classifier.json
```

## Train with DataSense/CIC CSV after downloading it

```bash
python3 scripts/train_attack_classifier.py \
  --input datasets/a11_seed_labeled_events.jsonl \
  --csv /path/to/DataSense_or_CIC_dataset.csv \
  --sample-per-class 5000 \
  --output models/attack_classifier.json
```

Then rebuild the API container:

```bash
docker compose build api
docker compose --profile automation up -d
```

The model is deliberately lightweight JSON so the Ubuntu lab can run offline
without installing scikit-learn, pandas or other heavy ML packages during the
Docker build.
