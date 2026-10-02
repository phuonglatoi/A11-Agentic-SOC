# A11 SOC attack training datasets

This directory contains the compact A11 seed/holdout data and the CICIDS2017
MachineLearningCSV benchmark used by the flow-classification experiments. The
seven original CICIDS2017 CSV files are stored with Git LFS under
`datasets/cicids2017/`; install Git LFS before cloning/pulling this repository
to retrieve the actual data instead of only the LFS pointer files.

On Ubuntu:

```bash
sudo apt update && sudo apt install -y git-lfs
git lfs install
git clone https://github.com/phuonglatoi/A11-Agentic-SOC.git
cd A11-Agentic-SOC
git lfs pull
```

The dataset is redistributed under the terms described by the Canadian
Institute for Cybersecurity. Retain the attribution below in any redistribution
or publication using these files.

Dataset citation: Iman Sharafaldin, Arash Habibi Lashkari, and Ali A. Ghorbani,
“Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic
Characterization,” *4th International Conference on Information Systems
Security and Privacy (ICISSP)*, 2018, pp. 108–116,
https://doi.org/10.5220/0006639801080116.

Official dataset page: https://www.unb.ca/cic/datasets/ids-2017.html
Dataset terms/FAQ: https://www.unb.ca/cic/datasets/index.html

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
- `a11_benchmark_labeled_events.jsonl`: held-out lab examples used only for
  evaluation. These rows are intentionally separate from the seed training
  rows so the reported score is not training accuracy.
- `cicids2017/*.csv`: the seven labeled CICIDS2017 CICFlowMeter CSVs. The raw
  files are stored in Git LFS; Git LFS must be installed on Ubuntu to download
  them.

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

## Run the reproducible benchmark

```bash
python3 scripts/benchmark_attack_classifier.py \
  --input datasets/a11_benchmark_labeled_events.jsonl \
  --model models/attack_classifier.json \
  --output benchmark_results.json
```

The JSON result contains accuracy, macro precision/recall/F1, per-class
metrics, a confusion matrix and each misclassified sample. For an external
DataSense/CIC benchmark, provide a held-out CSV that was not used for training:

```bash
python3 scripts/benchmark_attack_classifier.py \
  --csv /path/to/DataSense_test_only.csv \
  --model models/attack_classifier.json \
  --output benchmark_results.json
```

The model is deliberately lightweight JSON so the Ubuntu lab can run offline
without installing scikit-learn, pandas or other heavy ML packages during the
Docker build.
