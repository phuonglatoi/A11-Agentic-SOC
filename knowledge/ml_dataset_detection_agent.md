# ML Dataset Detection Agent

Tags: dataset, machine learning, DataSense, CIC, IIoT, attack classification, HTTP flood, DDoS, DoS, Recon, SQL injection, brute force

## Purpose

The ML Detection Agent adds a local machine-learning signal to the A11 SOC
decision chain. It does not replace deterministic triage or analyst approval.
It predicts the most likely attack family from normalized telemetry and gives
triage an additional confidence signal.

## Recommended dataset

Use DataSense: CIC IIoT dataset 2025 as the primary external benchmark for this
project because its classes match the A11 lab topology:

- Benign
- DDoS and DoS: HTTP Flood, TCP SYN Flood, UDP Flood, ICMP Flood, Slowloris
- Recon: Port Scan, OS Scan, Ping Sweep, Vulnerability Scan
- Web: SQL Injection, Blind SQL Injection, XSS, Command Injection
- Bruteforce: SSH and Telnet brute force
- MITM/spoofing
- Mirai-like malware

## Operating model

1. Normalize raw OPNsense, Apache, Suricata or Windows telemetry.
2. Convert the normalized event into text-like features.
3. Score the event with the local JSON Naive Bayes model.
4. Attach `ml_prediction` to the alert triage object.
5. Deterministic triage, RAG and optional local LLM use the ML result as one
   supporting signal.
6. High-risk response actions still require analyst approval.

## Analyst guidance

- Treat ML prediction as a supporting indicator, not final truth.
- Validate the prediction against raw telemetry, event volume and source/dest
  context.
- For HTTP flood / DoS, correlate OPNsense filterlog with Apache access logs
  when possible.
- For SQL injection, inspect the request path, query string and user-agent.
- For reconnaissance, compare the sequence of destination ports and the tool
  fingerprint such as Nmap, Nikto or Dirb.
