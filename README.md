
# Python Network Intrusion Detection System (IDS)

A learning project that monitors TCP network traffic, extracts traffic features, detects potentially suspicious activity using rule-based heuristics and machine learning, and logs security alerts.

## Overview

This project explores the fundamentals of network security and intrusion detection using Python. It combines packet capture, traffic analysis, signature-based detection, and an anomaly detection model built with Scikit-learn.

The project is intended for educational purposes and as a foundation for further experimentation with network monitoring and cybersecurity.

## Features

- **Packet capture:** Capture IPv4/TCP packets using Scapy.
- **Traffic analysis:** Extract packet size, flow duration, packet rate, byte rate, TCP flags, and TCP window size.
- **Rule-based detection:** Apply simple heuristics to identify suspicious SYN traffic and potential port-scanning activity.
- **Anomaly detection:** Use Scikit-learn's Isolation Forest to identify traffic features that differ from a learned baseline.
- **Alert logging:** Record detected threats in a log file.
- **Automated tests:** Test detection rules and packet-analysis behavior using Python's `unittest` framework.

## Project Structure

```text
IDS/
├── AlertSystem.py
├── DetectionEngine.py
├── IntrusionDetectionSystem.py
├── PacketCapture.py
├── TrafficAnalyzer.py
├── collect_baseline.py
├── train_model.py
├── test.py
├── requirements.txt
├── .gitignore
└── README.md
```

Generated files such as trained models, captured traffic, local datasets, and logs may be created when running the project. They should not be committed unless intentionally prepared for distribution.

## Technologies

- Python
- Scapy
- NumPy
- Scikit-learn
- Joblib
- Threading and queues
- Python logging
- `unittest`

## Requirements

- Python 3.11 or newer, subject to compatibility with the installed dependencies
- Linux or another Scapy-supported operating system
- Network interface access for live packet capture
- Elevated privileges or appropriate packet-capture capabilities for live capture

## Installation

### 1. Clone the repository

```bash
git clone <YOUR-REPOSITORY-URL>
cd IDS
```

Replace `<YOUR-REPOSITORY-URL>` with your GitHub repository URL.

### 2. Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If `requirements.txt` does not exist yet, create it with the project's direct dependencies:

```text
scapy
numpy
scikit-learn
joblib
```

After confirming that the project works, consider pinning the dependency versions you have tested.

## Running the Tests

Run the automated test suite without root privileges:

```bash
.venv/bin/python test.py
```

The tests cover:

- Normal feature values that should not trigger signature rules
- High-rate SYN traffic
- The port-scan heuristic
- Slow SYN traffic
- Packet-analysis behavior
- Ignoring non-TCP packets

The tests use synthetic packets and feature values. They do not generate real attacks or establish real-world detection accuracy.

## Collecting a Traffic Baseline

The project includes `collect_baseline.py` for collecting traffic features to use as a normal-traffic baseline.

Review the script before running it. Confirm the network interface and collection duration, and collect data only on networks you own or are authorized to monitor.

A representative, clean baseline is important for meaningful anomaly detection. Unstable flow-rate calculations or a baseline containing unusual activity can reduce detection quality.

## Training the Anomaly Detector

The project includes `train_model.py` for training an Isolation Forest model from baseline data.

Before training, ensure that:

- The dataset contains the features expected by the model.
- Values are finite and correctly ordered.
- The data reasonably represents normal traffic.
- Training and inference use the same feature definitions and preprocessing.

The generated model file is a local artifact and should not be committed unless you intentionally choose to distribute it.

## Running the IDS

Review `IntrusionDetectionSystem.py` and set the network interface to one available on your system.

For example:

```python
ids = IntrusionDetectionSystem(interface="wlan0")
ids.start()
```

Run the program with the required packet-capture privileges:

```bash
sudo .venv/bin/python IntrusionDetectionSystem.py
```

Replace `wlan0` with your actual interface name. You can inspect available interfaces with:

```bash
ip link
```

Stop the program with `Ctrl+C`.

Detected alerts are written to `ids_alerts.log`, depending on which detection rules are triggered and how the alert system is configured.

## Detection Approach

### Rule-based detection

The current detection engine uses simple feature thresholds to flag suspicious traffic patterns, including:

- High-rate TCP SYN traffic
- Small packets observed at a high rate

These rules are preliminary heuristics. They can produce false positives and false negatives and should not be treated as definitive evidence of an attack.

### Machine-learning anomaly detection

Isolation Forest learns patterns from the supplied baseline and identifies feature combinations that differ from those learned patterns.

An anomaly is not necessarily malicious. Unusual legitimate traffic may be flagged, while attacks that resemble the baseline may go undetected.

## Current Limitations

- Supports IPv4/TCP traffic rather than all network protocols.
- Detection rules are basic and require further validation.
- Port-scan detection is currently heuristic-based and does not yet establish a scan by tracking destination-port diversity over time.
- Packet-rate and byte-rate calculations need careful handling of very short flow durations and should be validated before relying on their results.
- The quality of machine-learning detection depends on the training baseline and consistent feature processing.
- The project logs alerts but does not automatically block traffic.
- Passing unit tests confirms expected behavior for tested cases, not production-level security effectiveness.

## Future Improvements

- Implement time-window-based traffic statistics.
- Track destination ports and connection attempts per source IP.
- Add tests for alert logging and end-to-end packet processing.
- Improve flow management and capture shutdown behavior.
- Evaluate detection performance using labeled datasets and metrics such as precision, recall, and false-positive rate.
- Add configurable thresholds and command-line arguments.
- Improve alert formatting and severity handling.
- Expand protocol support and add documentation for reproducible experiments.

## Responsible Use

Use this project only on networks and systems you own or have explicit permission to monitor. Follow applicable laws, organizational policies, and privacy requirements.

Packet captures and traffic datasets may contain sensitive information. Review them before sharing, and avoid committing private traffic, credentials, logs, or other sensitive data to a public repository.

## Disclaimer

This is an educational project and is not a replacement for a professionally maintained intrusion detection or network security platform. It has not been established as suitable for production security monitoring.

## Author

Developed as a hands-on project to learn Python, network traffic analysis, machine learning, and cybersecurity fundamentals.

Feedback, suggestions, and constructive contributions are welcome.
