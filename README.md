# HoneyShield AI

**Network Intrusion Detection, SSH Honeypot and Threat History Analysis**

## 1. Project Overview

HoneyShield AI is a university cybersecurity project designed to monitor network activity, detect suspicious events, redirect designated SSH traffic to a honeypot, and maintain a historical database of security events.

The project combines network security, Python automation and NoSQL technologies.

The current implementation uses rule-based detection and historical scoring. Deep Learning is considered a future improvement.

## 2. Architecture

The project uses four virtual machines managed with Oracle VirtualBox:

| Virtual Machine | Role |
|---|---|
| HoneyShield | Network monitoring, Suricata IDS, nftables firewall and Python decision engine |
| Real-Server | Protected HTTP service and MongoDB database |
| Cowrie | SSH honeypot for observing simulated attacker interactions |
| Kali Linux | Security testing and traffic generation |

### Network Communication

- Kali generates HTTP and SSH test traffic.
- Suricata generates network security events.
- nftables filters traffic and redirects designated SSH connections to Cowrie.
- Python analyzes Suricata alerts and assigns a security decision.
- MongoDB stores alerts, decisions and Cowrie events.
- The Threat History Analyzer calculates historical risk scores based on recorded activity.

## 3. Technologies

- Oracle VirtualBox
- Ubuntu Server
- Kali Linux
- Suricata IDS
- nftables
- Cowrie SSH Honeypot
- Python 3
- MongoDB
- PyMongo
- SSH and SCP
- systemd

## 4. Main Features

### Network Monitoring

Suricata monitors traffic and generates security events in `eve.json`.

### Security Decision Engine

A Python monitoring service analyzes alerts and produces decisions such as:

- `MONITOR`
- `INVESTIGATE`

### Threat History Analyzer

The historical analyzer uses MongoDB data to evaluate previous activity associated with an IP address.

It calculates a rule-based score from 0 to 100 and assigns a risk level.

### Cowrie Honeypot

Selected SSH connections are redirected to Cowrie, where simulated login attempts and commands can be recorded.

### MongoDB Storage

The project uses three main collections:

- `suricata_alerts`
- `security_decisions`
- `cowrie_sessions`

### Automated Collection

systemd services and timers automate monitoring, Cowrie log collection and MongoDB synchronization.

### Resilience

Security events are also written to local JSONL logs. The synchronization module can recover events that were recorded while MongoDB was unavailable.

## 5. Repository Structure

```text
honeyshield-ai/
├── engine/
│   ├── collect_cowrie.sh
│   ├── cowrie_collector.py
│   ├── decision_engine.py
│   ├── mongodb_client.py
│   ├── realtime_monitor_history.py
│   ├── sync_mongodb.py
│   └── threat_history_analyzer.py
├── tests/
│   ├── mongodb_test.py
│   └── test_log_rotation.py
├── config/
│   └── mongodb.env.example
├── requirements.txt
└── README.md
```

## 6. Python Setup

Create a Python virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

Create a MongoDB configuration file from the example:

```bash
cp config/mongodb.env.example config/mongodb.env
```

Update the credentials for your own MongoDB instance.

The complete laboratory also requires Suricata, Cowrie, nftables and systemd configuration. Python installation alone does not recreate the full network environment.

## 7. Monitoring and Verification

On a configured HoneyShield VM, check the monitoring service:

```bash
sudo systemctl status honeyshield-monitor.service
```

View monitoring logs:

```bash
sudo journalctl -u honeyshield-monitor.service -n 30 --no-pager
```

Check the MongoDB synchronization timer:

```bash
systemctl is-active honeyshield-mongodb-sync.timer
```

Check the Cowrie collection timer:

```bash
systemctl is-active honeyshield-cowrie-collector.timer
```

## 8. Demonstration

In the isolated laboratory environment, an HTTP test can be generated from Kali:

```bash
curl http://10.10.20.20/honeyshield-test
```

The monitoring service detects the corresponding Suricata alert, calculates the historical risk score and records the decision in MongoDB.

SSH redirection can also be demonstrated through the designated honeypot port.

## 9. Current Limitations

- The SSH redirection is configured statically using nftables.
- Historical risk scores enrich monitoring decisions but do not yet trigger dynamic firewall actions.
- The system uses rule-based scoring rather than a trained Deep Learning model.
- Suricata log-rotation handling has been tested with a simulated file truncation; additional real-world rotation tests would improve confidence.

## 10. Future Improvements

Potential improvements include:

- Deep Learning-based intrusion classification.
- Dynamic security actions based on historical risk.
- A security monitoring dashboard.
- Improved log-rotation reliability.
- Advanced threat correlation and behavioral analysis.

## 11. Security Notice

This project is intended for educational use in an isolated, authorized virtual laboratory.

Do not commit real passwords, SSH private keys, MongoDB credentials or sensitive security logs to the repository.
