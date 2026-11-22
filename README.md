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


## Automated Security Response — nftables Manager

HoneyShield AI includes an automated security response mechanism based on Suricata, Python, MongoDB, and nftables.

### Architecture

The security monitoring process collects Suricata alerts and generates an initial decision. The Threat History Analyzer calculates a historical risk score using security events stored in MongoDB.

The `nftables_manager.py` component retrieves the resulting decision and score from the `security_decisions` collection, evaluates the appropriate response, and dynamically updates nftables.

**Processing flow:**

Suricata → Realtime Monitor → Threat History Analyzer → MongoDB → nftables Manager → nftables

Successful firewall modifications are recorded in the MongoDB `firewall_changes` collection.

### Decision Policy

| Initial Decision | Historical Score | Final Action |
|---|---|---|
| MONITOR | 0–59 | NO_CHANGE |
| MONITOR | 60–100 | REDIRECT |
| INVESTIGATE | 0–59 | NO_CHANGE |
| INVESTIGATE | 60–79 | REDIRECT |
| INVESTIGATE | 80–100 | BLOCK |

The manager supports three actions:

- **NO_CHANGE:** Preserve existing firewall rules.
- **REDIRECT:** Add the source IP to the `redirected_sources` nftables set. SSH connections to the designated HoneyShield honeypot endpoint are redirected to Cowrie.
- **BLOCK:** Add the source IP to the `blocked_sources` nftables set, preventing its forwarded traffic through the configured firewall policy.

BLOCK takes priority over REDIRECT. Explicit UNBLOCK functionality allows the administrator to remove a restriction.

### Technical Implementation

- `engine/nftables_manager.py`: Decision evaluation, nftables updates, MongoDB monitoring, change logging, and administrative actions.
- `config/nftables.nft`: Firewall configuration, filtering rules, dynamic sets, and NAT redirection.
- `config/honeyshield-nftables-manager.service`: systemd service configuration for continuous execution.
- MongoDB `security_decisions`: Source of decisions and historical scores.
- MongoDB `firewall_changes`: Audit trail for effective firewall modifications.

The manager keeps track of processed decisions using local SQLite state, avoiding reliance solely on MongoDB ObjectId ordering.

### Validation Results

The following laboratory scenarios were successfully tested:

1. MONITOR with score 35 → NO_CHANGE.
2. MONITOR with score 70 → REDIRECT.
3. INVESTIGATE with score 90 → BLOCK.
4. SSH redirection from Kali Linux to Cowrie.
5. HTTP connection blocked after adding the Kali IP to the blocking set.
6. Manual UNBLOCK and restoration of HTTP access.
7. Audit logging in MongoDB.
8. Automatic processing of new decisions through systemd.

The REDIRECT and BLOCK automation tests used controlled test decisions inserted into MongoDB. They validate the response mechanism, not the accuracy of attack detection.

### Scope and Limitations

This implementation is a cybersecurity laboratory prototype. Automatic actions are restricted to the designated Kali Linux source IP.

The historical risk score and decision thresholds are experimental. The redirect mechanism applies to the configured SSH honeypot endpoint.

Restoration after reloading nftables has been tested. Full virtual-machine reboot persistence has not been validated.

The Deep Learning integration is outside the scope of this validation.