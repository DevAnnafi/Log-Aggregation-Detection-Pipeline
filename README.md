# 🔐 Log Aggregation & Detection Pipeline (Python + ELK)

A production-inspired, security‑focused log ingestion and detection pipeline built with **Python**, **YAML-based detection rules**, and optional **Elasticsearch/Kibana** output. This project mimics real-world SIEM/observability workflows and demonstrates hands-on skills in:

* Log engineering & parsing
* Normalization into structured schema (ECS‑inspired)
* Detection-as-code (Sigma-like rules)
* Python automation & backend logic
* Security analysis at scale
* Dashboarding & visualization using ELK

Perfect for Security Engineering / Detection Engineering internship applications (Datadog, CrowdStrike, Cloudflare, Palo Alto, etc.).

---

## 🚀 Features

* **Real-time log collector** (`tail -f` style)
* **Normalization layer** → Converts raw log strings into structured JSON
* **Detection engine** powered by **YAML rules**
* **Elasticsearch output** for visualization and analysis
* **Extensible architecture** for additional sources (syslog, API logs, Windows)
* **Sample SSH brute-force logs and rules** included

---

## 📁 Project Structure

```
log-pipeline/
├── collector/
│   └── log_collector.py
├── normalizer/
│   └── normalizer.py
├── detections/
│   ├── engine.py
│   └── rules/
│       ├── ssh_bruteforce.yml
│       └── suspicious_process.yml
├── output/
│   └── elasticsearch_output.py
├── sample_logs/
│   └── auth.log
├── main.py
└── README.md
```

---

## 🧠 Architecture Overview

### **1. Collector (Ingestion Layer)**

Streams logs from:

* Linux `/var/log/auth.log`
* Flat files
* Future expansion: Windows Event Logs, Syslog, API ingestion

### **2. Normalizer**

Converts messy raw logs into clean structured fields like:

```json
{
  "timestamp": "2025-11-27T10:15:01Z",
  "source": "auth.log",
  "event": {"action": "login_failed"},
  "user": "admin",
  "src_ip": "192.0.2.1",
  "process": {"name": "sshd"}
}
```

### **3. Detection Engine**

Loads `.yml` rule files and evaluates conditions using a lightweight rule interpreter.

Example rule (`ssh_bruteforce.yml`):

```yaml
id: ssh-bruteforce
name: SSH Brute Force Attempt
condition: "action == 'login_failed' and src_ip is not None"
severity: high
```

### **4. Output Layer → Elasticsearch**

* Logs → `log-pipeline-logs` index
* Alerts → `log-pipeline-alerts` index
* Viewable in **Kibana dashboards**

---

## 🧪 Example: Log Collector Snippet

```python
def tail_logs(file_path):
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.2)
                continue
            yield {"raw": line.strip(), "path": file_path}
```

---

## 📜 Example Detection Rule

```yaml
id: suspicious-process
name: Suspicious Process Execution
condition: "'sudo' in event_dict.get('original', '') or 'rm -rf' in event_dict.get('original', '')"
severity: medium
```

---

## 📊 Kibana Visualization Ideas

Once your logs are ingested, you can build dashboards such as:

* 🔥 **SSH brute force heatmap by source IP**
* 📈 **Failed logins over time**
* 🧭 **GeoIP world map of attacker locations**
* 🚨 **Top triggered detection rules**

---

## ▶️ Running the Pipeline

### **Local Execution (stdout mode)**

```
python main.py --log-file sample_logs/auth.log
```

### **With Elasticsearch Output**

```
python main.py --log-file sample_logs/auth.log --es-host http://localhost:9200
```

---

## 🔧 Future Enhancements

* Docker Compose (Pipeline + ES + Kibana)
* Syslog listener support
* MITRE ATT&CK mapping
* Sliding-window brute-force detection (stateful)
* Replace `eval` with safe rule evaluator (AST/DSL)

---

If you'd like, I can also:
✔ Add badges & visuals (architecture diagram, screenshots)
✔ Generate a Docker Compose setup
✔ Add GitHub Actions CI & unit tests
✔ Make this README even more flashy for recruiters

