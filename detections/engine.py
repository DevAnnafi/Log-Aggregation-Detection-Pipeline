import yaml
import glob
import time
from datetime import datetime, timedelta
from collections import defaultdict


class DetectionEngine:
    def __init__(self, rules_path="detections/rules/*.yaml"):
        self.rules = self.load_rules(rules_path)

    def load_rules(self, rules_path):
        rules = []
        for rule_file in glob.glob(rules_path):
            with open(rule_file, "r") as f:
                rule = yaml.safe_load(f)
                rules.append(rule)
        print(f"[+] Loaded {len(rules)} detection rules")
        return rules

    def match_query(self, log, query_str):
        """
        Very simple query matcher:
        - supports fields like: process.name, source.ip, message
        - supports contains: value in log[field]
        """
        conditions = [x.strip() for x in query_str.split("AND")]

        for cond in conditions:
            # example: message:*"Failed password"*
            if ":" not in cond:
                continue

            field, value = cond.split(":", 1)
            field = field.strip()
            value = value.replace('"', "").replace("*", "").strip()

            field_flat = field.replace(".", "_")

            if field_flat not in log:
                return False

            if value.lower() not in str(log[field_flat]).lower():
                return False

        return True

    def run_query_rule(self, rule, logs):
        alerts = []
        query = rule["query"]

        for log in logs:
            if self.match_query(log, query):
                alerts.append({
                    "rule_name": rule["name"],
                    "timestamp": log.get("timestamp"),
                    "log": log
                })
        return alerts

    def run_threshold_rule(self, rule, logs):
        alerts = []
        query = rule["query"]
        field = rule["threshold"]["field"].replace(".", "_")
        value = rule["threshold"]["value"]
        timeframe = rule["threshold"]["timeframe"]

        # Convert timeframe "5m" to minutes
        minutes = int(timeframe.replace("m", ""))

        bucket = defaultdict(list)

        for log in logs:
            if self.match_query(log, query):
                if field in log:
                    bucket[log[field]].append(log)

        for key, events in bucket.items():
            # Filter events in the last X minutes
            now = datetime.utcnow()
            window_start = now - timedelta(minutes=minutes)
            recent_events = [
                e for e in events
                if datetime.fromisoformat(e["timestamp"].replace("Z", "")) >= window_start
            ]

            if len(recent_events) >= value:
                alerts.append({
                    "rule_name": rule["name"],
                    "count": len(recent_events),
                    "field_value": key,
                    "timestamp": recent_events[-1]["timestamp"],
                    "logs": recent_events
                })

        return alerts

    def run(self, logs):
        all_alerts = []

        for rule in self.rules:
            rule_type = rule["type"]

            if rule_type == "query":
                alerts = self.run_query_rule(rule, logs)

            elif rule_type == "threshold":
                alerts = self.run_threshold_rule(rule, logs)

            else:
                print(f"[!] Unsupported rule type: {rule_type}")
                continue

            all_alerts.extend(alerts)

        return all_alerts


# Example usage:
if __name__ == "__main__":
    engine = DetectionEngine()

    # simulate logs
    sample_logs = [
        {
            "timestamp": "2025-12-02T21:55:00Z",
            "source_ip": "192.168.1.10",
            "message": "Failed password for root",
            "process_name": "",
        },
        {
            "timestamp": "2025-12-02T21:56:10Z",
            "process_name": "python3",
            "process_executable": "/tmp/malware.py"
        }
    ]

    alerts = engine.run(sample_logs)

    for alert in alerts:
        print("\n=== ALERT ===")
        print(alert)
