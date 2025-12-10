from __future__ import annotations

import argparse
import glob
import json
import logging
import os
import queue
import signal
import sys
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Optional

# Try to use your elasticsearch_output if available, otherwise fallback to internal LogCollector
try:
    from output.elasticsearch_output import ElasticsearchOutput  # type: ignore
    _HAS_ES_OUTPUT = True
except Exception:
    _HAS_ES_OUTPUT = False

# --------------------------
# Logging
# --------------------------
logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s %(message)s")
logger = logging.getLogger("log-pipeline")

# --------------------------
# Helper: graceful shutdown
# --------------------------
SHUTDOWN = threading.Event()


def handle_sig(signum, frame):
    logger.info("Received signal %s — shutting down...", signum)
    SHUTDOWN.set()


signal.signal(signal.SIGINT, handle_sig)
signal.signal(signal.SIGTERM, handle_sig)

# --------------------------
# CSV loader + cleaner
# --------------------------
import pandas as pd


def load_csv(path: str) -> pd.DataFrame:
    try:
        df = pd.read_csv(path, header=0, dtype=str, na_filter=False)
        return df
    except Exception as exc:
        logger.warning("Failed to load CSV %s: %s", path, exc)
        return pd.DataFrame()


def clean_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Apply a minimal cleaning step to remove accidental header rows and ensure required columns."""
    if df.empty:
        return df
    # If numeric columns etc. are present as headers in rows, drop rows that look like headers
    if "time" in df.columns:
        df = df[df["time"].str.contains(r"\d{2}/\d{2}/\d{4}", na=False)]
    required_cols = ["time", "payload", "from", "port", "country"]
    for col in required_cols:
        if col not in df.columns:
            df[col] = None
    return df.reset_index(drop=True)


# --------------------------
# Normalization functions
# --------------------------
import ipaddress
from datetime import timezone

def datetime_to_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def normalize_timestamp(raw_timestamp: str) -> Optional[str]:
    """Convert timestamp to ISO 8601 (expects formats like 'DD/MM/YYYY, HH:MM:SS' or iso)."""
    if not raw_timestamp:
        return None
    raw = raw_timestamp.strip()
    # If already ISO-like, try to parse
    try:
        # Try common ISO parse
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return datetime_to_iso(dt)
    except Exception:
        pass
    # Try d/m/Y, H:M:S
    for fmt in ("%d/%m/%Y, %H:%M:%S", "%d/%m/%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            dt = datetime.strptime(raw, fmt)
            return datetime_to_iso(dt)
        except Exception:
            continue
    return None


def event_type(raw_payload: str) -> str:
    if not isinstance(raw_payload, str) or raw_payload.strip() == "":
        return "empty_payload"
    clean = raw_payload.strip().strip('"').strip("'")
    if clean.startswith("b'\\x16") or clean.startswith('b"\\x16'):
        return "tls_handshake"
    if clean.startswith("GET") or clean.startswith("POST") or "HTTP/1" in clean:
        return "http_request"
    if "SMBr" in clean:
        return "smb_probe"
    return "text_probe"


def normalize_ip(raw_ip: Any) -> Optional[str]:
    if raw_ip is None:
        return None
    s = str(raw_ip).strip().strip("'").strip('"')
    if s == "" or s.lower() == "null":
        return None
    try:
        return str(ipaddress.ip_address(s))
    except ValueError:
        return None


def normalize_port(raw_port: Any) -> Optional[int]:
    if raw_port is None or raw_port == "":
        return None
    s = str(raw_port).strip().strip("'").strip('"')
    if s == "" or s.lower() == "null":
        return None
    try:
        p = int(s)
        return p if 0 <= p <= 65535 else None
    except Exception:
        return None


def normalize_country(raw_country: Any) -> Optional[str]:
    if raw_country is None:
        return None
    s = str(raw_country).strip().strip("'").strip('"')
    if s == "":
        return None
    return s.title()


def row_to_event(row: Dict[str, Any], source: str = "csv") -> Dict[str, Any]:
    """
    Turn a CSV row (dict-like) into a normalized event dict.
    Fields chosen to be friendly to your mappings/more ECS-like names.
    """
    event = {
        "timestamp": normalize_timestamp(row.get("time", "") or ""),
        "source": source,
        "message": row.get("payload") or "",
        "event_type": event_type(row.get("payload") or ""),
        "user": None,
        "src_ip": normalize_ip(row.get("from") or row.get("source_ip") or row.get("source.ip")),
        "dest_ip": None,
        "port": normalize_port(row.get("port")),
        "country": normalize_country(row.get("country")),
        "original": dict(row),  # keep original row for context
    }
    return event


# --------------------------
# Simple Log Collector (DataFrame bulk indexer) - uses requests bulk endpoint
# This is a cleaned-up version of the LogCollector you pasted.
# --------------------------
import requests


class LogCollector:
    def __init__(self, es_host: Optional[str], logs_index: str = "log-pipeline-logs", alerts_index: str = "log-pipeline-alerts", bulk_size: int = 500):
        self.es_host = es_host.rstrip("/") if es_host else None
        self.logs_index = logs_index
        self.alerts_index = alerts_index
        self.bulk_size = max(1, int(bulk_size))
        # session
        self._session = requests.Session()
        self._session.headers.update({"Content-Type": "application/x-ndjson"})

    def _rest_bulk(self, actions: List[str]) -> Optional[Dict[str, Any]]:
        if not self.es_host:
            # fallback: print
            for line in actions:
                print(line)
            return None
        url = f"{self.es_host}/_bulk"
        try:
            resp = self._session.post(url, data="\n".join(actions) + "\n", timeout=30)
            try:
                return resp.json()
            except Exception:
                logger.warning("Bulk response not JSON: %s", resp.text[:200])
                return None
        except Exception as exc:
            logger.exception("Bulk request failed: %s", exc)
            return None

    def bulk_index_events(self, events: List[Dict[str, Any]], index: Optional[str] = None):
        if not events:
            return
        idx = index or self.logs_index
        actions: List[str] = []
        for ev in events:
            actions.append(json.dumps({"index": {"_index": idx}}))
            actions.append(json.dumps(ev))
            if len(actions) >= self.bulk_size * 2:
                self._rest_bulk(actions)
                actions = []
        if actions:
            self._rest_bulk(actions)

    def index_alerts(self, alerts: List[Dict[str, Any]]):
        if not alerts:
            return
        self.bulk_index_events(alerts, index=self.alerts_index)

    def close(self):
        try:
            self._session.close()
        except Exception:
            pass


# --------------------------
# Detection Engine (YAML rules)
# --------------------------
import yaml


class DetectionEngine:
    def __init__(self, rules_path: str = "detections/rules/*.yml"):
        self.rules_path = rules_path
        self.rules = self.load_rules(rules_path)

    def load_rules(self, rules_path: str) -> List[Dict[str, Any]]:
        rules = []
        for rule_file in glob.glob(rules_path):
            try:
                with open(rule_file, "r") as fh:
                    data = yaml.safe_load(fh)
                    if isinstance(data, list):
                        rules.extend(data)
                    else:
                        rules.append(data)
            except Exception as exc:
                logger.warning("Failed to load rule %s: %s", rule_file, exc)
        logger.info("Loaded %d rule(s) from %s", len(rules), rules_path)
        return rules

    # Very small query matcher (string contains on flattened keys)
    def match_query(self, log: Dict[str, Any], query_str: str) -> bool:
        if not query_str:
            return False
        # Split AND (simple) — supports 'field: *"value"*' style from your YAML
        conditions = [c.strip() for c in query_str.split("AND")]
        for cond in conditions:
            if ":" not in cond:
                continue
            field, val = cond.split(":", 1)
            field = field.strip()
            # normalize patterns like *"Failed password"*
            val_clean = val.replace('"', "").replace("'", "").replace("*", "").strip()
            # flatten field: replace '.' with '_' and try common locations
            flat = field.replace(".", "_")
            # check in event top-level and original payload
            candidates = []
            if flat in log:
                candidates.append(str(log.get(flat, "")))
            # check original nested message and process fields
            candidates.append(str(log.get("message", "")))
            candidates.append(str(log.get("original", "")))
            hit = False
            for c in candidates:
                if val_clean.lower() in c.lower():
                    hit = True
                    break
            if not hit:
                return False
        return True

    def run_query_rule(self, rule: Dict[str, Any], logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        alerts = []
        query = rule.get("query", "")
        for log in logs:
            if self.match_query(log, query):
                alerts.append({
                    "timestamp": log.get("timestamp"),
                    "rule_id": rule.get("rule_id"),
                    "rule_name": rule.get("name"),
                    "severity": rule.get("severity"),
                    "risk_score": rule.get("risk_score"),
                    "alert": {
                        "summary": rule.get("description"),
                        "matched_event": log
                    }
                })
        return alerts

    def run_threshold_rule(self, rule: Dict[str, Any], logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        alerts = []
        query = rule.get("query", "")
        threshold = rule.get("threshold", {})
        field = threshold.get("field", "").replace(".", "_")
        value = int(threshold.get("value", 0))
        timeframe = threshold.get("timeframe", "5m")
        # convert timeframe "5m" to minutes
        if timeframe.endswith("m"):
            minutes = int(timeframe[:-1])
        else:
            minutes = int(threshold.get("minutes", 5))
        # bucket by field value
        bucket = defaultdict(list)
        now = datetime.utcnow()
        window_start = now - timedelta(minutes=minutes)
        for log in logs:
            if self.match_query(log, query):
                key = log.get(field)
                if key is None:
                    continue
                # parse timestamp ISO
                ts = log.get("timestamp")
                if not ts:
                    continue
                try:
                    # handle trailing Z
                    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                except Exception:
                    continue
                if dt >= window_start:
                    bucket[key].append(log)
        for key, events in bucket.items():
            if len(events) >= value:
                alerts.append({
                    "timestamp": events[-1].get("timestamp"),
                    "rule_id": rule.get("rule_id"),
                    "rule_name": rule.get("name"),
                    "severity": rule.get("severity"),
                    "risk_score": rule.get("risk_score"),
                    "count": len(events),
                    "field_value": key,
                    "alert": {
                        "summary": rule.get("description"),
                        "logs_sample": events[:10]
                    }
                })
        return alerts

    def evaluate(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Evaluate all rules against provided logs and return list of alerts."""
        all_alerts: List[Dict[str, Any]] = []
        for rule in self.rules:
            rtype = rule.get("type")
            try:
                if rtype == "query":
                    all_alerts.extend(self.run_query_rule(rule, logs))
                elif rtype == "threshold":
                    all_alerts.extend(self.run_threshold_rule(rule, logs))
                else:
                    logger.debug("Unsupported rule type %s for rule %s", rtype, rule.get("rule_id"))
            except Exception as exc:
                logger.exception("Error evaluating rule %s: %s", rule.get("rule_id"), exc)
        return all_alerts


# --------------------------
# Orchestration: batch, detect, index
# --------------------------
def process_dataframe(df: pd.DataFrame, source_name: str = "csv", normalizer_batch: int = 500) -> List[Dict[str, Any]]:
    """Return list of normalized events from dataframe."""
    events: List[Dict[str, Any]] = []
    if df.empty:
        return events
    # Clean & ensure columns
    df = clean_dataframe(df)
    for _, row in df.iterrows():
        row_dict = row.to_dict()
        ev = row_to_event(row_dict, source=source_name)
        # If timestamp absent, use now
        if not ev.get("timestamp"):
            ev["timestamp"] = datetime_to_iso(datetime.utcnow())
        events.append(ev)
    return events


def chunked(iterable: List[Any], size: int):
    for i in range(0, len(iterable), size):
        yield iterable[i:i + size]


def run_pipeline_from_csvs(csv_paths: List[str], es_host: Optional[str], rules_dir: str, batch_size: int = 500, dry_run: bool = False):
    # Setup collector (either your ElasticsearchOutput or built-in LogCollector)
    if _HAS_ES_OUTPUT and es_host:
        es_forwarder = ElasticsearchOutput(es_host=es_host, bulk_size=batch_size)
        use_forwarder = es_forwarder
        logger.info("Using ElasticsearchOutput from output.elasticsearch_output")
    else:
        use_forwarder = LogCollector(es_host=es_host, bulk_size=batch_size)
        logger.info("Using internal LogCollector (REST fallback)")

    engine = DetectionEngine(rules_path=os.path.join(rules_dir, "*.yml"))
    all_events: List[Dict[str, Any]] = []

    # Load all CSVs, normalize into events
    for path in csv_paths:
        if SHUTDOWN.is_set():
            break
        logger.info("Loading CSV: %s", path)
        df = load_csv(path)
        if df.empty:
            logger.info("No rows in %s - skipping", path)
            continue
        df_clean = clean_dataframe(df)
        events = process_dataframe(df_clean, source_name=os.path.basename(path))
        logger.info("Normalized %d events from %s", len(events), path)
        all_events.extend(events)

    # If dry-run just evaluate detections and print
    if dry_run:
        logger.info("Dry-run mode: evaluating detection rules without indexing")
        alerts = engine.evaluate(all_events)
        logger.info("Generated %d alert(s)", len(alerts))
        for a in alerts:
            print(json.dumps(a, indent=2))
        return

    # Index logs in batches and evaluate detection on per-batch basis
    logger.info("Indexing %d events in batches of %d", len(all_events), batch_size)
    for batch in chunked(all_events, batch_size):
        if SHUTDOWN.is_set():
            break
        # index logs
        try:
            use_forwarder.bulk_index_events(batch)
        except Exception:
            logger.exception("Failed to index batch; continuing")

        # run detection on this batch (for threshold rules this implementation is per-batch with time window)
        try:
            alerts = engine.evaluate(batch)
            if alerts:
                logger.info("Generated %d alerts for current batch", len(alerts))
                use_forwarder.index_alerts(alerts)
                for a in alerts:
                    logger.warning("ALERT: %s - %s", a.get("rule_name"), a.get("alert", {}).get("summary"))
        except Exception:
            logger.exception("Detection evaluation failed for a batch")

    logger.info("Done indexing. Flushing and closing forwarder.")
    try:
        if hasattr(use_forwarder, "flush"):
            use_forwarder.flush()  # type: ignore
    except Exception:
        pass
    try:
        use_forwarder.close()
    except Exception:
        pass


# --------------------------
# CLI
# --------------------------
def parse_args():
    p = argparse.ArgumentParser(description="Log Aggregation & Detection Pipeline (CSV -> Detect -> ES)")
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--csv", help="Path to a single CSV file")
    group.add_argument("--dir", help="Directory with CSV files (will glob *.csv)")
    p.add_argument("--es-host", help="Elasticsearch host (e.g. http://localhost:9200). If omitted, will print NDJSON to stdout.")
    p.add_argument("--rules-dir", default="detections/rules", help="Directory containing YAML detection rules")
    p.add_argument("--batch-size", type=int, default=500, help="Batch size for bulk indexing")
    p.add_argument("--dry-run", action="store_true", help="Only run detection and print alerts; do not index")
    return p.parse_args()


def main():
    args = parse_args()
    csv_paths: List[str] = []
    if args.csv:
        csv_paths = [args.csv]
    elif args.dir:
        csv_paths = sorted(glob.glob(os.path.join(args.dir, "*.csv")))

    if not csv_paths:
        logger.error("No CSV files found to process.")
        sys.exit(1)

    logger.info("Starting pipeline with %d CSV(s)", len(csv_paths))
    run_pipeline_from_csvs(csv_paths, es_host=args.es_host, rules_dir=args.rules_dir, batch_size=args.batch_size, dry_run=args.dry_run)
    logger.info("Pipeline finished.")


if __name__ == "__main__":
    main()
