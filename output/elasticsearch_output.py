"""
elasticsearch_output.py
-----------------------

Log/alert output layer for the Log Aggregation & Detection Pipeline.

Features:
- Send normalized logs to an ES index (bulk API)
- Send detection alerts to a separate alerts index
- Optional index creation with simple ECS-inspired mapping
- Batching with flush on size or manual flush()
- Retry with exponential backoff on transient failures
- Fallback to stdout if Elasticsearch is unreachable or not configured

Usage:
    from elasticsearch_output import ElasticsearchOutput

    es = ElasticsearchOutput(
        es_host="http://localhost:9200",
        username=None,
        password=None,
        logs_index="log-pipeline-logs",
        alerts_index="log-pipeline-alerts",
        bulk_size=100,
        max_retries=3,
        verify_ssl=True
    )

    es.send_log(normalized_event_dict)
    es.send_alert(alert_dict)

    # At shutdown
    es.flush()
    es.close()
"""

from typing import Optional, List, Dict, Any
import json
import time
import logging
import threading

# Try to use official client if available (better performance / features)
try:
    from elasticsearch import Elasticsearch, helpers as es_helpers  # type: ignore
    _HAS_ES_CLIENT = True
except Exception:
    _HAS_ES_CLIENT = False

import requests

logger = logging.getLogger("elasticsearch_output")
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s %(message)s"))
    logger.addHandler(ch)


class ElasticsearchOutput:
    def __init__(
        self,
        es_host: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        logs_index: str = "log-pipeline-logs",
        alerts_index: str = "log-pipeline-alerts",
        bulk_size: int = 200,
        max_retries: int = 4,
        backoff_factor: float = 0.5,
        verify_ssl: bool = True,
        create_indices: bool = True,
        default_ttl_days: Optional[int] = None,
    ):
        """
        Args:
            es_host: URL like "http://localhost:9200". If None -> stdout fallback only.
            username/password: optional basic auth for ES.
            logs_index: index name for normalized logs.
            alerts_index: index name for detection alerts.
            bulk_size: flush batch size for bulk indexing.
            max_retries: number of retry attempts for transient errors.
            backoff_factor: multiplier for exponential backoff.
            verify_ssl: whether to verify TLS certs when using HTTPS.
            create_indices: attempt to create indices with basic mapping on init.
            default_ttl_days: optional, for index lifecycle (not implemented here but stored as metadata).
        """
        self.es_host = es_host.rstrip("/") if es_host else None
        self.auth = (username, password) if username and password else None
        self.logs_index = logs_index
        self.alerts_index = alerts_index
        self.bulk_size = max(1, bulk_size)
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.verify_ssl = verify_ssl
        self.create_indices = create_indices
        self.default_ttl_days = default_ttl_days

        self._log_buffer: List[Dict[str, Any]] = []
        self._alert_buffer: List[Dict[str, Any]] = []
        self._lock = threading.RLock()

        self._session = requests.Session()
        if self.auth:
            self._session.auth = self.auth
        self._session.verify = self.verify_ssl
        self._session.headers.update({"Content-Type": "application/x-ndjson"})

        self._es_client = None
        if self.es_host:
            if _HAS_ES_CLIENT:
                try:
                    self._es_client = Elasticsearch(
                        hosts=[self.es_host],
                        http_auth=self.auth,
                        verify_certs=self.verify_ssl,
                        timeout=30
                    )
                    # quick ping
                    if not self._es_client.ping():
                        logger.warning("Elasticsearch client ping failed; falling back to REST mode")
                        self._es_client = None
                except Exception as e:
                    logger.warning("Elasticsearch client init failed: %s; falling back to REST mode", e)
                    self._es_client = None

            if self.create_indices:
                try:
                    self._ensure_index(self.logs_index, kind="logs")
                    self._ensure_index(self.alerts_index, kind="alerts")
                except Exception as e:
                    logger.warning("Index ensure failed: %s", e)

    # ----------------------
    # Index creation / mapping
    # ----------------------
    def _ensure_index(self, index_name: str, kind: str = "logs"):
        """Create index if it doesn't exist with a simple ECS-inspired mapping."""
        if not self.es_host:
            logger.debug("No es_host configured; skipping index creation")
            return

        mapping = {
            "mappings": {
                "properties": {
                    "timestamp": {"type": "date"},
                    "source": {"type": "keyword"},
                    "event": {"type": "object", "enabled": False},
                    "message": {"type": "text"},
                    "user": {"type": "keyword"},
                    "src_ip": {"type": "ip"},
                    "dest_ip": {"type": "ip"},
                    "process": {"type": "object", "enabled": False},
                    "rule_id": {"type": "keyword"},
                    "rule_name": {"type": "keyword"},
                    "severity": {"type": "keyword"},
                    "risk_score": {"type": "integer"},
                }
            }
        }

        # Alerts may have additional fields
        if kind == "alerts":
            mapping["mappings"]["properties"].update({
                "alert": {"type": "object", "enabled": False},
                "count": {"type": "integer"},
                "field_value": {"type": "keyword"}
            })

        if self._es_client:
            if not self._es_client.indices.exists(index=index_name):
                logger.info("Creating index %s via client", index_name)
                self._es_client.indices.create(index=index_name, body=mapping)
            else:
                logger.debug("Index %s already exists", index_name)
        else:
            # Use REST
            url = f"{self.es_host}/{index_name}"
            resp = self._session.head(url)
            if resp.status_code == 404:
                logger.info("Creating index %s via REST", index_name)
                create_resp = self._session.put(url, json=mapping)
                if not (200 <= create_resp.status_code < 300):
                    logger.warning("Failed to create index %s: %s - %s", index_name, create_resp.status_code, create_resp.text)

    # ----------------------
    # Public API
    # ----------------------
    def send_log(self, event: Dict[str, Any]):
        """Add a normalized event to the log buffer and flush if needed."""
        with self._lock:
            self._log_buffer.append(event)
            if len(self._log_buffer) >= self.bulk_size:
                self._flush_logs_locked()

    def send_alert(self, alert: Dict[str, Any]):
        """Add an alert to the alert buffer and flush if needed."""
        with self._lock:
            self._alert_buffer.append(alert)
            if len(self._alert_buffer) >= self.bulk_size:
                self._flush_alerts_locked()

    def flush(self):
        """Public flush - sends whatever is in buffers to ES (or stdout)."""
        with self._lock:
            self._flush_logs_locked()
            self._flush_alerts_locked()

    def close(self):
        """Flush and close resources."""
        try:
            self.flush()
        except Exception as e:
            logger.exception("Error during flush on close: %s", e)
        try:
            self._session.close()
        except Exception:
            pass
        if self._es_client:
            try:
                self._es_client.transport.close()
            except Exception:
                pass

    # ----------------------
    # Internal flush helpers
    # ----------------------
    def _flush_logs_locked(self):
        if not self._log_buffer:
            return
        buffer_copy = self._log_buffer
        self._log_buffer = []
        self._bulk_index(buffer_copy, index=self.logs_index)

    def _flush_alerts_locked(self):
        if not self._alert_buffer:
            return
        buffer_copy = self._alert_buffer
        self._alert_buffer = []
        self._bulk_index(buffer_copy, index=self.alerts_index)

    # ----------------------
    # Bulk indexing implementations
    # ----------------------
    def _bulk_index(self, docs: List[Dict[str, Any]], index: str):
        if not docs:
            return

        logger.info("Indexing %d documents into index '%s' (bulk_size=%d)", len(docs), index, self.bulk_size)
        if self._es_client:
            # Use official client's bulk helper (handles chunking)
            actions = []
            for doc in docs:
                # ensure timestamp exists (ELK-friendly)
                actions.append({"_index": index, "_source": doc})
            try:
                success, errors = es_helpers.bulk(self._es_client, actions, max_retries=self.max_retries)
                # helpers.bulk returns (success_count, errors_list) or raises on fatal errors
                logger.info("Bulk API success: %s documents", success)
                if errors:
                    logger.debug("Bulk errors: %s", errors)
            except Exception as exc:
                logger.exception("Bulk index via client failed: %s. Falling back to REST bulk", exc)
                # fallback to REST NDJSON bulk
                self._rest_bulk_index(docs, index)
        else:
            # REST path
            self._rest_bulk_index(docs, index)

    def _rest_bulk_index(self, docs: List[Dict[str, Any]], index: str):
        """
        Build NDJSON payload and call POST /_bulk. Basic retry/backoff implemented.
        """
        url = f"{self.es_host}/_bulk"
        ndjson_lines = []
        for doc in docs:
            action_meta = {"index": {"_index": index}}
            ndjson_lines.append(json.dumps(action_meta))
            ndjson_lines.append(json.dumps(doc))
        body = "\n".join(ndjson_lines) + "\n"

        attempt = 0
        while attempt <= self.max_retries:
            attempt += 1
            try:
                resp = self._session.post(url, data=body, timeout=30)
                if 200 <= resp.status_code < 300:
                    rj = resp.json()
                    if rj.get("errors"):
                        # Partial failures
                        logger.warning("Bulk API returned partial errors: %s", rj.get("items", [])[:3])
                    else:
                        logger.info("REST bulk succeeded (%d docs)", len(docs))
                    return
                else:
                    logger.warning("REST bulk failed: %s - %s", resp.status_code, resp.text[:200])
            except requests.RequestException as exc:
                logger.warning("REST bulk request exception (attempt %d): %s", attempt, exc)

            sleep_time = self.backoff_factor * (2 ** (attempt - 1))
            logger.debug("Retrying in %.2f seconds", sleep_time)
            time.sleep(sleep_time)

        # After retries exhausted -> fallback to stdout for durability
        logger.error("Bulk indexing failed after %d attempts. Falling back to stdout for %d docs.", self.max_retries, len(docs))
        for d in docs:
            print(json.dumps(d))

    # ----------------------
    # Convenience single index (useful for development)
    # ----------------------
    def index_single(self, doc: Dict[str, Any], index: str):
        """Index a single document. Attempt to use client, then REST, then stdout."""
        if self._es_client:
            try:
                self._es_client.index(index=index, document=doc)
                return True
            except Exception as exc:
                logger.warning("Client single index failed, falling back to REST: %s", exc)
        if self.es_host:
            url = f"{self.es_host}/{index}/_doc"
            attempt = 0
            while attempt <= self.max_retries:
                attempt += 1
                try:
                    resp = self._session.post(url, json=doc, timeout=20)
                    if 200 <= resp.status_code < 300:
                        return True
                    else:
                        logger.warning("REST single index failed: %s - %s", resp.status_code, resp.text[:200])
                except requests.RequestException as exc:
                    logger.warning("REST single index exception (attempt %d): %s", attempt, exc)
                time.sleep(self.backoff_factor * (2 ** (attempt - 1)))

        # Final fallback: print
        logger.warning("Indexing single doc failed; printing to stdout")
        print(json.dumps(doc))
        return False


# ----------------------
# Example integration helper
# ----------------------
def make_default_event(original_line: str, source: str = "stdin") -> Dict[str, Any]:
    """Create a minimal normalized event structure if you need a default / placeholder."""
    return {
        "timestamp": datetime_to_iso_now(),
        "source": source,
        "message": original_line,
        "event": {"action": None},
        "user": None,
        "src_ip": None,
        "process": {"name": None, "executable": None},
        "original": original_line
    }


def datetime_to_iso_now():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


# ----------------------
# If run as script - small demo
# ----------------------
if __name__ == "__main__":
    import argparse
    from datetime import datetime, timezone

    parser = argparse.ArgumentParser(description="Elasticsearch output demo for log-pipeline")
    parser.add_argument("--es-host", help="Elasticsearch host (http://localhost:9200)", default=None)
    parser.add_argument("--logs-index", default="log-pipeline-logs")
    parser.add_argument("--alerts-index", default="log-pipeline-alerts")
    parser.add_argument("--bulk-size", type=int, default=10)
    args = parser.parse_args()

    es_out = ElasticsearchOutput(
        es_host=args.es_host,
        logs_index=args.logs_index,
        alerts_index=args.alerts_index,
        bulk_size=args.bulk_size
    )

    # Simple demo: index a few fake logs and an alert
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    sample_logs = [
        {"timestamp": now, "source": "sample", "message": "Failed password for root", "event": {"action": "login_failed"}, "user": "root", "src_ip": "203.0.113.5", "process": {"name": "sshd"}},
        {"timestamp": now, "source": "sample", "message": "Accepted password for alice", "event": {"action": "login_success"}, "user": "alice", "src_ip": "198.51.100.8", "process": {"name": "sshd"}}
    ]

    for sl in sample_logs:
        es_out.send_log(sl)

    sample_alert = {
        "timestamp": now,
        "rule_id": "ssh_bruteforce_001",
        "rule_name": "SSH Bruteforce Attempts",
        "severity": "high",
        "count": 12,
        "field_value": "203.0.113.5",
        "alert": {
            "summary": "12 failed SSH logins from same IP in 5m",
            "logs_sample": sample_logs
        }
    }
    es_out.send_alert(sample_alert)

    logger.info("Flushing...")
    es_out.flush()
    logger.info("Done.")
