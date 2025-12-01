import pandas as pd
import json
from datetime import datetime
import re
import ipaddress
from typing import Dict, Any

df_logs = pd.read_csv("sample_logs/london.csv", header=0)

# Drop accidental header rows
df_logs = df_logs[df_logs["time"].str.contains(r"\d{2}/\d{2}/\d{4}", na=False)]


def normalize_timestamp(raw_timestamp: str) -> str:
    """
    Convert a single raw timestamp string to ISO 8601 format with Zulu time.
    """
    dt = datetime.strptime(raw_timestamp, "%m/%d/%Y, %H:%M:%S")
    return dt.isoformat() + "Z"

# Normalize Timestamps to ISO 8601 standard
normalized_list = []
# Iterate through each row in timestamp
for index, row in df_logs.iterrows():
    # Extract the timestamp
    raw_timestamp = row["time"]
    # Normalize the timestamp and append to the list
    normalized_ts = normalize_timestamp(raw_timestamp)
    normalized_list.append(normalized_ts)
df_logs["normalized_time"] = normalized_list


def event_type(raw_payload: str) -> str:
    """
    Determine the event type based on the payload content.
    """

    if not isinstance(raw_payload, str) or raw_payload.strip() == "":
        return "empty_payload"

    # Remove outer quotes if they exist
    clean = raw_payload.strip().strip('"').strip("'")

    # TLS Handshake (binary TLS bytes always start with \x16 03)
    if clean.startswith("b'\\x16") or clean.startswith('b"\\x16'):
        return "tls_handshake"

    # HTTP request
    if clean.startswith("GET") or clean.startswith("POST") or "HTTP/1" in clean:
        return "http_request"

    # SMB scan
    if "SMBr" in clean:
        return "smb_probe"

    # Completely empty
    if clean == "":
        return "empty_payload"

    return "text_probe"


normalized_event_type = []

for index, row in df_logs.iterrows():
    raw_payload = row["payload"]
    normalized_event = event_type(raw_payload)
    normalized_event_type.append(normalized_event)

df_logs["event_type"] = normalized_event_type




