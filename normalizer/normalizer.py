import pandas as pd
import ipaddress
from datetime import datetime

# 1️⃣ Load CSV
df_logs = pd.read_csv("sample_logs/london.csv", header=0)

# Drop accidental header rows if any
df_logs = df_logs[df_logs["time"].str.contains(r"\d{2}/\d{2}/\d{4}", na=False)]

# 2️⃣ Define normalization functions

def normalize_timestamp(raw_timestamp: str) -> str | None:
    """Convert timestamp to ISO 8601 format with Zulu time."""
    if raw_timestamp is None or raw_timestamp.strip() == "":
        return None
    try:
        dt = datetime.strptime(raw_timestamp, "%d/%m/%Y, %H:%M:%S")
        return dt.isoformat() + "Z"
    except ValueError:
        return None

def event_type(raw_payload: str) -> str:
    """Determine event type based on payload content."""
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

def normalize_ip(raw_ip: str) -> str | None:
    """Clean and validate IP addresses."""
    if raw_ip is None:
        return None
    clean_ip = raw_ip.strip().strip("'").strip('"')
    if clean_ip == "" or clean_ip.lower() == "null":
        return None
    try:
        return str(ipaddress.ip_address(clean_ip))
    except ValueError:
        return None

def normalize_port(raw_port: str | int) -> int | None:
    """Normalize port numbers to integers in range 0–65535."""
    if raw_port is None:
        return None
    if isinstance(raw_port, str):
        cleaned = raw_port.strip().strip("'").strip('"')
    else:
        cleaned = str(raw_port)
    if cleaned == "" or cleaned.lower() == "null":
        return None
    try:
        port_int = int(cleaned)
        return port_int if 0 <= port_int <= 65535 else None
    except ValueError:
        return None

def normalize_country(raw_country: str) -> str | None:
    """Clean country names by stripping quotes and whitespace."""
    if raw_country is None:
        return None
    clean_country = raw_country.strip().strip("'").strip('"')
    if clean_country == "":
        return None
    return clean_country.title()  # Optional: standardize case

# 3️⃣ Apply all normalizations using .apply()
df_logs["normalized_time"] = df_logs["time"].apply(normalize_timestamp)
df_logs["event_type"] = df_logs["payload"].apply(event_type)
df_logs["normalized_ip"] = df_logs["from"].apply(normalize_ip)
df_logs["normalized_port"] = df_logs["port"].apply(normalize_port)
df_logs["normalized_country"] = df_logs["country"].apply(normalize_country)

# 5️⃣ Inspect first few rows
print(df_logs.head(10))

