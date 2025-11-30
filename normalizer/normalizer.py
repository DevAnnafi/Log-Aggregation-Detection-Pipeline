import pandas as pd
import json
from datetime import datetime
import re
import ipaddress
from typing import Dict, Any

df_logs = pd.read_csv("sample_logs/london.csv")

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


print(normalize_timestamp("05/01/2021, 19:42:28"))
   







