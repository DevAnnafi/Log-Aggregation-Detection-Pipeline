import json
import requests
import pandas as pd

class LogCollector:
    def __init__(self, es_host: str, index: str, bulk_size: int = 500):
        self.es_host = es_host
        self.index = index
        self.bulk_size = bulk_size

    def bulk_index(self, df: pd.DataFrame):
        if df.empty:
            return

        buffer = []
        for _, row in df.iterrows():
            action = {"index": {"_index": self.index}}
            buffer.append(json.dumps(action))
            buffer.append(json.dumps(row.to_dict()))
            if len(buffer) >= self.bulk_size * 2:
                self.flush(buffer)
                buffer.clear()

        if buffer:
            self.flush(buffer)

    def flush(self, buffer):
        body = "\n".join(buffer) + "\n"
        url = f"{self.es_host}/_bulk"
        r = requests.post(url, data=body, headers={"Content-Type": "application/json"})
        try:
            result = r.json()
            if result.get("errors"):
                print("Bulk index errors detected.")
        except:
            print("Bulk response not JSON:", r.text)


def load_csv(path: str) -> pd.DataFrame:
    try:
        return pd.read_csv(path, header=0)
    except:
        return pd.DataFrame()


def clean_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df
    df = df[df["time"].str.contains(r"\d{2}/\d{2}/\d{4}", na=False)]
    required_cols = ["time", "payload", "from", "port", "country"]
    for col in required_cols:
        if col not in df.columns:
            df[col] = None
    return df.reset_index(drop=True)


if __name__ == "__main__":
    df_raw = clean_dataframe(load_csv("sample_logs/london.csv"))
    if df_raw.empty:
        print("No logs collected.")
    else:
        collector = LogCollector(
            es_host="http://localhost:9200",
            index="log-pipeline-logs",
            bulk_size=100
        )
        collector.bulk_index(df_raw)
        print(f"Indexed {len(df_raw)} entries.")
