import pandas as pd

def load_csv(path: str) -> pd.DataFrame:
    try:
        return pd.read_csv(path, header=0)
    except (FileNotFoundError, pd.errors.EmptyDataError):
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
    if not df_raw.empty:
        print(f"Collected {len(df_raw)} log entries.")
        print(df_raw.head(10))
        df_raw.to_csv("sample_logs/london_raw.csv", index=False)
    else:
        print("No logs collected.")
