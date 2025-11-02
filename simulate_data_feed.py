# simulate_data_feed.py
"""
Posts synthetic alerts to the backend /ingest endpoint on a loop.

Usage:
  python simulate_data_feed.py --api http://127.0.0.1:8000 --batch 12 --interval 5

If you have a trained model+scaler (joblib) and a CSV to sample features from,
you can add:
  --csv alerts_mitre.csv --model artifacts/model.joblib --scaler artifacts/scaler.joblib
This will score y_prob using your model. Otherwise it will use heuristics.
"""
import argparse
import json
import random
import time
from pathlib import Path

import numpy as np
import pandas as pd
import requests

def rand_ip(internal=False):
    if internal:
        return f"192.168.{np.random.randint(0,255)}.{np.random.randint(1,255)}"
    return f"{np.random.randint(1,223)}.{np.random.randint(0,255)}.{np.random.randint(0,255)}.{np.random.randint(1,255)}"

def guess_mitre(protocol: str, dst_port: int, pps: float, bps: float):
    tags = []
    if pps > 1000 or (pps > 300 and bps < 5e5):
        tags.append("T1499 Endpoint Denial of Service")
    if dst_port in [21,22,23,3389] and pps > 50 and bps < 5e5:
        tags.append("T1110 Brute Force")
    if bps > 5e6 and dst_port not in [80,443]:
        tags.append("T1041 Exfiltration Over C2 Channel")
    if protocol.upper() in ["FTP","TELNET"]:
        tags.append("T1071 Application Layer Protocol")
    return sorted(set(tags))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", default="http://127.0.0.1:8000", help="FastAPI base URL")
    ap.add_argument("--batch", type=int, default=20, help="rows per post")
    ap.add_argument("--interval", type=float, default=30.0, help="seconds between posts")
    ap.add_argument("--csv", default="", help="optional CSV to sample baseline rows")
    ap.add_argument("--model", default="", help="optional joblib model path for y_prob")
    ap.add_argument("--scaler", default="", help="optional joblib scaler path")
    args = ap.parse_args()

    csv_df = None
    model = None
    scaler = None

    if args.csv and Path(args.csv).exists():
        try:
            csv_df = pd.read_csv(args.csv, low_memory=False)
        except Exception as e:
            print(f"Failed to read csv {args.csv}: {e}")

    if args.model and Path(args.model).exists() and args.scaler and Path(args.scaler).exists():
        try:
            import joblib
            model = joblib.load(args.model)
            scaler = joblib.load(args.scaler)
            print("Loaded model and scaler for scoring.")
        except Exception as e:
            print(f"Failed to load model/scaler: {e}")
            model = None
            scaler = None

    row_id = 0
    print(f"Posting to {args.api}/ingest every {args.interval}s (batch={args.batch}). Ctrl+C to stop.")
    while True:
        try:
            batch = []
            for _ in range(args.batch):
                if csv_df is not None and not csv_df.empty:
                    base = csv_df.sample(1).to_dict(orient="records")[0]
                    protocol = str(base.get("protocol") or base.get("Protocol") or "TCP")
                    dst_port = int(float(base.get("dst_port") or base.get("Destination Port") or 80))
                    pps = float(base.get("approx_packets_per_s") or base.get("Flow Packets/s") or np.random.uniform(1, 400))
                    bps = float(base.get("approx_bytes_per_s") or base.get("Flow Bytes/s") or np.random.uniform(1e3, 8e6))
                else:
                    protocol = random.choice(["TCP","UDP","TCP","TCP","UDP"])
                    dst_port = random.choice([22,23,21,80,443,8080,8443,53,3389])
                    pps = float(abs(np.random.normal(120, 80)) + np.random.choice([0, 400], p=[0.8, 0.2]))
                    bps = float(pps * np.random.uniform(200, 15000))

                # y_prob via model if available, else heuristic
                if model is not None and scaler is not None and csv_df is not None and not csv_df.empty:
                    # minimal feature set if present
                    feats = []
                    num_cols = [c for c in csv_df.columns if pd.api.types.is_numeric_dtype(csv_df[c])]
                    if not num_cols:
                        y_prob = float(np.clip(pps / 1200 + (bps / 1e7), 0, 1))
                    else:
                        # build a small numeric vector, fillna 0
                        x = pd.DataFrame([ {c: float(base.get(c, 0) if pd.notna(base.get(c, 0)) else 0) for c in num_cols} ])
                        x = x.replace([np.inf, -np.inf], np.nan).fillna(0.0)
                        xs = scaler.transform(x)
                        y_prob = float(model.predict_proba(xs)[:, 1][0])
                else:
                    # heuristic probability
                    y_prob = float(np.clip(pps / 1200 + (bps / 1e7), 0, 1))

                src_ip = rand_ip(internal=True)
                dst_ip = rand_ip(internal=False)
                tags = guess_mitre(protocol, dst_port, pps, bps)

                batch.append({
                    "row_id": row_id,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": int(dst_port),
                    "protocol": protocol,
                    "approx_packets_per_s": float(pps),
                    "approx_bytes_per_s": float(bps),
                    "y_prob": float(y_prob),
                    "mitre_tags": tags,
                })
                row_id += 1

            resp = requests.post(f"{args.api}/ingest", json=batch, timeout=15)
            resp.raise_for_status()
            js = resp.json()
            print(f"Ingested {js.get('received', js.get('ingested', 0))} rows, total={js.get('total', 0)}")

            time.sleep(args.interval)
        except KeyboardInterrupt:
            print("Stopped.")
            break
        except Exception as e:
            print(f"POST failed: {e}")
            time.sleep(args.interval)
            continue

if __name__ == "__main__":
    main()
