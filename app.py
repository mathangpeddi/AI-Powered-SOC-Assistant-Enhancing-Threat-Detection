# app.py
from __future__ import annotations

from fastapi import FastAPI, Body, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from typing import List
import json
import random
import os
import csv

app = FastAPI(title="SOC Backend", version="1.1")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------- In-memory store --------
ALERTS: List[dict] = []     # newest appended last
ROW_COUNTER = 0             # server-side monotonically increasing id


# -------- Heuristics: add MITRE tags if missing --------
def _infer_mitre(a: dict) -> List[str]:
    tags = []
    dst_port = int(a.get("dst_port", 0) or 0)
    proto = str(a.get("protocol", "")).upper()
    try:
        pps = float(a.get("approx_packets_per_s", 0) or 0.0)
    except Exception:
        pps = 0.0
    try:
        bps = float(a.get("approx_bytes_per_s", 0) or 0.0)
    except Exception:
        bps = 0.0

    # T1499: Endpoint Denial of Service (very high pps, or short spikes)
    if pps > 300:
        tags.append("T1499 Endpoint Denial of Service")

    # T1110: Brute Force (ssh/ftp/telnet/rpd-ish ports & lots of attempts)
    if dst_port in (21, 22, 23, 3389) and pps > 50 and bps < 5e5:
        tags.append("T1110 Brute Force")

    # T1041: Exfiltration Over C2 Channel (huge sustained throughput to non-web ports)
    if bps > 5_000_000 and dst_port not in (80, 443):
        tags.append("T1041 Exfiltration Over C2 Channel")

    # T1071: Application Layer Protocol (legacy/plaintext)
    if proto in ("FTP", "TELNET"):
        tags.append("T1071 Application Layer Protocol")

    # Deduplicate, keep stable order
    seen, out = set(), []
    for t in tags:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out


# -------- Helpers --------
def _ensure_row_id(a: dict) -> dict:
    global ROW_COUNTER
    if "row_id" not in a:
        ROW_COUNTER += 1
        a["row_id"] = ROW_COUNTER
    else:
        try:
            rid = int(a["row_id"])
            if rid > ROW_COUNTER:
                ROW_COUNTER = rid
        except Exception:
            ROW_COUNTER += 1
            a["row_id"] = ROW_COUNTER
    return a


def _normalize(a: dict) -> dict:
    """Make an alert row consistent & add MITRE tags if missing."""
    a = dict(a)

    # Coerce numbers
    for k in ("dst_port",):
        if k in a:
            try:
                a[k] = int(a[k])
            except Exception:
                pass
    for k in ("approx_packets_per_s", "approx_bytes_per_s", "y_prob"):
        if k in a:
            try:
                a[k] = float(a[k])
            except Exception:
                pass

    # y_prob fallback if absent
    if "y_prob" not in a:
        # give something plausible but low unless it looks risky
        base = 0.01 + min(float(a.get("approx_packets_per_s", 0))/2000.0, 0.2)
        a["y_prob"] = round(min(0.9999, base + random.random()*0.01), 6)

    # mitre_tags: accept list, JSON string, or plain string; else infer
    mt = a.get("mitre_tags")
    if isinstance(mt, str):
        try:
            parsed = json.loads(mt)
            a["mitre_tags"] = parsed if isinstance(parsed, list) else [mt]
        except Exception:
            a["mitre_tags"] = [mt]
    elif mt is None:
        a["mitre_tags"] = []
    elif not isinstance(mt, list):
        a["mitre_tags"] = [str(mt)]

    if not a["mitre_tags"]:
        a["mitre_tags"] = _infer_mitre(a)

    return _ensure_row_id(a)


# -------- Endpoints --------
@app.get("/")
def root():
    return {"ok": True, "message": "SOC Backend running", "count": len(ALERTS)}


@app.post("/ingest")
def ingest(payload: dict | list = Body(...)):
    """
    Accepts:
      - {"alerts": [ {...}, ... ]}
      - [ {...}, ... ]
      - {"rows":[...]} / {"records":[...]} / {"data":[...]}
      - single alert dict {...}
    """
    alerts = None

    if isinstance(payload, list):
        alerts = payload
    elif isinstance(payload, dict):
        for k in ("alerts", "rows", "records", "data"):
            if isinstance(payload.get(k), list):
                alerts = payload[k]
                break
        if alerts is None and any(k in payload for k in ("src_ip","dst_ip","dst_port","protocol","y_prob","mitre_tags")):
            alerts = [payload]

    if not isinstance(alerts, list):
        raise HTTPException(status_code=400, detail="Invalid body for /ingest")

    normed = [_normalize(a) for a in alerts if isinstance(a, dict)]
    ALERTS.extend(normed)
    return {"received": len(normed), "total": len(ALERTS)}


@app.get("/alerts")
def alerts(
    limit: int = Query(500, ge=1, le=5000, description="Maximum number of alerts to return"),
):
    """
    Returns alerts in the format expected by the frontend dashboard.
    Returns: {"alerts": [...], "last_row_id": ...}
    """
    if not ALERTS:
        return {"alerts": [], "last_row_id": 0}
    
    # Return all alerts up to limit, sorted by row_id
    result = sorted(ALERTS, key=lambda x: int(x.get("row_id", 0)))
    result = result[-limit:] if len(result) > limit else result
    
    last_row_id = int(result[-1].get("row_id", 0)) if result else 0
    
    return {
        "alerts": result,
        "last_row_id": last_row_id
    }


@app.get("/alerts/live")
def alerts_live(
    since_id: int = Query(-1, description="Return rows with row_id > since_id"),
    limit: int = Query(100, ge=1, le=5000),
):
    if not ALERTS:
        return []
    result = [a for a in ALERTS if int(a.get("row_id", -1)) > since_id]
    result.sort(key=lambda x: int(x.get("row_id", 0)))
    return result[:limit]


@app.post("/reset")
def reset():
    ALERTS.clear()
    global ROW_COUNTER
    ROW_COUNTER = 0
    return {"ok": True, "total": 0}


@app.get("/summary")
def summary():
    """
    Returns a summary of current alerts for analyst review.
    """
    if not ALERTS:
        return {"summary": "No alerts available."}
    
    high_risk = [a for a in ALERTS if float(a.get("y_prob", 0)) > 0.7]
    mitre_count = {}
    for alert in ALERTS:
        tags = alert.get("mitre_tags", [])
        if isinstance(tags, list):
            for tag in tags:
                mitre_count[tag] = mitre_count.get(tag, 0) + 1
    
    summary_parts = [
        f"Total alerts: {len(ALERTS)}",
        f"High-risk alerts (y_prob > 0.7): {len(high_risk)}",
    ]
    
    if mitre_count:
        top_tags = sorted(mitre_count.items(), key=lambda x: x[1], reverse=True)[:5]
        summary_parts.append(f"Top MITRE tags: {', '.join(f'{tag} ({count})' for tag, count in top_tags)}")
    
    return {"summary": " | ".join(summary_parts)}


@app.post("/bootstrap")
def bootstrap(
    count: int = Query(200, ge=1, le=5000),
    path: str = Query("artifacts/alerts_mitre.csv", description="CSV file to seed from"),
):
    """
    Quickly load N rows from a CSV (so the dashboard shows a full table immediately).
    It expects columns like:
      src_ip, dst_ip, dst_port, protocol, approx_packets_per_s, approx_bytes_per_s, y_prob, mitre_tags
    Unknown columns are ignored; missing ones get sensible defaults.
    """
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail=f"CSV not found: {path}")

    loaded = 0
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if loaded >= count:
                break
            # Map likely column names
            a = {
                "src_ip": row.get("src_ip") or row.get("Source IP") or row.get("Src IP"),
                "dst_ip": row.get("dst_ip") or row.get("Destination IP") or row.get("Dst IP"),
                "dst_port": row.get("dst_port") or row.get("Destination Port") or row.get("Dst Port"),
                "protocol": row.get("protocol") or row.get("Protocol"),
                "approx_packets_per_s": row.get("approx_packets_per_s") or row.get("Flow Packets/s"),
                "approx_bytes_per_s": row.get("approx_bytes_per_s") or row.get("Flow Bytes/s"),
                "y_prob": row.get("y_prob"),
                "mitre_tags": row.get("mitre_tags"),
            }
            ALERTS.append(_normalize(a))
            loaded += 1

    return {"bootstrapped": loaded, "total": len(ALERTS), "from": path}
