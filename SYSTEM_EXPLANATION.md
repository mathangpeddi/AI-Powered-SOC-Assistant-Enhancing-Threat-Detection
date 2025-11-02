# System Architecture & Data Flow Explanation

## 📊 **Complete Data Flow**

### 1. **Data Source - Where Alerts Come From**

The alerts in your system come from **synthetic data generation** via `simulate_data_feed.py`:

**Primary Source:**
- `simulate_data_feed.py` generates **synthetic/artificial network alerts** in real-time
- It runs continuously, posting batches of alerts every 30 seconds
- Default: **20 alerts per batch** every **30 seconds**

**Optional Data Sources:**
- `artifacts/alerts_mitre.csv` - Can be used as a baseline/template if provided via `--csv` argument
- The script can sample from this CSV to generate more realistic alerts

**Data Generation Process:**
```
simulate_data_feed.py (runs continuously)
    ↓
    Generates synthetic alerts with:
    - Random source/destination IPs
    - Random protocols (TCP, UDP)
    - Random ports (22, 23, 21, 80, 443, etc.)
    - Random packet/byte rates
    - Calculated y_prob (threat probability)
    - Initial MITRE tags (optional)
    ↓
    POSTs to backend at /ingest endpoint
    ↓
    Backend (app.py) receives and normalizes alerts
    ↓
    Stored in-memory (ALERTS list)
    ↓
    Streamlit dashboard fetches via /alerts endpoint
```

---

## 🏷️ **MITRE Tags Generation**

MITRE tags are generated in **TWO places** with slightly different logic:

### **Location 1: `simulate_data_feed.py` (line 28-38)**

The data feed script generates initial MITRE tags when creating alerts:

```python
def guess_mitre(protocol: str, dst_port: int, pps: float, bps: float):
    tags = []
    # T1499: Endpoint Denial of Service
    if pps > 1000 or (pps > 300 and bps < 5e5):
        tags.append("T1499 Endpoint Denial of Service")
    
    # T1110: Brute Force
    if dst_port in [21,22,23,3389] and pps > 50 and bps < 5e5:
        tags.append("T1110 Brute Force")
    
    # T1041: Exfiltration Over C2 Channel
    if bps > 5e6 and dst_port not in [80,443]:
        tags.append("T1041 Exfiltration Over C2 Channel")
    
    # T1071: Application Layer Protocol
    if protocol.upper() in ["FTP","TELNET"]:
        tags.append("T1071 Application Layer Protocol")
    
    return sorted(set(tags))
```

### **Location 2: `app.py` (line 28-63) - _infer_mitre()**

The backend **also generates tags** if alerts don't have any when ingested:

```python
def _infer_mitre(a: dict) -> List[str]:
    # Similar logic but with slightly different thresholds:
    # - T1499: if pps > 300 (vs 1000 in simulate_data_feed.py)
    # - T1110: same logic
    # - T1041: if bps > 5,000,000 (vs 5e6)
    # - T1071: same logic
```

### **Tag Generation Rules:**

| MITRE Tag | Condition | Description |
|-----------|-----------|-------------|
| **T1499: Endpoint Denial of Service** | `pps > 300` OR `(pps > 300 AND bps < 500,000)` | Very high packet rate indicates DDoS |
| **T1110: Brute Force** | `dst_port in [21,22,23,3389] AND pps > 50 AND bps < 500,000` | High attempts to SSH/FTP/Telnet/RDP |
| **T1041: Exfiltration Over C2 Channel** | `bps > 5,000,000 AND dst_port NOT in [80,443]` | Huge data transfer to non-web ports |
| **T1071: Application Layer Protocol** | `protocol in ["FTP", "TELNET"]` | Uses legacy/plaintext protocols |

---

## ❓ **Why Only Some Alerts Have MITRE Tags?**

**MITRE tags are ONLY generated when alerts match specific threat patterns:**

### **Alerts WITH tags:**
- ✅ High packet rate (>300 pps) → Gets T1499
- ✅ Traffic to SSH/FTP/Telnet/RDP with many packets → Gets T1110
- ✅ Large data transfer to non-web ports → Gets T1041
- ✅ Using FTP or Telnet protocol → Gets T1071

### **Alerts WITHOUT tags (empty mitre_tags):**
- ❌ Normal web traffic (ports 80, 443) with normal rates
- ❌ Low packet rates (<300 pps) to normal ports
- ❌ Traffic that doesn't match any threat pattern
- ❌ Legitimate-looking network flows

**Example:**
- Alert with port 80 (HTTP), 50 pps, 200KB/s → **NO tags** (normal web traffic)
- Alert with port 22 (SSH), 100 pps, 50KB/s → **Gets T1110 Brute Force** (suspicious SSH activity)
- Alert with port 8080, 500 pps, 10MB/s → **Gets T1041 Exfiltration** (huge data transfer)

---

## 🔄 **Complete System Flow**

```
┌─────────────────────────────────────┐
│  simulate_data_feed.py              │
│  (Synthetic Data Generator)         │
│  - Runs every 30 seconds            │
│  - Generates 20 alerts per batch    │
│  - Creates initial MITRE tags       │
└──────────────┬──────────────────────┘
               │
               │ POST /ingest
               │ (JSON with alerts)
               ▼
┌─────────────────────────────────────┐
│  app.py (FastAPI Backend)            │
│  - Receives alerts via /ingest      │
│  - Calls _normalize() on each alert │
│  - _normalize() checks for tags     │
│  - If no tags, calls _infer_mitre() │
│  - Stores in ALERTS list (memory)  │
└──────────────┬──────────────────────┘
               │
               │ GET /alerts
               │ (Returns all alerts)
               ▼
┌─────────────────────────────────────┐
│  streamlit_app.py (Dashboard)       │
│  - Fetches alerts every 30 seconds  │
│  - Displays in tables               │
│  - Shows MITRE tags (formatted)     │
└─────────────────────────────────────┘
```

---

## 📝 **Key Functions:**

### `simulate_data_feed.py`:
- **`guess_mitre()`**: Generates initial MITRE tags based on alert characteristics
- **`main()`**: Main loop that generates synthetic alerts and posts to backend

### `app.py`:
- **`_infer_mitre()`**: Backend heuristic function that generates tags if missing
- **`_normalize()`**: Normalizes alert data and ensures tags exist (calls _infer_mitre if needed)
- **`/ingest`**: Endpoint that receives alerts from data feed
- **`/alerts`**: Endpoint that returns all stored alerts to dashboard

### `streamlit_app.py`:
- **`fetch_json()`**: Helper to fetch data from backend
- Auto-refresh every 30 seconds to show new alerts

---

## 💡 **Summary:**

1. **Data Source**: Synthetic alerts from `simulate_data_feed.py` (can optionally use CSV)
2. **MITRE Tags**: Generated by heuristics in both `simulate_data_feed.py` and `app.py`
3. **Why Empty Tags**: Only alerts matching threat patterns get tags; normal traffic gets none
4. **Data Flow**: Data Feed → Backend → Dashboard (all in-memory, no database)

