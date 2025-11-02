# app.py
from __future__ import annotations

from fastapi import FastAPI, Body, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Dict, Optional
import json
import random
import os
import csv
import requests
from collections import Counter, defaultdict
from datetime import datetime, timedelta

# AI/ML imports (optional - will fail gracefully if not installed)
try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    print("Warning: OpenAI not installed. LLM features will use fallback mode.")

try:
    from sentence_transformers import SentenceTransformer
    import numpy as np
    from sklearn.cluster import DBSCAN
    from sklearn.ensemble import IsolationForest
    EMBEDDINGS_AVAILABLE = True
    ANOMALY_DETECTION_AVAILABLE = True
except ImportError:
    EMBEDDINGS_AVAILABLE = False
    ANOMALY_DETECTION_AVAILABLE = False
    print("Warning: sentence-transformers/scikit-learn not installed. Clustering and anomaly detection features disabled.")

# Threat Intelligence imports (optional - will fail gracefully if not installed)
try:
    import geoip2.database
    import geoip2.errors
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False
    print("Warning: geoip2 not installed. GeoIP features will use fallback mode.")

try:
    import ipwhois
    from ipwhois import IPWhois
    IPWHOIS_AVAILABLE = True
except ImportError:
    IPWHOIS_AVAILABLE = False
    print("Warning: ipwhois not installed. WHOIS features will use fallback mode.")

try:
    import pycountry
    PYCOUNTRY_AVAILABLE = True
except ImportError:
    PYCOUNTRY_AVAILABLE = False
    print("Warning: pycountry not installed. Country lookups will use fallback mode.")

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

# -------- AI Components --------
# Lazy load models to avoid startup delay
_embedding_model = None
_openai_client = None

def get_embedding_model():
    """Lazy load sentence transformer model."""
    global _embedding_model
    if _embedding_model is None and EMBEDDINGS_AVAILABLE:
        try:
            _embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
        except Exception as e:
            print(f"Warning: Could not load embedding model: {e}")
    return _embedding_model

def get_openai_client():
    """Lazy load OpenAI client."""
    global _openai_client
    if _openai_client is None and OPENAI_AVAILABLE:
        api_key = os.getenv("OPENAI_API_KEY")
        if api_key:
            try:
                from openai import OpenAI
                _openai_client = OpenAI(api_key=api_key)
            except Exception as e:
                print(f"Warning: Could not initialize OpenAI client: {e}")
        else:
            print("Warning: OPENAI_API_KEY not set. LLM features will use fallback mode.")
    return _openai_client


# -------- Threat Intelligence Components --------
# Cache for API responses to avoid rate limits
_threat_intel_cache = {}

# MITRE ATT&CK technique cache
_mitre_techniques_cache = {}


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


# -------- AI-Powered Insights Layer --------

def _generate_llm_summary(alerts: List[dict], limit: int = 50) -> str:
    """Generate LLM summary of recent alerts."""
    client = get_openai_client()
    if not client or not OPENAI_AVAILABLE:
        # Fallback to rule-based summary
        return _generate_fallback_summary(alerts, limit)
    
    try:
        # Prepare alert context
        recent = sorted(alerts, key=lambda x: int(x.get("row_id", 0)))[-limit:]
        
        # Extract key patterns
        src_ips = Counter(a.get("src_ip", "unknown") for a in recent)
        ports = Counter(a.get("dst_port", 0) for a in recent)
        protocols = Counter(a.get("protocol", "unknown") for a in recent)
        mitre_tags = Counter()
        for a in recent:
            tags = a.get("mitre_tags", [])
            if isinstance(tags, list):
                mitre_tags.update(tags)
        
        # Build prompt
        prompt = f"""Analyze these {len(recent)} security alerts and provide a concise 2-3 sentence summary.

Key patterns:
- Top source IPs: {', '.join(f'{ip}({count})' for ip, count in src_ips.most_common(5))}
- Top ports targeted: {', '.join(f'{port}({count})' for port, count in ports.most_common(5))}
- Protocols: {', '.join(f'{proto}({count})' for proto, count in protocols.most_common(3))}
- MITRE techniques: {', '.join(f'{tag}({count})' for tag, count in mitre_tags.most_common(5))}

Provide a natural language summary highlighting the main threat patterns and any notable trends."""
        
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a cybersecurity analyst summarizing security alerts."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=200,
            temperature=0.7
        )
        
        return response.choices[0].message.content.strip()
    
    except Exception as e:
        print(f"LLM summary generation failed: {e}")
        return _generate_fallback_summary(alerts, limit)


def _generate_fallback_summary(alerts: List[dict], limit: int = 50) -> str:
    """Fallback rule-based summary when LLM unavailable."""
    if not alerts:
        return "No alerts available."
    
    recent = sorted(alerts, key=lambda x: int(x.get("row_id", 0)))[-limit:]
    
    src_ips = Counter(a.get("src_ip", "unknown") for a in recent)
    ports = Counter(a.get("dst_port", 0) for a in recent)
    mitre_tags = Counter()
    for a in recent:
        tags = a.get("mitre_tags", [])
        if isinstance(tags, list):
            mitre_tags.update(tags)
    
    parts = []
    if mitre_tags:
        top_tag = mitre_tags.most_common(1)[0]
        parts.append(f"Surge in {top_tag[0]} attacks ({top_tag[1]} alerts)")
    
    if src_ips:
        unique_ips = len(src_ips)
        top_ip = src_ips.most_common(1)[0]
        parts.append(f"from {unique_ips} unique IPs (top: {top_ip[0]})")
    
    if ports:
        top_port = ports.most_common(1)[0]
        parts.append(f"targeting port {top_port[0]}")
    
    return ". ".join(parts) if parts else f"Analyzed {len(recent)} recent alerts."


def _cluster_alerts(alerts: List[dict]) -> Dict[int, List[dict]]:
    """Cluster similar alerts using embeddings."""
    if not EMBEDDINGS_AVAILABLE or not alerts:
        return {}
    
    try:
        model = get_embedding_model()
        if not model:
            return {}
        
        # Create alert descriptions for embedding
        alert_texts = []
        for a in alerts:
            tags = ", ".join(a.get("mitre_tags", [])) if a.get("mitre_tags") else "normal"
            text = f"{a.get('src_ip')} -> {a.get('dst_ip')}:{a.get('dst_port')} {a.get('protocol')} {tags}"
            alert_texts.append(text)
        
        # Generate embeddings
        embeddings = model.encode(alert_texts, show_progress_bar=False)
        
        # Cluster using DBSCAN
        if len(embeddings) < 2:
            return {}
        
        clustering = DBSCAN(eps=0.3, min_samples=2, metric='cosine')
        cluster_labels = clustering.fit_predict(embeddings)
        
        # Group alerts by cluster
        clusters = defaultdict(list)
        for idx, label in enumerate(cluster_labels):
            if label != -1:  # -1 means noise/outlier
                clusters[label].append(alerts[idx])
        
        return dict(clusters)
    
    except Exception as e:
        print(f"Clustering failed: {e}")
        return {}


def _generate_root_cause_hypothesis(alert_group: List[dict]) -> str:
    """Generate root cause hypothesis for a group of alerts."""
    if not alert_group:
        return "Insufficient data for analysis."
    
    # Analyze patterns
    src_ips = set(a.get("src_ip") for a in alert_group)
    dst_ports = Counter(a.get("dst_port") for a in alert_group)
    protocols = Counter(a.get("protocol") for a in alert_group)
    mitre_tags = Counter()
    for a in alert_group:
        tags = a.get("mitre_tags", [])
        if isinstance(tags, list):
            mitre_tags.update(tags)
    
    # Generate hypothesis based on patterns
    hypotheses = []
    
    if len(src_ips) == 1 and mitre_tags:
        top_tag = mitre_tags.most_common(1)[0][0]
        if "Brute Force" in top_tag:
            hypotheses.append("Single source IP conducting automated credential stuffing campaign")
        elif "Denial of Service" in top_tag:
            hypotheses.append("DDoS attack from single source attempting to overwhelm target")
    
    if len(src_ips) > 10 and mitre_tags:
        hypotheses.append("Distributed attack pattern suggesting coordinated botnet activity")
    
    if dst_ports.most_common(1)[0][1] > len(alert_group) * 0.8:
        port = dst_ports.most_common(1)[0][0]
        if port in [22, 23, 21, 3389]:
            hypotheses.append("Focused brute-force attack targeting exposed remote access services")
    
    # Try LLM generation if available
    client = get_openai_client()
    if client and OPENAI_AVAILABLE and len(alert_group) >= 3:
        try:
            prompt = f"""Given this group of {len(alert_group)} related security alerts, generate a concise root cause hypothesis (1 sentence).

Patterns:
- Unique source IPs: {len(src_ips)}
- Top destination port: {dst_ports.most_common(1)[0][0]} ({dst_ports.most_common(1)[0][1]} alerts)
- Top protocol: {protocols.most_common(1)[0][0]}
- MITRE techniques: {', '.join(set(tag for tags in [a.get('mitre_tags', []) for a in alert_group] for tag in tags if isinstance(tags, list)))}

Provide a hypothesis about the root cause of these attacks."""
            
            response = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are a cybersecurity analyst identifying root causes of attacks."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=100,
                temperature=0.7
            )
            return response.choices[0].message.content.strip()
        except:
            pass
    
    # Fallback to rule-based
    if hypotheses:
        return hypotheses[0]
    
    return "Multiple indicators suggest coordinated attack activity requiring investigation."


def _calculate_ai_priority_score(alert: dict) -> float:
    """Calculate AI-based priority score (0-1) for an alert."""
    # Base score from y_prob
    base_score = float(alert.get("y_prob", 0.0))
    
    # Boost factors
    boost = 0.0
    
    # MITRE tags boost
    mitre_tags = alert.get("mitre_tags", [])
    if isinstance(mitre_tags, list) and mitre_tags:
        boost += 0.1 * len(mitre_tags)
    
    # High packet rate boost
    pps = float(alert.get("approx_packets_per_s", 0) or 0)
    if pps > 500:
        boost += 0.15
    elif pps > 300:
        boost += 0.1
    
    # High byte rate boost
    bps = float(alert.get("approx_bytes_per_s", 0) or 0)
    if bps > 10_000_000:  # >10MB/s
        boost += 0.15
    elif bps > 5_000_000:  # >5MB/s
        boost += 0.1
    
    # Sensitive port boost
    dst_port = int(alert.get("dst_port", 0) or 0)
    if dst_port in [22, 3389]:  # SSH, RDP
        boost += 0.1
    elif dst_port in [21, 23]:  # FTP, Telnet
        boost += 0.05
    
    # Combine base + boost, capped at 1.0
    final_score = min(1.0, base_score + boost)
    
    return round(final_score, 4)


# -------- Threat Intelligence Functions --------

def _check_abuseipdb(ip: str) -> Optional[Dict]:
    """Check IP reputation using AbuseIPDB API."""
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        return None
    
    # Check cache first
    cache_key = f"abuseipdb_{ip}"
    if cache_key in _threat_intel_cache:
        return _threat_intel_cache[cache_key]
    
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": api_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""}
        
        response = requests.get(url, headers=headers, params=params, timeout=5)
        if response.status_code == 200:
            data = response.json()
            result = {
                "is_public": data.get("data", {}).get("isPublic", False),
                "ip_reputation": data.get("data", {}).get("abuseConfidencePercentage", 0),
                "usage_type": data.get("data", {}).get("usageType", "unknown"),
                "isp": data.get("data", {}).get("isp", "unknown"),
                "country_code": data.get("data", {}).get("countryCode", "unknown"),
                "total_reports": data.get("data", {}).get("totalReports", 0),
                "last_reported_at": data.get("data", {}).get("lastReportedAt", None),
                "source": "AbuseIPDB"
            }
            _threat_intel_cache[cache_key] = result
            return result
    except Exception as e:
        print(f"AbuseIPDB check failed for {ip}: {e}")
    
    return None


def _get_mitre_technique_info(technique_id: str) -> Optional[Dict]:
    """Get MITRE ATT&CK technique information from MITRE API."""
    if not technique_id:
        return None
    
    # Extract technique ID (e.g., "T1110" from "T1110 Brute Force")
    tech_id = technique_id.split()[0] if " " in technique_id else technique_id
    if not tech_id.startswith("T"):
        return None
    
    # Remove leading zeros if present (e.g., T01041 -> T1041)
    if len(tech_id) > 5 and tech_id[1:5].isdigit() and tech_id[5:].isdigit():
        tech_id = tech_id[0] + tech_id[1:5].lstrip('0') + tech_id[5:]
    
    # Check cache first
    if tech_id in _mitre_techniques_cache:
        return _mitre_techniques_cache[tech_id]
    
    try:
        # MITRE ATT&CK API v3 endpoint format
        # Try different endpoint formats
        endpoints_to_try = [
            f"https://attack.mitre.org/api/v3/techniques/{tech_id}/",
            f"https://attack.mitre.org/api/techniques/{tech_id}/",
            f"https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/attack-pattern/attack-pattern--{tech_id.lower()}.json"
        ]
        
        for url in endpoints_to_try:
            try:
                headers = {"Accept": "application/json"}
                response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
                
                if response.status_code == 200:
                    data = response.json()
                    
                    # Handle different response formats
                    if isinstance(data, dict):
                        # Direct object format
                        technique = data
                        if "objects" in data and isinstance(data["objects"], list) and len(data["objects"]) > 0:
                            technique = data["objects"][0]
                        elif "objects" in data:
                            # Try getting first item from objects dict
                            technique = data.get("objects", {})
                            if isinstance(technique, dict) and len(technique) > 0:
                                technique = list(technique.values())[0] if isinstance(list(technique.values())[0], dict) else technique
                    else:
                        continue
                    
                    # Extract information
                    name = technique.get("name", tech_id)
                    description = technique.get("description", "")
                    if isinstance(description, list) and len(description) > 0:
                        description = description[0]
                    
                    # Get tactics/phase names
                    tactics = []
                    if "kill_chain_phases" in technique:
                        phases = technique["kill_chain_phases"]
                        if isinstance(phases, list):
                            tactics = [p.get("phase_name", "") for p in phases if isinstance(p, dict)]
                    
                    # Get platforms
                    platforms = technique.get("x_mitre_platforms", [])
                    if not platforms:
                        platforms = technique.get("platforms", [])
                    
                    result = {
                        "id": tech_id,
                        "name": name,
                        "description": description if description else "Technique description from MITRE ATT&CK framework.",
                        "tactics": tactics if tactics else ["Exfiltration"] if "1041" in tech_id else ["Credential Access"] if "1110" in tech_id else [],
                        "platforms": platforms if platforms else ["Windows", "Linux", "macOS"],
                        "url": f"https://attack.mitre.org/techniques/{tech_id}/",
                        "source": "MITRE ATT&CK"
                    }
                    
                    _mitre_techniques_cache[tech_id] = result
                    return result
            except Exception as e:
                continue
        
    except Exception as e:
        print(f"MITRE API lookup failed for {tech_id}: {e}")
    
    # Enhanced fallback with known technique info
    known_techniques = {
        "T1041": {
            "name": "Exfiltration Over C2 Channel",
            "description": "Adversaries may steal data by exfiltrating it over an existing command and control channel. Stolen data is encoded into the normal communications channel using the same protocol as command and control communications.",
            "tactics": ["Exfiltration"],
            "platforms": ["ESXi", "Linux", "Windows", "macOS"]
        },
        "T1110": {
            "name": "Brute Force",
            "description": "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained. Credential Dumping to obtain password hashes may only get an adversary so far when Pass the Hash is not an option. Brute forcing credentials can be used to gain access to accounts.",
            "tactics": ["Credential Access"],
            "platforms": ["Linux", "macOS", "Windows"]
        },
        "T1499": {
            "name": "Endpoint Denial of Service",
            "description": "Adversaries may perform Endpoint Denial of Service (DoS) attacks to degrade or block the availability of services to users. Endpoint DoS can be performed by exhausting the system resources those services are hosted on or exploiting the system to cause a persistent crash condition.",
            "tactics": ["Impact"],
            "platforms": ["Linux", "macOS", "Windows"]
        },
        "T1071": {
            "name": "Application Layer Protocol",
            "description": "Adversaries may communicate using application layer protocols to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server.",
            "tactics": ["Command and Control"],
            "platforms": ["Linux", "macOS", "Windows"]
        }
    }
    
    # Use known technique info if available
    if tech_id in known_techniques:
        result = {
            "id": tech_id,
            "name": known_techniques[tech_id]["name"],
            "description": known_techniques[tech_id]["description"],
            "tactics": known_techniques[tech_id]["tactics"],
            "platforms": known_techniques[tech_id]["platforms"],
            "url": f"https://attack.mitre.org/techniques/{tech_id}/",
            "source": "MITRE ATT&CK (fallback)"
        }
        _mitre_techniques_cache[tech_id] = result
        return result
    
    # Basic fallback
    fallback = {
        "id": tech_id,
        "name": tech_id,
        "description": "Technique information not available from MITRE API. Please check https://attack.mitre.org/techniques/{}/ for details.".format(tech_id),
        "tactics": [],
        "platforms": [],
        "url": f"https://attack.mitre.org/techniques/{tech_id}/",
        "source": "MITRE ATT&CK (fallback)"
    }
    return fallback


def _is_private_ip(ip: str) -> bool:
    """Check if an IP address is a private IP."""
    if not ip:
        return True
    try:
        parts = ip.strip().split('.')
        if len(parts) != 4:
            return False
        parts = [int(p) for p in parts]
        # Private IP ranges:
        # 10.0.0.0/8 (10.0.0.0 - 10.255.255.255)
        # 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
        # 192.168.0.0/16 (192.168.0.0 - 192.168.255.255)
        if parts[0] == 10:
            return True
        elif parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        elif parts[0] == 192 and parts[1] == 168:
            return True
        elif parts[0] == 127:
            return True  # Loopback
        elif parts[0] == 0 or parts[0] >= 224:
            return True  # Reserved/multicast
        return False
    except (ValueError, IndexError):
        return False


def _get_geoip_info(ip: str) -> Optional[Dict]:
    """Get GeoIP information for an IP address."""
    if not ip or _is_private_ip(ip):
        return None  # Skip private IPs
    
    # Check cache first
    cache_key = f"geoip_{ip}"
    if cache_key in _threat_intel_cache:
        return _threat_intel_cache[cache_key]
    
    # Try using GeoIP2 database (if available)
    if GEOIP_AVAILABLE:
        try:
            # Note: Requires MaxMind GeoLite2 database file
            # Download from: https://dev.maxmind.com/geoip/geoip2/geolite2/
            db_path = os.getenv("GEOLITE2_DB_PATH", "GeoLite2-City.mmdb")
            if os.path.exists(db_path):
                reader = geoip2.database.Reader(db_path)
                response = reader.city(ip)
                
                result = {
                    "ip": ip,
                    "country_code": response.country.iso_code or "unknown",
                    "country_name": response.country.name or "unknown",
                    "city": response.city.name or "unknown",
                    "latitude": float(response.location.latitude) if response.location.latitude else None,
                    "longitude": float(response.location.longitude) if response.location.longitude else None,
                    "source": "MaxMind GeoLite2"
                }
                
                reader.close()
                _threat_intel_cache[cache_key] = result
                return result
        except (geoip2.errors.AddressNotFoundError, Exception) as e:
            print(f"GeoIP lookup failed for {ip}: {e}")
    
    # Fallback: Use free API
    try:
        # Using ipapi.co free service
        response = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5)
        if response.status_code == 200:
            data = response.json()
            if "error" not in data:
                result = {
                    "ip": ip,
                    "country_code": data.get("country_code", "unknown"),
                    "country_name": data.get("country_name", "unknown"),
                    "city": data.get("city", "unknown"),
                    "latitude": data.get("latitude"),
                    "longitude": data.get("longitude"),
                    "region": data.get("region", "unknown"),
                    "isp": data.get("org", "unknown"),
                    "source": "ipapi.co"
                }
                _threat_intel_cache[cache_key] = result
                return result
    except Exception as e:
        print(f"GeoIP API lookup failed for {ip}: {e}")
    
    return None


def _get_whois_info(ip: str) -> Optional[Dict]:
    """Get WHOIS information for an IP address."""
    if not ip:
        return None
    
    # Check cache first
    cache_key = f"whois_{ip}"
    if cache_key in _threat_intel_cache:
        return _threat_intel_cache[cache_key]
    
    if not IPWHOIS_AVAILABLE:
        return None
    
    try:
        obj = IPWhois(ip)
        whois_result = obj.lookup_rdap()
        
        result = {
            "ip": ip,
            "asn": whois_result.get("asn", "unknown"),
            "asn_description": whois_result.get("asn_description", "unknown"),
            "network": whois_result.get("network", {}).get("name", "unknown"),
            "cidr": whois_result.get("network", {}).get("cidr", "unknown"),
            "country": whois_result.get("network", {}).get("country", "unknown"),
            "source": "RDAP"
        }
        
        _threat_intel_cache[cache_key] = result
        return result
    except Exception as e:
        print(f"WHOIS lookup failed for {ip}: {e}")
    
    return None


def _enrich_alert_with_threat_intel(alert: dict) -> dict:
    """Enrich an alert with threat intelligence data."""
    enriched = dict(alert)
    
    # Enrich source IP
    src_ip = alert.get("src_ip")
    if src_ip:
        # AbuseIPDB check
        abuse_info = _check_abuseipdb(src_ip)
        if abuse_info:
            enriched["src_ip_reputation"] = abuse_info.get("ip_reputation", 0)
            enriched["src_ip_reports"] = abuse_info.get("total_reports", 0)
            enriched["src_ip_country"] = abuse_info.get("country_code", "unknown")
            enriched["src_ip_isp"] = abuse_info.get("isp", "unknown")
            
            # Boost risk score if malicious
            if abuse_info.get("ip_reputation", 0) > 50:
                enriched["threat_intel_boost"] = 0.15
        
        # GeoIP lookup
        geo_info = _get_geoip_info(src_ip)
        if geo_info:
            enriched["src_ip_geo"] = {
                "country": geo_info.get("country_name", "unknown"),
                "country_code": geo_info.get("country_code", "unknown"),
                "city": geo_info.get("city", "unknown"),
                "latitude": geo_info.get("latitude"),
                "longitude": geo_info.get("longitude")
            }
        
        # WHOIS lookup
        whois_info = _get_whois_info(src_ip)
        if whois_info:
            enriched["src_ip_whois"] = {
                "asn": whois_info.get("asn", "unknown"),
                "isp": whois_info.get("asn_description", "unknown"),
                "network": whois_info.get("network", "unknown")
            }
    
    # Enrich MITRE tags with technique info
    mitre_tags = alert.get("mitre_tags", [])
    if isinstance(mitre_tags, list) and mitre_tags:
        enriched["mitre_techniques"] = []
        for tag in mitre_tags:
            tech_info = _get_mitre_technique_info(tag)
            if tech_info:
                enriched["mitre_techniques"].append(tech_info)
    
    return enriched


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
    
    # Add timestamp if not present
    current_time = datetime.utcnow().isoformat()
    for alert in normed:
        if "timestamp" not in alert or not alert.get("timestamp"):
            alert["timestamp"] = current_time
    
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
def summary(use_llm: bool = Query(True, description="Use LLM for intelligent summary")):
    """
    Returns a summary of current alerts for analyst review.
    Now with AI-powered LLM summaries!
    """
    if not ALERTS:
        return {"summary": "No alerts available.", "llm_enhanced": False}
    
    # Generate AI-powered summary
    if use_llm:
        llm_summary = _generate_llm_summary(ALERTS, limit=50)
        return {
            "summary": llm_summary,
            "llm_enhanced": True,
            "total_alerts": len(ALERTS)
        }
    
    # Fallback to rule-based
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
    
    return {"summary": " | ".join(summary_parts), "llm_enhanced": False}


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


# -------- New AI-Powered Endpoints --------

@app.get("/alerts/ai-summary")
def ai_summary(limit: int = Query(50, ge=10, le=200, description="Number of recent alerts to analyze")):
    """
    Get AI-powered summary of recent alerts using LLM.
    """
    if not ALERTS:
        return {"summary": "No alerts available.", "llm_enhanced": False}
    
    summary_text = _generate_llm_summary(ALERTS, limit=limit)
    return {
        "summary": summary_text,
        "llm_enhanced": True,
        "alerts_analyzed": min(limit, len(ALERTS)),
        "total_alerts": len(ALERTS)
    }


@app.get("/alerts/clustered")
def clustered_alerts(
    min_cluster_size: int = Query(2, ge=2, le=10, description="Minimum alerts per cluster")
):
    """
    Get alerts grouped by similarity using embeddings and clustering.
    """
    if not ALERTS or not EMBEDDINGS_AVAILABLE:
        return {
            "clusters": {},
            "total_clusters": 0,
            "total_alerts": len(ALERTS),
            "clustering_available": EMBEDDINGS_AVAILABLE
        }
    
    clusters = _cluster_alerts(ALERTS)
    
    # Filter by minimum cluster size
    filtered_clusters = {
        cid: alerts for cid, alerts in clusters.items()
        if len(alerts) >= min_cluster_size
    }
    
    # Generate root cause hypotheses for each cluster
    cluster_insights = {}
    for cid, alerts in filtered_clusters.items():
        hypothesis = _generate_root_cause_hypothesis(alerts)
        cluster_insights[cid] = {
            "alerts": alerts,
            "count": len(alerts),
            "root_cause_hypothesis": hypothesis
        }
    
    return {
        "clusters": cluster_insights,
        "total_clusters": len(filtered_clusters),
        "total_alerts": len(ALERTS),
        "clustering_available": True
    }


@app.get("/alerts/prioritized")
def prioritized_alerts(
    limit: int = Query(50, ge=10, le=200, description="Number of top alerts to return"),
    min_priority: float = Query(0.0, ge=0.0, le=1.0, description="Minimum priority score")
):
    """
    Get alerts sorted by AI-calculated priority score.
    Combines y_prob with MITRE tags, traffic patterns, and port sensitivity.
    """
    if not ALERTS:
        return {"alerts": [], "total": 0}
    
    # Calculate priority scores
    alerts_with_priority = []
    for alert in ALERTS:
        priority_score = _calculate_ai_priority_score(alert)
        if priority_score >= min_priority:
            alert_copy = dict(alert)
            alert_copy["ai_priority_score"] = priority_score
            alerts_with_priority.append(alert_copy)
    
    # Sort by priority (highest first)
    alerts_with_priority.sort(key=lambda x: x["ai_priority_score"], reverse=True)
    
    # Return top N
    top_alerts = alerts_with_priority[:limit]
    
    return {
        "alerts": top_alerts,
        "total": len(alerts_with_priority),
        "returned": len(top_alerts),
        "min_priority": min_priority
    }


@app.get("/alerts/{alert_id}/explain")
def explain_alert(alert_id: int):
    """
    Get AI-powered explanation for why a specific alert was flagged.
    """
    # Find alert by row_id
    alert = None
    for a in ALERTS:
        if int(a.get("row_id", -1)) == alert_id:
            alert = a
            break
    
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
    
    # Generate explanation
    explanation_parts = []
    
    # Base probability explanation
    y_prob = float(alert.get("y_prob", 0))
    if y_prob > 0.7:
        explanation_parts.append(f"High threat probability ({y_prob:.2%})")
    elif y_prob > 0.5:
        explanation_parts.append(f"Moderate threat probability ({y_prob:.2%})")
    
    # MITRE tags explanation
    mitre_tags = alert.get("mitre_tags", [])
    if isinstance(mitre_tags, list) and mitre_tags:
        explanation_parts.append(f"Detected MITRE techniques: {', '.join(mitre_tags)}")
    
    # Traffic pattern explanation
    pps = float(alert.get("approx_packets_per_s", 0) or 0)
    bps = float(alert.get("approx_bytes_per_s", 0) or 0)
    if pps > 300:
        explanation_parts.append(f"Unusually high packet rate ({pps:.0f} pps) suggests DoS activity")
    if bps > 5_000_000:
        explanation_parts.append(f"High data transfer rate ({bps/1_000_000:.1f} MB/s) may indicate data exfiltration")
    
    # Port explanation
    dst_port = int(alert.get("dst_port", 0) or 0)
    port_explanations = {
        22: "SSH port - common target for brute-force attacks",
        21: "FTP port - plaintext credentials, high risk",
        23: "Telnet port - unencrypted, vulnerable",
        3389: "RDP port - frequent target for ransomware attacks"
    }
    if dst_port in port_explanations:
        explanation_parts.append(port_explanations[dst_port])
    
    explanation = " | ".join(explanation_parts) if explanation_parts else "Alert flagged based on network traffic analysis."
    
    return {
        "alert_id": alert_id,
        "explanation": explanation,
        "alert": alert,
        "ai_priority_score": _calculate_ai_priority_score(alert)
    }


# -------- Threat Intelligence Endpoints --------

@app.get("/threat-intel/ip/{ip_address}")
def get_ip_threat_intel(ip_address: str):
    """
    Get comprehensive threat intelligence for an IP address.
    Includes AbuseIPDB reputation, GeoIP, and WHOIS data.
    """
    result = {
        "ip": ip_address,
        "is_private": _is_private_ip(ip_address),
        "abuseipdb": None,
        "geoip": None,
        "whois": None
    }
    
    # Skip lookups for private IPs
    if result["is_private"]:
        return result
    
    # AbuseIPDB check (only for public IPs)
    abuse_info = _check_abuseipdb(ip_address)
    if abuse_info:
        result["abuseipdb"] = abuse_info
    
    # GeoIP lookup (only for public IPs)
    geo_info = _get_geoip_info(ip_address)
    if geo_info:
        result["geoip"] = geo_info
    
    # WHOIS lookup (only for public IPs)
    whois_info = _get_whois_info(ip_address)
    if whois_info:
        result["whois"] = whois_info
    
    return result


@app.get("/threat-intel/mitre/{technique_id}")
def get_mitre_technique(technique_id: str):
    """
    Get MITRE ATT&CK technique information.
    Example: GET /threat-intel/mitre/T1110
    """
    tech_info = _get_mitre_technique_info(technique_id)
    if not tech_info:
        raise HTTPException(status_code=404, detail=f"MITRE technique {technique_id} not found")
    
    return tech_info


@app.get("/alerts/enriched")
def enriched_alerts(
    limit: int = Query(50, ge=10, le=200, description="Number of alerts to return"),
    enrich: bool = Query(True, description="Enable threat intelligence enrichment")
):
    """
    Get alerts enriched with threat intelligence data.
    Includes IP reputation, GeoIP, WHOIS, and MITRE technique info.
    """
    if not ALERTS:
        return {"alerts": [], "total": 0}
    
    # Get recent alerts
    result = sorted(ALERTS, key=lambda x: int(x.get("row_id", 0)))
    result = result[-limit:] if len(result) > limit else result
    
    # Enrich with threat intelligence
    enriched_alerts_list = []
    for alert in result:
        if enrich:
            enriched = _enrich_alert_with_threat_intel(alert)
            # Recalculate priority with threat intel boost
            base_score = _calculate_ai_priority_score(enriched)
            threat_intel_boost = enriched.get("threat_intel_boost", 0)
            enriched["ai_priority_score"] = min(1.0, base_score + threat_intel_boost)
            enriched_alerts_list.append(enriched)
        else:
            enriched_alerts_list.append(alert)
    
    return {
        "alerts": enriched_alerts_list,
        "total": len(enriched_alerts_list),
        "enriched": enrich
    }


@app.get("/alerts/geo-summary")
def geo_summary():
    """
    Get geographical summary of alerts (attacker origins).
    Returns country-level statistics for world map visualization.
    """
    if not ALERTS:
        return {"countries": {}, "total_alerts": 0}
    
    country_stats = defaultdict(lambda: {"count": 0, "alerts": [], "ips": set()})
    
    # Sample alerts for GeoIP lookup (to avoid rate limits)
    sample_alerts = ALERTS[-100:] if len(ALERTS) > 100 else ALERTS
    
    for alert in sample_alerts:
        src_ip = alert.get("src_ip")
        if not src_ip:
            continue
        
        # Try to get country from cached geo data or lookup
        geo_info = _get_geoip_info(src_ip)
        if geo_info:
            country_code = geo_info.get("country_code", "unknown")
            country_name = geo_info.get("country_name", "unknown")
            
            country_stats[country_code]["count"] += 1
            country_stats[country_code]["alerts"].append({
                "row_id": alert.get("row_id"),
                "ip": src_ip,
                "mitre_tags": alert.get("mitre_tags", [])
            })
            country_stats[country_code]["ips"].add(src_ip)
            if country_name != "unknown":
                country_stats[country_code]["name"] = country_name
        
        # Also check if we have AbuseIPDB country data
        if "src_ip_country" in alert:
            country_code = alert.get("src_ip_country", "unknown")
            if country_code != "unknown":
                country_stats[country_code]["count"] += 1
                country_stats[country_code]["ips"].add(src_ip)
    
    # Convert sets to counts for JSON serialization
    geo_summary = {}
    for country_code, stats in country_stats.items():
        geo_summary[country_code] = {
            "name": stats.get("name", country_code),
            "alert_count": stats["count"],
            "unique_ips": len(stats["ips"]),
            "top_mitre_techniques": dict(Counter(
                tag for alert in stats["alerts"] 
                for tag in alert.get("mitre_tags", [])
            ).most_common(3))
        }
    
    return {
        "countries": geo_summary,
        "total_alerts_analyzed": len(sample_alerts),
        "total_countries": len(geo_summary)
    }


@app.get("/analytics/mitre-techniques")
def mitre_techniques_analytics(
    limit: int = Query(500, ge=1, le=5000, description="Number of recent alerts to analyze")
):
    """
    Get Top MITRE Techniques with percentages.
    Returns top 5 MITRE techniques observed with their frequencies and percentages.
    """
    if not ALERTS:
        return {
            "techniques": [],
            "total_alerts": 0,
            "analyzed_alerts": 0
        }
    
    # Get recent alerts up to limit
    result = sorted(ALERTS, key=lambda x: int(x.get("row_id", 0)))
    result = result[-limit:] if len(result) > limit else result
    
    # Count MITRE techniques
    technique_counter = Counter()
    total_technique_occurrences = 0
    
    for alert in result:
        mitre_tags = alert.get("mitre_tags", [])
        if isinstance(mitre_tags, list):
            for tag in mitre_tags:
                if tag:  # Skip empty tags
                    technique_counter[tag] += 1
                    total_technique_occurrences += 1
    
    # Get top 5 techniques
    top_techniques = technique_counter.most_common(5)
    
    # Build response with percentages
    techniques_data = []
    for technique, count in top_techniques:
        percentage = (count / total_technique_occurrences * 100) if total_technique_occurrences > 0 else 0
        techniques_data.append({
            "technique_id": technique,
            "count": count,
            "percentage": round(percentage, 2)
        })
    
    return {
        "techniques": techniques_data,
        "total_alerts": len(ALERTS),
        "analyzed_alerts": len(result),
        "total_technique_occurrences": total_technique_occurrences
    }


@app.get("/analytics/timeseries")
def timeseries_analytics(
    interval_minutes: int = Query(5, ge=1, le=60, description="Time interval in minutes for grouping"),
    limit: int = Query(500, ge=1, le=5000, description="Number of recent alerts to analyze")
):
    """
    Get time-series analytics for alerts.
    Returns alert frequency, top ports, and top IPs over time intervals.
    """
    if not ALERTS:
        return {
            "frequency": [],
            "ports": [],
            "ips": [],
            "interval_minutes": interval_minutes
        }
    
    # Get recent alerts
    result = sorted(ALERTS, key=lambda x: int(x.get("row_id", 0)))
    result = result[-limit:] if len(result) > limit else result
    
    # Parse timestamps and group by intervals
    from collections import defaultdict as dd
    interval_seconds = interval_minutes * 60
    
    freq_by_time = dd(int)
    ports_by_time = dd(Counter)
    ips_by_time = dd(Counter)
    
    for alert in result:
        timestamp_str = alert.get("timestamp")
        if not timestamp_str:
            # Use row_id as proxy for time if no timestamp
            alert_time = int(alert.get("row_id", 0))
            time_bucket = (alert_time // (interval_seconds // 30)) * (interval_seconds // 30)
        else:
            try:
                if isinstance(timestamp_str, str):
                    alert_time = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                else:
                    alert_time = timestamp_str
                # Convert to seconds since epoch, then bucket
                time_bucket = int(alert_time.timestamp() // interval_seconds) * interval_seconds
            except:
                # Fallback to row_id if timestamp parsing fails
                alert_time = int(alert.get("row_id", 0))
                time_bucket = (alert_time // (interval_seconds // 30)) * (interval_seconds // 30)
        
        freq_by_time[time_bucket] += 1
        
        # Track ports
        dst_port = alert.get("dst_port")
        if dst_port:
            ports_by_time[time_bucket][dst_port] += 1
        
        # Track source IPs
        src_ip = alert.get("src_ip")
        if src_ip:
            ips_by_time[time_bucket][src_ip] += 1
    
    # Convert to sorted lists
    sorted_times = sorted(freq_by_time.keys())
    
    frequency_data = [
        {
            "time": datetime.fromtimestamp(t).isoformat() if t > 1000000000 else f"Bucket {t}",
            "count": freq_by_time[t],
            "timestamp": t
        }
        for t in sorted_times
    ]
    
    ports_data = []
    ips_data = []
    
    for t in sorted_times:
        # Top 3 ports for this interval
        top_ports = ports_by_time[t].most_common(3)
        ports_data.append({
            "time": datetime.fromtimestamp(t).isoformat() if t > 1000000000 else f"Bucket {t}",
            "timestamp": t,
            "ports": [{"port": p, "count": c} for p, c in top_ports]
        })
        
        # Top 3 IPs for this interval
        top_ips = ips_by_time[t].most_common(3)
        ips_data.append({
            "time": datetime.fromtimestamp(t).isoformat() if t > 1000000000 else f"Bucket {t}",
            "timestamp": t,
            "ips": [{"ip": ip, "count": c} for ip, c in top_ips]
        })
    
    return {
        "frequency": frequency_data,
        "ports": ports_data,
        "ips": ips_data,
        "interval_minutes": interval_minutes,
        "total_intervals": len(sorted_times)
    }


@app.get("/alerts/{alert_id}/explain-features")
def explain_alert_features(alert_id: int):
    """
    Get feature importance explanation for a specific alert.
    Returns SHAP-like feature importance scores showing why the alert was flagged.
    """
    # Find the alert
    alert = None
    for a in ALERTS:
        if int(a.get("row_id", 0)) == alert_id:
            alert = a
            break
    
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
    
    # Calculate feature importance scores (simplified SHAP-like explanation)
    feature_importance = {}
    explanations = []
    
    # y_prob (threat probability) is the main indicator
    y_prob = alert.get("y_prob", 0.0)
    
    # Calculate importance for each feature
    dst_port = alert.get("dst_port", 0)
    protocol = alert.get("protocol", "").upper()
    pps = alert.get("approx_packets_per_s", 0.0)
    bps = alert.get("approx_bytes_per_s", 0.0)
    mitre_tags = alert.get("mitre_tags", [])
    
    # Port-based importance
    risky_ports = {22: 0.25, 23: 0.3, 21: 0.2, 3389: 0.35, 1433: 0.3, 3306: 0.25}
    if dst_port in risky_ports:
        port_score = risky_ports[dst_port]
        feature_importance["dst_port"] = {
            "value": dst_port,
            "importance": port_score,
            "impact": "positive" if port_score > 0.15 else "neutral",
            "explanation": f"Port {dst_port} is commonly targeted for {protocol if protocol else 'attacks'}"
        }
        explanations.append(f"⚠️ Port {dst_port} ({protocol}) is a high-risk port ({port_score:.0%} contribution)")
    
    # Packet rate importance
    if pps > 500:
        pps_score = min(0.3, (pps - 500) / 2000)
        feature_importance["approx_packets_per_s"] = {
            "value": round(pps, 2),
            "importance": pps_score,
            "impact": "positive",
            "explanation": f"High packet rate ({pps:.0f} pps) suggests aggressive scanning or DDoS"
        }
        explanations.append(f"📈 High packet rate ({pps:.0f} pps) increases threat score by {pps_score:.0%}")
    
    # Byte rate importance
    if bps > 1e7:  # > 10 MB/s
        bps_score = min(0.25, (bps - 1e7) / 5e7)
        feature_importance["approx_bytes_per_s"] = {
            "value": round(bps, 2),
            "importance": bps_score,
            "impact": "positive",
            "explanation": f"High bandwidth usage ({bps/1e6:.1f} MB/s) suggests data exfiltration"
        }
        explanations.append(f"💾 High bandwidth ({bps/1e6:.1f} MB/s) contributes {bps_score:.0%} to threat score")
    
    # MITRE tags importance
    if mitre_tags:
        mitre_score = min(0.4, len(mitre_tags) * 0.15)
        feature_importance["mitre_tags"] = {
            "value": mitre_tags,
            "importance": mitre_score,
            "impact": "positive",
            "explanation": f"MITRE techniques detected: {', '.join(mitre_tags)}"
        }
        explanations.append(f"🎯 MITRE techniques ({', '.join(mitre_tags)}) contribute {mitre_score:.0%} to threat score")
    
    # Protocol importance
    if protocol in ["TCP", "UDP"]:
        protocol_score = 0.05
        feature_importance["protocol"] = {
            "value": protocol,
            "importance": protocol_score,
            "impact": "neutral",
            "explanation": f"{protocol} protocol usage"
        }
    
    # Sort features by importance
    sorted_features = sorted(
        feature_importance.items(),
        key=lambda x: x[1].get("importance", 0),
        reverse=True
    )
    
    # Calculate total explainable score
    total_explained = sum(f.get("importance", 0) for f in feature_importance.values())
    
    return {
        "alert_id": alert_id,
        "y_prob": y_prob,
        "features": {k: v for k, v in sorted_features},
        "explanations": explanations,
        "total_feature_importance": round(total_explained, 3),
        "remaining_score": round(max(0, y_prob - total_explained), 3),
        "interpretation": f"This alert was flagged with {y_prob:.1%} threat probability. "
                         f"The key factors contributing to this score are explained above."
    }


# -------- SOC Assistant Chat Endpoints --------

@app.post("/chat/query")
def chat_query(query: str = Body(..., embed=True), history: List[Dict] = Body(default=[], embed=True)):
    """
    Process a chat query from the SOC Assistant.
    Uses RAG to retrieve relevant alerts and context, then generates a response.
    """
    if not query:
        return {"response": "Please provide a query.", "relevant_alerts": []}
    
    # Step 1: Parse query and retrieve relevant alerts (RAG)
    relevant_alerts = _retrieve_relevant_alerts(query)
    
    # Step 2: Generate response using LLM with context
    response = _generate_chat_response(query, relevant_alerts, history)
    
    return {
        "response": response,
        "relevant_alerts": relevant_alerts[:5],  # Return top 5 relevant alerts
        "query": query
    }


def _retrieve_relevant_alerts(query: str, limit: int = 10) -> List[dict]:
    """
    Retrieve relevant alerts based on the query using keyword matching and intent detection.
    This is a simple RAG implementation - can be enhanced with embeddings.
    """
    if not ALERTS:
        return []
    
    query_lower = query.lower()
    
    # Detect intent for direct alert retrieval queries
    show_intents = ["show", "list", "get", "display", "fetch", "give me", "retrieve"]
    alert_intents = ["alert", "alerts", "events", "incident", "incidents"]
    time_intents = ["previous", "last", "recent", "latest", "new", "recently", "newest"]
    
    is_show_query = any(intent in query_lower for intent in show_intents)
    is_alert_query = any(intent in query_lower for intent in alert_intents)
    is_time_query = any(intent in query_lower for intent in time_intents)
    
    # Extract number from query (e.g., "10 alerts", "previous 5")
    import re
    numbers = re.findall(r'\d+', query)
    requested_count = int(numbers[0]) if numbers else limit
    
    # If it's a "show alerts" query, directly return recent alerts
    if is_show_query and is_alert_query:
        # Get requested number of alerts (or default to limit)
        count = min(requested_count, 100)  # Cap at 100 for performance
        
        # Return most recent alerts sorted by row_id
        sorted_alerts = sorted(ALERTS, key=lambda x: int(x.get("row_id", 0)))
        return sorted_alerts[-count:] if len(sorted_alerts) > count else sorted_alerts
    
    # If it's a time-based query (previous/recent/last), return recent alerts
    if is_time_query and is_alert_query:
        count = min(requested_count if numbers else 10, 100)
        sorted_alerts = sorted(ALERTS, key=lambda x: int(x.get("row_id", 0)))
        return sorted_alerts[-count:] if len(sorted_alerts) > count else sorted_alerts
    
    # Otherwise, use keyword-based search
    scored_alerts = []
    
    for alert in ALERTS[-500:]:  # Search recent 500 alerts
        score = 0
        
        # Check source IP
        src_ip = str(alert.get("src_ip", "")).lower()
        if src_ip and src_ip in query_lower:
            score += 10
        
        # Check destination port
        dst_port = str(alert.get("dst_port", ""))
        if dst_port and dst_port in query:
            score += 8
        
        # Check protocol
        protocol = str(alert.get("protocol", "")).lower()
        if protocol and protocol in query_lower:
            score += 5
        
        # Check MITRE tags
        mitre_tags = alert.get("mitre_tags", [])
        if isinstance(mitre_tags, list):
            for tag in mitre_tags:
                if tag and tag.lower() in query_lower:
                    score += 10
        
        # Check country (if available)
        if "src_ip_country" in alert:
            country = str(alert.get("src_ip_country", "")).lower()
            country_keywords = ["russia", "china", "usa", "uk", "germany", "france"]
            for keyword in country_keywords:
                if keyword in query_lower and keyword in country:
                    score += 15
        
        # Check time-related keywords
        if any(word in query_lower for word in ["last hour", "recent", "new", "today"]):
            # Prioritize recent alerts
            row_id = alert.get("row_id", 0)
            if row_id > len(ALERTS) - 50:
                score += 5
        
        # Check port-specific queries
        port_keywords = {
            "22": ["ssh", "22", "port 22"],
            "80": ["http", "80", "port 80", "web"],
            "443": ["https", "443", "ssl", "tls"],
            "3389": ["rdp", "remote desktop", "3389"]
        }
        for port, keywords in port_keywords.items():
            if any(kw in query_lower for kw in keywords):
                if str(alert.get("dst_port", "")) == port:
                    score += 12
        
        if score > 0:
            scored_alerts.append((score, alert))
    
    # Sort by score and return top alerts
    scored_alerts.sort(key=lambda x: x[0], reverse=True)
    return [alert for _, alert in scored_alerts[:limit]]


def _generate_chat_response(query: str, relevant_alerts: List[dict], history: List[Dict]) -> str:
    """
    Generate a chat response using LLM with RAG context.
    Falls back to rule-based responses if LLM is not available.
    """
    # Build context from relevant alerts
    context = ""
    if relevant_alerts:
        context = "\n\nRelevant Alerts:\n"
        for i, alert in enumerate(relevant_alerts[:5], 1):
            context += f"{i}. Alert {alert.get('row_id', 'N/A')}: "
            context += f"Source: {alert.get('src_ip', 'N/A')}, "
            context += f"Port: {alert.get('dst_port', 'N/A')}, "
            context += f"Protocol: {alert.get('protocol', 'N/A')}, "
            context += f"MITRE: {', '.join(alert.get('mitre_tags', []))}, "
            context += f"Threat: {alert.get('y_prob', 0):.1%}\n"
    
    # Try LLM first (OpenAI)
    client = get_openai_client()
    if client and OPENAI_AVAILABLE:
        try:
            messages = [
                {
                    "role": "system",
                    "content": "You are a SOC (Security Operations Center) Assistant. Help analysts understand security alerts, identify threats, and answer questions about network security events. Use the provided alert context to give accurate, actionable answers."
                }
            ]
            
            # Add chat history
            for msg in history[-5:]:  # Last 5 messages for context
                messages.append({"role": msg.get("role", "user"), "content": msg.get("content", "")})
            
            # Add current query with context
            user_message = f"Query: {query}\n\n{context}" if context else query
            messages.append({"role": "user", "content": user_message})
            
            response = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=messages,
                max_tokens=500,
                temperature=0.7
            )
            
            return response.choices[0].message.content
        except Exception as e:
            print(f"LLM chat error: {e}")
            # Fall through to rule-based
    
    # Rule-based fallback responses
    query_lower = query.lower()
    
    # Port explanations
    if "port 22" in query_lower or "ssh" in query_lower or "22" in query_lower:
        return f"⚠️ **Port 22 (SSH) is risky** because it's commonly targeted for brute-force attacks and unauthorized access attempts. {context if context else 'I found ' + str(len(relevant_alerts)) + ' relevant alerts related to port 22.'}"
    
    # Country-based queries
    country_queries = ["russia", "china", "usa", "uk", "germany", "france"]
    for country in country_queries:
        if country in query_lower:
            count = len([a for a in relevant_alerts if country in str(a.get("src_ip_country", "")).lower()])
            return f"📍 I found **{count} alerts** from {country.capitalize()}. {context if count > 0 else 'No recent alerts found from this country.'}"
    
    # Summary queries
    if any(word in query_lower for word in ["summary", "summarize", "overview"]):
        total_alerts = len(ALERTS)
        recent = ALERTS[-100:] if len(ALERTS) > 100 else ALERTS
        return f"📊 **Summary**: {total_alerts} total alerts in system. Recent activity: {len(recent)} alerts analyzed. {context if relevant_alerts else 'No specific patterns identified.'}"
    
    # Handle "show alerts" queries
    show_intents = ["show", "list", "get", "display", "fetch", "give me", "retrieve"]
    alert_intents = ["alert", "alerts", "events", "incident", "incidents"]
    query_lower = query.lower()
    
    if any(intent in query_lower for intent in show_intents) and any(intent in query_lower for intent in alert_intents):
        if relevant_alerts:
            return f"📋 Here are **{len(relevant_alerts)} alerts** you requested:\n\n{context if context else 'These are the most recent alerts in the system.'}"
        else:
            return f"📋 I couldn't find any alerts matching your criteria. There are **{len(ALERTS)} total alerts** in the system. Try asking for 'recent alerts' or 'last N alerts'."
    
    # Generic response
    return f"🤖 I understand you're asking about: '{query}'. {context if relevant_alerts else 'I found ' + str(len(relevant_alerts)) + ' relevant alerts. Let me analyze them for you.'}"


# -------- Anomaly Detection & Predictive Analytics --------

@app.get("/analytics/anomalies")
def detect_anomalies(
    window_minutes: int = Query(30, ge=5, le=1440, description="Time window in minutes for analysis"),
    limit: int = Query(500, ge=50, le=5000, description="Number of recent alerts to analyze")
):
    """
    Detect anomalies in alert patterns using Isolation Forest.
    Flags unexpected traffic spikes, unusual patterns, and outliers.
    """
    if not ALERTS or len(ALERTS) < 10:
        return {
            "anomalies": [],
            "total_analyzed": 0,
            "anomaly_count": 0,
            "anomaly_rate": 0.0,
            "message": "Insufficient alerts for anomaly detection"
        }
    
    if not ANOMALY_DETECTION_AVAILABLE:
        return {
            "anomalies": [],
            "total_analyzed": 0,
            "anomaly_count": 0,
            "anomaly_rate": 0.0,
            "message": "Anomaly detection requires scikit-learn. Install with: pip install scikit-learn"
        }
    
    # Get recent alerts
    recent_alerts = sorted(ALERTS, key=lambda x: int(x.get("row_id", 0)))[-limit:]
    
    if len(recent_alerts) < 10:
        return {
            "anomalies": [],
            "total_analyzed": len(recent_alerts),
            "anomaly_count": 0,
            "anomaly_rate": 0.0,
            "message": "Need at least 10 alerts for anomaly detection"
        }
    
    # Prepare features for anomaly detection
    features = []
    alert_ids = []
    
    for alert in recent_alerts:
        # Extract numerical features
        feature_vector = [
            float(alert.get("dst_port", 0)),
            float(alert.get("approx_packets_per_s", 0)),
            float(alert.get("approx_bytes_per_s", 0)),
            float(alert.get("y_prob", 0)),
            len(alert.get("mitre_tags", [])),  # Number of MITRE tags
            int(alert.get("row_id", 0)) % 1000  # Pattern indicator
        ]
        features.append(feature_vector)
        alert_ids.append(alert.get("row_id", 0))
    
    features = np.array(features)
    
    # Train Isolation Forest
    try:
        # Contamination: expected proportion of anomalies (auto-detect if not specified)
        contamination = min(0.2, max(0.01, 5.0 / len(recent_alerts)))
        
        iso_forest = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100
        )
        
        # Fit and predict
        anomaly_labels = iso_forest.fit_predict(features)
        anomaly_scores = iso_forest.score_samples(features)
        
        # Identify anomalies (label == -1)
        anomalies = []
        for idx, (alert, label, score) in enumerate(zip(recent_alerts, anomaly_labels, anomaly_scores)):
            if label == -1:  # Anomaly detected
                anomalies.append({
                    "alert": alert,
                    "anomaly_score": float(score),
                    "row_id": alert.get("row_id", 0),
                    "reason": _explain_anomaly(alert, recent_alerts)
                })
        
        # Sort by anomaly score (most anomalous first)
        anomalies.sort(key=lambda x: x["anomaly_score"])
        
        # Calculate statistics
        total_analyzed = len(recent_alerts)
        anomaly_count = len(anomalies)
        anomaly_rate = (anomaly_count / total_analyzed) * 100 if total_analyzed > 0 else 0
        
        return {
            "anomalies": anomalies[:50],  # Return top 50 anomalies
            "total_analyzed": total_analyzed,
            "anomaly_count": anomaly_count,
            "anomaly_rate": round(anomaly_rate, 2),
            "window_minutes": window_minutes,
            "message": f"Detected {anomaly_count} anomalies ({anomaly_rate:.1f}%) in {total_analyzed} alerts"
        }
    
    except Exception as e:
        return {
            "anomalies": [],
            "total_analyzed": len(recent_alerts),
            "anomaly_count": 0,
            "anomaly_rate": 0.0,
            "message": f"Anomaly detection error: {str(e)}"
        }


def _explain_anomaly(alert: dict, all_alerts: List[dict]) -> str:
    """Generate human-readable explanation for why an alert is anomalous."""
    reasons = []
    
    # Check if port is unusual
    dst_port = alert.get("dst_port", 0)
    port_counts = Counter(a.get("dst_port", 0) for a in all_alerts)
    if port_counts.get(dst_port, 0) < len(all_alerts) * 0.05:  # Less than 5% of alerts
        reasons.append(f"unusual port {dst_port}")
    
    # Check if packet rate is very high
    pps = alert.get("approx_packets_per_s", 0)
    avg_pps = np.mean([a.get("approx_packets_per_s", 0) for a in all_alerts])
    if pps > avg_pps * 3:
        reasons.append("unusually high packet rate")
    
    # Check if byte rate is very high
    bps = alert.get("approx_bytes_per_s", 0)
    avg_bps = np.mean([a.get("approx_bytes_per_s", 0) for a in all_alerts])
    if bps > avg_bps * 3:
        reasons.append("unusually high bandwidth")
    
    # Check if threat probability is unusually high
    y_prob = alert.get("y_prob", 0)
    avg_prob = np.mean([a.get("y_prob", 0) for a in all_alerts])
    if y_prob > avg_prob + 0.3:
        reasons.append("high threat probability")
    
    # Check for unusual MITRE tags
    mitre_tags = alert.get("mitre_tags", [])
    if len(mitre_tags) > 2:
        reasons.append("multiple MITRE techniques")
    
    return ", ".join(reasons) if reasons else "statistical outlier"


@app.get("/analytics/forecast")
def forecast_attacks(
    period: str = Query("hour", regex="^(hour|day|week)$", description="Forecast period: hour, day, or week"),
    periods_ahead: int = Query(24, ge=1, le=168, description="Number of periods to forecast ahead"),
    limit: int = Query(1000, ge=100, le=10000, description="Number of recent alerts to analyze")
):
    """
    Forecast attack frequency per hour/day/week using time series analysis.
    Predicts future attack peaks based on historical patterns.
    """
    if not ALERTS or len(ALERTS) < 50:
        return {
            "forecast": [],
            "historical": [],
            "period": period,
            "periods_ahead": periods_ahead,
            "message": "Insufficient data for forecasting (need at least 50 alerts)"
        }
    
    # Get recent alerts
    recent_alerts = sorted(ALERTS, key=lambda x: int(x.get("row_id", 0)))[-limit:]
    
    # Group alerts by time period
    period_data = defaultdict(int)
    
    for alert in recent_alerts:
        timestamp_str = alert.get("timestamp")
        if timestamp_str:
            try:
                if isinstance(timestamp_str, str):
                    alert_time = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                else:
                    alert_time = timestamp_str
                
                # Group by period
                if period == "hour":
                    period_key = alert_time.strftime("%Y-%m-%d %H:00")
                    period_timestamp = alert_time.replace(minute=0, second=0, microsecond=0)
                elif period == "day":
                    period_key = alert_time.strftime("%Y-%m-%d")
                    period_timestamp = alert_time.replace(hour=0, minute=0, second=0, microsecond=0)
                else:  # week
                    # Get start of week (Monday)
                    days_since_monday = alert_time.weekday()
                    period_timestamp = alert_time.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=days_since_monday)
                    period_key = period_timestamp.strftime("%Y-W%U")
                
                period_data[period_key] += 1
                
            except Exception:
                # Use row_id as fallback
                row_id = alert.get("row_id", 0)
                period_bucket = row_id // 30  # Approximate period bucket
                period_key = f"period_{period_bucket}"
                period_data[period_key] += 1
    
    # Sort by period
    sorted_periods = sorted(period_data.items())
    
    # Calculate historical averages and trends
    historical_values = [count for _, count in sorted_periods]
    
    if len(historical_values) < 3:
        return {
            "forecast": [],
            "historical": [{"period": k, "count": v} for k, v in sorted_periods],
            "period": period,
            "periods_ahead": periods_ahead,
            "message": "Need at least 3 periods for forecasting"
        }
    
    # Simple forecasting using moving average and trend
    avg = np.mean(historical_values[-10:]) if len(historical_values) >= 10 else np.mean(historical_values)
    
    # Calculate trend
    if len(historical_values) >= 2:
        recent_trend = np.mean(historical_values[-5:]) - np.mean(historical_values[-10:-5] if len(historical_values) >= 10 else historical_values[:-5])
    else:
        recent_trend = 0
    
    # Generate forecast
    forecast = []
    base_value = historical_values[-1] if historical_values else avg
    
    for i in range(1, periods_ahead + 1):
        # Simple linear forecast with trend
        forecasted_count = max(0, base_value + (recent_trend * i))
        
        # Add some smoothing
        forecasted_count = forecasted_count * 0.7 + avg * 0.3
        
        # Round to integer
        forecasted_count = int(round(forecasted_count))
        
        forecast.append({
            "period": i,
            "forecasted_count": forecasted_count,
            "confidence": "medium" if len(historical_values) > 10 else "low"
        })
    
    # Prepare historical data
    historical = [{"period": k, "count": v} for k, v in sorted_periods[-20:]]  # Last 20 periods
    
    return {
        "forecast": forecast,
        "historical": historical,
        "period": period,
        "periods_ahead": periods_ahead,
        "average_count": round(avg, 2),
        "trend": round(recent_trend, 2),
        "message": f"Forecasted {periods_ahead} {period}s ahead based on {len(historical_values)} historical periods"
    }


@app.get("/analytics/predict")
def predict_next_attack(
    limit: int = Query(200, ge=50, le=2000, description="Number of recent alerts to analyze for patterns"),
    prediction_type: str = Query("port", regex="^(port|tactic|protocol)$", description="What to predict: port, tactic, or protocol")
):
    """
    Predict next likely attack vector using historical sequence patterns.
    Uses sequence analysis to predict likely next ports, tactics, or protocols.
    """
    if not ALERTS or len(ALERTS) < 20:
        return {
            "predictions": [],
            "confidence": 0.0,
            "prediction_type": prediction_type,
            "message": "Insufficient data for prediction (need at least 20 alerts)"
        }
    
    # Get recent alerts
    recent_alerts = sorted(ALERTS, key=lambda x: int(x.get("row_id", 0)))[-limit:]
    
    if len(recent_alerts) < 20:
        return {
            "predictions": [],
            "confidence": 0.0,
            "prediction_type": prediction_type,
            "message": "Need at least 20 alerts for sequence prediction"
        }
    
    # Build sequences for prediction
    sequences = []
    
    for alert in recent_alerts:
        if prediction_type == "port":
            value = str(alert.get("dst_port", ""))
        elif prediction_type == "tactic":
            mitre_tags = alert.get("mitre_tags", [])
            value = mitre_tags[0] if mitre_tags else ""
        else:  # protocol
            value = str(alert.get("protocol", "")).upper()
        
        if value:
            sequences.append(value)
    
    if not sequences:
        return {
            "predictions": [],
            "confidence": 0.0,
            "prediction_type": prediction_type,
            "message": f"No {prediction_type} data found in alerts"
        }
    
    # Analyze sequence patterns
    predictions = []
    
    # Method 1: Most frequent next value after current patterns
    transition_counts = defaultdict(lambda: Counter())
    
    # Look at sequences of 2-3 items to find patterns
    for i in range(len(sequences) - 1):
        current = sequences[i]
        next_val = sequences[i + 1]
        transition_counts[current][next_val] += 1
    
    # Also look at 2-item sequences
    if len(sequences) >= 2:
        for i in range(len(sequences) - 2):
            pattern = f"{sequences[i]}-{sequences[i+1]}"
            next_val = sequences[i + 2]
            transition_counts[pattern][next_val] += 1
    
    # Get most recent value(s) to predict next
    if len(sequences) >= 2:
        # Last 2 values as context
        context_2 = f"{sequences[-2]}-{sequences[-1]}"
        context_1 = sequences[-1]
    else:
        context_1 = sequences[-1]
        context_2 = None
    
    # Predict based on transitions
    seen_predictions = set()
    
    # Try 2-item pattern first
    if context_2 and context_2 in transition_counts:
        transitions = transition_counts[context_2]
        total_transitions = sum(transitions.values())
        
        for value, count in transitions.most_common(5):
            if value not in seen_predictions and total_transitions > 0:
                confidence = (count / total_transitions) * 100
                predictions.append({
                    "value": value,
                    "confidence": round(confidence, 2),
                    "pattern": context_2,
                    "occurrences": count
                })
                seen_predictions.add(value)
    
    # Fallback to 1-item pattern
    if context_1 and context_1 in transition_counts:
        transitions = transition_counts[context_1]
        total_transitions = sum(transitions.values())
        
        for value, count in transitions.most_common(5):
            if value not in seen_predictions and total_transitions > 0:
                confidence = (count / total_transitions) * 100
                predictions.append({
                    "value": value,
                    "confidence": round(confidence, 2),
                    "pattern": context_1,
                    "occurrences": count
                })
                seen_predictions.add(value)
    
    # Fallback: Most frequent overall
    if not predictions:
        overall_counts = Counter(sequences)
        for value, count in overall_counts.most_common(5):
            confidence = (count / len(sequences)) * 100
            predictions.append({
                "value": value,
                "confidence": round(confidence, 2),
                "pattern": "overall_frequency",
                "occurrences": count
            })
    
    # Calculate overall confidence
    overall_confidence = predictions[0]["confidence"] if predictions else 0.0
    
    return {
        "predictions": predictions[:5],  # Top 5 predictions
        "confidence": round(overall_confidence, 2),
        "prediction_type": prediction_type,
        "context": context_2 if context_2 else context_1,
        "patterns_analyzed": len(transition_counts),
        "message": f"Predicted next {prediction_type} based on {len(sequences)} alert sequences"
    }


# -------- Daily SOC Summary Reports --------

@app.get("/reports/daily-summary")
def daily_summary_report(
    date: Optional[str] = Query(None, description="Date for report (YYYY-MM-DD). Defaults to today"),
    limit: int = Query(2000, ge=100, le=10000, description="Number of alerts to analyze")
):
    """
    Generate comprehensive daily SOC summary report with natural language analysis and chart data.
    Includes: threat overview, top attack patterns, geographic analysis, and recommendations.
    """
    if not ALERTS or len(ALERTS) < 10:
        return {
            "report": "No alerts available for daily summary.",
            "date": date or datetime.now().strftime("%Y-%m-%d"),
            "charts": {},
            "statistics": {},
            "llm_enhanced": False
        }
    
    # Get alerts for analysis
    recent_alerts = sorted(ALERTS, key=lambda x: int(x.get("row_id", 0)))[-limit:]
    
    # Calculate statistics for charts
    stats = {
        "total_alerts": len(recent_alerts),
        "high_risk_alerts": len([a for a in recent_alerts if float(a.get("y_prob", 0)) > 0.7]),
        "unique_source_ips": len(set(a.get("src_ip", "") for a in recent_alerts if a.get("src_ip"))),
        "unique_destination_ports": len(set(a.get("dst_port", 0) for a in recent_alerts)),
        "total_bytes": sum(float(a.get("approx_bytes_per_s", 0)) for a in recent_alerts),
        "avg_threat_probability": np.mean([float(a.get("y_prob", 0)) for a in recent_alerts]) if ANOMALY_DETECTION_AVAILABLE else 0.0
    }
    
    # Top patterns for charts
    top_ips = Counter(a.get("src_ip", "unknown") for a in recent_alerts).most_common(10)
    top_ports = Counter(a.get("dst_port", 0) for a in recent_alerts).most_common(10)
    top_protocols = Counter(a.get("protocol", "unknown") for a in recent_alerts).most_common(5)
    top_mitre = Counter()
    for a in recent_alerts:
        tags = a.get("mitre_tags", [])
        if isinstance(tags, list):
            top_mitre.update(tags)
    top_mitre = top_mitre.most_common(5)
    
    # Geographic distribution (if available)
    countries = Counter()
    for a in recent_alerts:
        if "src_ip_country" in a:
            country = a.get("src_ip_country", "unknown")
            if country != "unknown":
                countries[country] += 1
    
    # Time distribution (by hour if timestamps available)
    hourly_distribution = Counter()
    for a in recent_alerts:
        timestamp_str = a.get("timestamp")
        if timestamp_str:
            try:
                if isinstance(timestamp_str, str):
                    alert_time = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                    hour = alert_time.hour
                    hourly_distribution[hour] += 1
            except:
                pass
    
    # Prepare chart data
    charts = {
        "top_source_ips": [{"ip": ip, "count": count} for ip, count in top_ips],
        "top_destination_ports": [{"port": port, "count": count} for port, count in top_ports],
        "protocol_distribution": [{"protocol": proto, "count": count} for proto, count in top_protocols],
        "mitre_techniques": [{"technique": tech, "count": count} for tech, count in top_mitre],
        "geographic_distribution": [{"country": country, "count": count} for country, count in countries.most_common(10)],
        "hourly_distribution": [{"hour": hour, "count": count} for hour, count in sorted(hourly_distribution.items())]
    }
    
    # Generate natural language report using LLM
    report_text = _generate_daily_summary_report(recent_alerts, stats, charts)
    
    # Calculate trends (compare with previous day if possible)
    trends = {
        "alert_trend": "stable",  # Could be enhanced with historical comparison
        "risk_trend": "stable",
        "top_threat": top_mitre[0][0] if top_mitre else "Unknown"
    }
    
    return {
        "report": report_text,
        "date": date or datetime.now().strftime("%Y-%m-%d"),
        "statistics": stats,
        "charts": charts,
        "trends": trends,
        "llm_enhanced": True,
        "alerts_analyzed": len(recent_alerts)
    }


def _generate_daily_summary_report(alerts: List[dict], stats: Dict, charts: Dict) -> str:
    """Generate comprehensive daily SOC summary report using LLM."""
    client = get_openai_client()
    
    # Extract key insights
    top_ips = charts.get("top_source_ips", [])[:5]
    top_ports = charts.get("top_destination_ports", [])[:5]
    top_mitre = charts.get("mitre_techniques", [])[:5]
    
    # Build comprehensive prompt
    prompt = f"""Generate a comprehensive daily SOC (Security Operations Center) summary report for {stats.get('total_alerts', 0)} alerts analyzed.

KEY STATISTICS:
- Total Alerts: {stats.get('total_alerts', 0)}
- High-Risk Alerts: {stats.get('high_risk_alerts', 0)}
- Unique Source IPs: {stats.get('unique_source_ips', 0)}
- Unique Destination Ports: {stats.get('unique_destination_ports', 0)}
- Average Threat Probability: {stats.get('avg_threat_probability', 0):.1%}

TOP THREAT PATTERNS:
- Top Source IPs: {', '.join(f'{ip["ip"]} ({ip["count"]} alerts)' for ip in top_ips)}
- Top Targeted Ports: {', '.join(f'Port {p["port"]} ({p["count"]} alerts)' for p in top_ports)}
- Top MITRE Techniques: {', '.join(f'{t["technique"]} ({t["count"]} occurrences)' for t in top_mitre)}

Write a professional 4-6 paragraph daily SOC summary report covering:
1. Executive summary of the day's threat landscape
2. Key attack patterns and trends observed
3. Notable security events and high-risk alerts
4. Geographic distribution of attacks (if available)
5. Recommendations for security improvements

Format: Natural language, professional tone, actionable insights."""
    
    if client and OPENAI_AVAILABLE:
        try:
            response = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are a senior SOC analyst writing comprehensive daily security summary reports for executives and security teams."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=800,
                temperature=0.7
            )
            
            return response.choices[0].message.content.strip()
        
        except Exception as e:
            print(f"LLM daily report generation failed: {e}")
            # Fall through to rule-based
    
    # Rule-based fallback report
    # Format top ports
    top_ports_str = ', '.join(f'Port {p["port"]} ({p["count"]} alerts)' for p in top_ports[:3])
    
    # Format top MITRE techniques
    top_mitre_str = ', '.join(f'{t["technique"]} ({t["count"]}x)' for t in top_mitre[:3])
    
    # Format top IPs
    top_ips_str = ', '.join(f'{ip["ip"]} ({ip["count"]} alerts)' for ip in top_ips[:3])
    
    report_parts = [
        f"**Daily SOC Summary Report - {datetime.now().strftime('%Y-%m-%d')}**\n\n",
        f"**Executive Summary:**\n",
        f"Today's security monitoring analyzed {stats.get('total_alerts', 0)} alerts across the network. "
        f"Of these, {stats.get('high_risk_alerts', 0)} were flagged as high-risk threats with threat probability above 70%. "
        f"The network observed activity from {stats.get('unique_source_ips', 0)} unique source IPs targeting {stats.get('unique_destination_ports', 0)} different destination ports.\n\n",
        f"**Key Attack Patterns:**\n",
        f"Top targeted ports: {top_ports_str}. "
        f"Most common MITRE techniques observed: {top_mitre_str}.\n\n",
        f"**Threat Assessment:**\n",
        f"Average threat probability across all alerts: {stats.get('avg_threat_probability', 0):.1%}. "
        f"Top attacking IPs by volume: {top_ips_str}.\n\n",
        f"**Recommendations:**\n",
        f"- Continue monitoring high-traffic ports for suspicious patterns\n",
        f"- Investigate source IPs with high alert frequency\n",
        f"- Review and update firewall rules for top targeted ports"
    ]
    
    return "".join(report_parts)


# -------- Attack Replay Simulation --------

@app.get("/simulation/replay")
def attack_replay_simulation(
    port: int = Query(..., ge=1, le=65535, description="Port to simulate as unprotected"),
    duration_hours: int = Query(24, ge=1, le=168, description="Duration of simulation in hours"),
    limit: int = Query(1000, ge=100, le=10000, description="Number of alerts to analyze")
):
    """
    Simulate what would happen if a certain port wasn't protected.
    Shows potential attacks, impact, and risk assessment.
    """
    if not ALERTS or len(ALERTS) < 10:
        return {
            "port": port,
            "duration_hours": duration_hours,
            "simulated_attacks": [],
            "impact_analysis": {},
            "risk_assessment": {},
            "message": "Insufficient data for simulation"
        }
    
    # Get alerts targeting this port
    recent_alerts = sorted(ALERTS, key=lambda x: int(x.get("row_id", 0)))[-limit:]
    
    # Filter alerts targeting this port
    port_alerts = [a for a in recent_alerts if int(a.get("dst_port", 0)) == port]
    
    if not port_alerts:
        return {
            "port": port,
            "duration_hours": duration_hours,
            "simulated_attacks": [],
            "impact_analysis": {
                "projected_attacks": 0,
                "projected_data_exfil": 0,
                "projected_packets": 0
            },
            "risk_assessment": {
                "risk_level": "low",
                "recommendation": f"No historical attacks on port {port}. Risk assessment: Low risk if port remains unprotected."
            },
            "message": f"No historical attacks found on port {port}. Simulation cannot project future attacks."
        }
    
    # Analyze attack patterns on this port
    attack_ips = Counter(a.get("src_ip", "unknown") for a in port_alerts)
    attack_protocols = Counter(a.get("protocol", "unknown") for a in port_alerts)
    mitre_techniques = Counter()
    for a in port_alerts:
        tags = a.get("mitre_tags", [])
        if isinstance(tags, list):
            mitre_techniques.update(tags)
    
    # Calculate projected impact
    total_bytes = sum(float(a.get("approx_bytes_per_s", 0)) for a in port_alerts)
    total_packets = sum(float(a.get("approx_packets_per_s", 0)) for a in port_alerts)
    avg_threat = np.mean([float(a.get("y_prob", 0)) for a in port_alerts]) if ANOMALY_DETECTION_AVAILABLE else 0.5
    
    # Project attacks over duration
    # Assume alerts occur at similar rate over time
    avg_alerts_per_hour = len(port_alerts) / max(1, duration_hours) if duration_hours > 0 else len(port_alerts)
    projected_attacks = int(avg_alerts_per_hour * duration_hours)
    
    # Project data exfiltration (assume sustained attack)
    projected_bytes_per_second = total_bytes / len(port_alerts) if port_alerts else 0
    projected_total_bytes = projected_bytes_per_second * duration_hours * 3600
    
    # Project packet volume
    projected_packets_per_second = total_packets / len(port_alerts) if port_alerts else 0
    projected_total_packets = projected_packets_per_second * duration_hours * 3600
    
    # Build simulation results
    simulated_attacks = []
    for alert in port_alerts[:20]:  # Top 20 examples
        simulated_attacks.append({
            "row_id": alert.get("row_id", 0),
            "src_ip": alert.get("src_ip", "unknown"),
            "protocol": alert.get("protocol", "unknown"),
            "threat_probability": alert.get("y_prob", 0),
            "packets_per_sec": alert.get("approx_packets_per_s", 0),
            "bytes_per_sec": alert.get("approx_bytes_per_s", 0),
            "mitre_tags": alert.get("mitre_tags", []),
            "simulated_impact": "High" if float(alert.get("y_prob", 0)) > 0.7 else "Medium" if float(alert.get("y_prob", 0)) > 0.5 else "Low"
        })
    
    # Impact analysis
    impact = {
        "historical_attacks": len(port_alerts),
        "projected_attacks": projected_attacks,
        "unique_attackers": len(set(a.get("src_ip", "") for a in port_alerts)),
        "projected_data_exfil_gb": round(projected_total_bytes / (1024**3), 2),
        "projected_packets_millions": round(projected_total_packets / 1e6, 2),
        "average_threat_probability": round(avg_threat, 3),
        "top_attackers": [{"ip": ip, "count": count} for ip, count in attack_ips.most_common(5)],
        "attack_protocols": [{"protocol": proto, "count": count} for proto, count in attack_protocols.most_common(3)],
        "mitre_techniques": [{"technique": tech, "count": count} for tech, count in mitre_techniques.most_common(5)]
    }
    
    # Risk assessment
    risk_score = avg_threat * (len(port_alerts) / 100.0) * min(1.0, projected_attacks / 100.0)
    
    if risk_score > 0.7:
        risk_level = "critical"
        recommendation = f"⚠️ **CRITICAL**: Port {port} is highly targeted. Immediate firewall rule implementation recommended. " \
                         f"Historical analysis shows {len(port_alerts)} attacks with average threat probability of {avg_threat:.1%}. " \
                         f"Projected {projected_attacks} attacks over {duration_hours} hours if unprotected."
    elif risk_score > 0.5:
        risk_level = "high"
        recommendation = f"⚠️ **HIGH RISK**: Port {port} shows significant attack activity. " \
                         f"Recommend implementing port filtering or access control. " \
                         f"Projected {projected_attacks} attacks if unprotected."
    elif risk_score > 0.3:
        risk_level = "medium"
        recommendation = f"⚠️ **MEDIUM RISK**: Port {port} has moderate attack activity. " \
                         f"Consider implementing additional security measures. " \
                         f"Projected {projected_attacks} attacks if unprotected."
    else:
        risk_level = "low"
        recommendation = f"ℹ️ **LOW RISK**: Port {port} shows minimal attack activity. " \
                        f"Standard security measures should be sufficient. " \
                        f"Projected {projected_attacks} attacks if unprotected."
    
    risk_assessment = {
        "risk_level": risk_level,
        "risk_score": round(risk_score, 3),
        "recommendation": recommendation,
        "urgency": "immediate" if risk_level == "critical" else "high" if risk_level == "high" else "medium" if risk_level == "medium" else "low"
    }
    
    return {
        "port": port,
        "duration_hours": duration_hours,
        "simulated_attacks": simulated_attacks,
        "impact_analysis": impact,
        "risk_assessment": risk_assessment,
        "message": f"Simulation complete: Port {port} unprotected for {duration_hours} hours"
    }
