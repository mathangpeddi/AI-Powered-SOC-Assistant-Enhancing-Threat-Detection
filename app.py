# app.py
from __future__ import annotations

from fastapi import FastAPI, Body, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Dict, Optional
import json
import random
import os
import csv
from collections import Counter, defaultdict

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
    EMBEDDINGS_AVAILABLE = True
except ImportError:
    EMBEDDINGS_AVAILABLE = False
    print("Warning: sentence-transformers/scikit-learn not installed. Clustering features disabled.")

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
