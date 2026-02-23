#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════════╗
║              THREAT INTEL ENRICHER — NEATLABS                                  ║
║              Standalone GUI · VirusTotal · AbuseIPDB · WHOIS                   ║
╚══════════════════════════════════════════════════════════════════════════════════╝

Standalone threat intelligence enrichment GUI for the NEATLABS security suite.
All backend enrichment logic is merged inline — single file, no pip dependencies.

USAGE:
    python3 threat_intel_gui.py                  # Launch GUI
    python3 threat_intel_gui.py capture.pcap     # Pre-load and analyze a PCAP
    python3 threat_intel_gui.py results.json     # Pre-load PCAP analyzer results

REQUIRES:
    Python 3.9+
    tkinter  (included in most Python installs; on Linux: sudo apt install python3-tk)
    No other dependencies — PCAP parsing is built in.

LICENSE:
    MIT License

    Copyright (c) 2025 NEATLABS / Security 360, LLC

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
"""

import sys, os, json, threading, time, re

# ── Startup crash logger ──────────────────────────────────────────────────────
def _write_crash_log(msg: str):
    try:
        log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "neatlabs_crash.log")
        with open(log_path, "a") as f:
            f.write(f"\n{'='*60}\n")
            f.write(f"Crash at {__import__('datetime').datetime.now()}\n")
            f.write(msg + "\n")
        print(f"Crash log written to: {log_path}")
    except Exception:
        pass

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

# ═════════════════════════════════════════════════════════════════════════════
# ENRICHER BACKEND (merged inline — no separate file needed)
# ═════════════════════════════════════════════════════════════════════════════

import socket, hashlib
import urllib.request, urllib.error, urllib.parse
from datetime import timedelta
from collections import OrderedDict

# ─────────────────────────────────────────────────────────────────────────────
# CONFIG LOADER
# ─────────────────────────────────────────────────────────────────────────────

_CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "neatlabs_config.json")
_LOADED_CONFIG: Optional[dict] = None

def _load_config() -> dict:
    global _LOADED_CONFIG
    if _LOADED_CONFIG is not None:
        return _LOADED_CONFIG
    cfg = {}
    if os.path.isfile(_CONFIG_FILE):
        try:
            with open(_CONFIG_FILE) as f:
                cfg = json.load(f)
        except Exception:
            pass
    _LOADED_CONFIG = cfg
    return cfg

def _invalidate_config_cache():
    """Force config to be re-read from disk on next access."""
    global _LOADED_CONFIG
    _LOADED_CONFIG = None

def _get_setting(env_key: str, config_key: str, default=None):
    """Resolve a setting: env var takes priority over config file."""
    env_val = os.environ.get(env_key)
    if env_val:
        return env_val
    cfg = _load_config()
    return cfg.get(config_key, default)

def get_vt_key() -> str:
    return _get_setting("NEATLABS_VT_KEY", "virustotal_api_key", "")

def get_abuseipdb_key() -> str:
    return _get_setting("NEATLABS_ABUSEIPDB_KEY", "abuseipdb_api_key", "")

def get_whois_age_days() -> int:
    val = _get_setting("NEATLABS_WHOIS_AGE_DAYS", "whois_new_domain_days", 60)
    try:
        return int(val)
    except (ValueError, TypeError):
        return 60

def enrichment_available() -> dict:
    """Return which enrichment services are configured."""
    return {
        "virustotal": bool(get_vt_key()),
        "abuseipdb":  bool(get_abuseipdb_key()),
        "whois":      True,
    }

# ─────────────────────────────────────────────────────────────────────────────
# LRU RESULT CACHE
# ─────────────────────────────────────────────────────────────────────────────

class _LRUCache:
    """Simple thread-safe LRU cache."""
    def __init__(self, maxsize=512):
        self._cache = OrderedDict()
        self._maxsize = maxsize
        self._lock = threading.Lock()

    def get(self, key):
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
                return self._cache[key]
        return None

    def set(self, key, value):
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
            self._cache[key] = value
            if len(self._cache) > self._maxsize:
                self._cache.popitem(last=False)

_vt_cache    = _LRUCache(512)
_abuse_cache = _LRUCache(512)
_whois_cache = _LRUCache(512)


# ─────────────────────────────────────────────────────────────────────────────
# RATE LIMITER
# ─────────────────────────────────────────────────────────────────────────────

class _RateLimiter:
    """Token bucket rate limiter."""
    def __init__(self, calls_per_minute: float):
        self._interval = 60.0 / max(calls_per_minute, 0.01)
        self._last_call = 0.0
        self._lock = threading.Lock()

    def wait(self, stop_event: threading.Event = None):
        with self._lock:
            now = time.time()
            elapsed = now - self._last_call
            remaining = self._interval - elapsed
            if remaining > 0:
                # Sleep in small increments so stop_event can interrupt
                slept = 0.0
                chunk = 0.1
                while slept < remaining:
                    if stop_event and stop_event.is_set():
                        return
                    time.sleep(min(chunk, remaining - slept))
                    slept += chunk
            self._last_call = time.time()

_vt_limiter    = _RateLimiter(calls_per_minute=4)
_abuse_limiter = _RateLimiter(calls_per_minute=20)
_whois_limiter = _RateLimiter(calls_per_minute=30)


# ─────────────────────────────────────────────────────────────────────────────
# HTTP HELPER
# ─────────────────────────────────────────────────────────────────────────────

def _http_get(url: str, headers: dict, timeout: int = 10) -> Optional[dict]:
    """Make an authenticated GET request, return parsed JSON or None."""
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return {"_http_error": e.code, "_reason": str(e.reason)}
    except Exception as e:
        return {"_error": str(e)}


# ─────────────────────────────────────────────────────────────────────────────
# VIRUSTOTAL
# ─────────────────────────────────────────────────────────────────────────────

def _vt_lookup_ip(ip: str, api_key: str, stop_event: threading.Event = None) -> dict:
    cached = _vt_cache.get(f"ip:{ip}")
    if cached is not None:
        return cached
    _vt_limiter.wait(stop_event)
    if stop_event and stop_event.is_set():
        return {"indicator": ip, "type": "ip", "source": "VirusTotal", "error": "Stopped"}
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    data = _http_get(url, {"x-apikey": api_key})
    result = _parse_vt_ip(ip, data)
    _vt_cache.set(f"ip:{ip}", result)
    return result

def _vt_lookup_domain(domain: str, api_key: str, stop_event: threading.Event = None) -> dict:
    cached = _vt_cache.get(f"domain:{domain}")
    if cached is not None:
        return cached
    _vt_limiter.wait(stop_event)
    if stop_event and stop_event.is_set():
        return {"indicator": domain, "type": "domain", "source": "VirusTotal", "error": "Stopped"}
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    data = _http_get(url, {"x-apikey": api_key})
    result = _parse_vt_domain(domain, data)
    _vt_cache.set(f"domain:{domain}", result)
    return result

def _parse_vt_ip(ip: str, data: Optional[dict]) -> dict:
    base = {"indicator": ip, "type": "ip", "source": "VirusTotal", "error": None}
    if not data or "_error" in data:
        base["error"] = data.get("_error", "No response") if data else "No response"
        return base
    if "_http_error" in data:
        base["error"] = f"HTTP {data['_http_error']}"
        return base
    try:
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless   = stats.get("harmless", 0)
        total      = sum(stats.values()) or 1
        base.update({
            "malicious":       malicious,
            "suspicious":      suspicious,
            "harmless":        harmless,
            "total_engines":   total,
            "detection_ratio": f"{malicious + suspicious}/{total}",
            "verdict":         _vt_verdict(malicious, suspicious),
            "country":         attrs.get("country", ""),
            "asn":             attrs.get("asn", ""),
            "as_owner":        attrs.get("as_owner", ""),
            "reputation":      attrs.get("reputation", 0),
            "categories":      list(attrs.get("categories", {}).values())[:5],
            "vt_link":         f"https://www.virustotal.com/gui/ip-address/{ip}",
        })
    except Exception as e:
        base["error"] = f"Parse error: {e}"
    return base

def _parse_vt_domain(domain: str, data: Optional[dict]) -> dict:
    base = {"indicator": domain, "type": "domain", "source": "VirusTotal", "error": None}
    if not data or "_error" in data:
        base["error"] = data.get("_error", "No response") if data else "No response"
        return base
    if "_http_error" in data:
        base["error"] = f"HTTP {data['_http_error']}"
        return base
    try:
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total      = sum(stats.values()) or 1
        base.update({
            "malicious":       malicious,
            "suspicious":      suspicious,
            "total_engines":   total,
            "detection_ratio": f"{malicious + suspicious}/{total}",
            "verdict":         _vt_verdict(malicious, suspicious),
            "reputation":      attrs.get("reputation", 0),
            "categories":      list(attrs.get("categories", {}).values())[:5],
            "registrar":       attrs.get("registrar", ""),
            "creation_date":   _ts_to_iso(attrs.get("creation_date")),
            "vt_link":         f"https://www.virustotal.com/gui/domain/{domain}",
        })
    except Exception as e:
        base["error"] = f"Parse error: {e}"
    return base

def _vt_verdict(malicious: int, suspicious: int) -> str:
    if malicious >= 5:  return "MALICIOUS"
    if malicious >= 2:  return "LIKELY_MALICIOUS"
    if malicious == 1:  return "SUSPICIOUS"
    if suspicious >= 3: return "SUSPICIOUS"
    return "CLEAN"


# ─────────────────────────────────────────────────────────────────────────────
# ABUSEIPDB
# ─────────────────────────────────────────────────────────────────────────────

def _abuseipdb_lookup(ip: str, api_key: str, stop_event: threading.Event = None) -> dict:
    cached = _abuse_cache.get(ip)
    if cached is not None:
        return cached
    _abuse_limiter.wait(stop_event)
    if stop_event and stop_event.is_set():
        return {"indicator": ip, "type": "ip", "source": "AbuseIPDB", "error": "Stopped"}
    params = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": "90", "verbose": ""})
    url    = f"https://api.abuseipdb.com/api/v2/check?{params}"
    data   = _http_get(url, {"Key": api_key, "Accept": "application/json"})
    result = _parse_abuseipdb(ip, data)
    _abuse_cache.set(ip, result)
    return result

def _parse_abuseipdb(ip: str, data: Optional[dict]) -> dict:
    base = {"indicator": ip, "type": "ip", "source": "AbuseIPDB", "error": None}
    if not data or "_error" in data:
        base["error"] = data.get("_error", "No response") if data else "No response"
        return base
    if "_http_error" in data:
        base["error"] = f"HTTP {data['_http_error']}"
        return base
    try:
        d     = data.get("data", {})
        score = d.get("abuseConfidenceScore", 0)
        base.update({
            "abuse_score":    score,
            "verdict":        _abuse_verdict(score),
            "total_reports":  d.get("totalReports", 0),
            "distinct_users": d.get("numDistinctUsers", 0),
            "country":        d.get("countryCode", ""),
            "isp":            d.get("isp", ""),
            "domain":         d.get("domain", ""),
            "is_tor":         d.get("isTor", False),
            "is_public":      d.get("isPublic", True),
            "last_reported":  d.get("lastReportedAt", ""),
            "abuseipdb_link": f"https://www.abuseipdb.com/check/{ip}",
        })
    except Exception as e:
        base["error"] = f"Parse error: {e}"
    return base

def _abuse_verdict(score: int) -> str:
    if score >= 80: return "MALICIOUS"
    if score >= 50: return "HIGH_RISK"
    if score >= 25: return "SUSPICIOUS"
    if score >= 5:  return "LOW_RISK"
    return "CLEAN"


# ─────────────────────────────────────────────────────────────────────────────
# WHOIS — STDLIB ONLY
# ─────────────────────────────────────────────────────────────────────────────

_WHOIS_SERVERS = {
    "com": "whois.verisign-grs.com", "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",          "info": "whois.afilias.net",
    "biz": "whois.biz",              "io":   "whois.nic.io",
    "co":  "whois.nic.co",           "us":   "whois.nic.us",
    "gov": "whois.nic.gov",          "mil":  "whois.nic.mil",
    "edu": "whois.educause.edu",     "xyz":  "whois.nic.xyz",
    "club":"whois.nic.club",         "top":  "whois.nic.top",
    "online":"whois.nic.online",     "site": "whois.nic.site",
    "ru":  "whois.tcinet.ru",        "uk":   "whois.nic.uk",
    "de":  "whois.denic.de",         "nl":   "whois.domain-registry.nl",
    "eu":  "whois.eu",               "cn":   "whois.cnnic.cn",
    "jp":  "whois.jprs.jp",          "au":   "whois.auda.org.au",
    "ca":  "whois.cira.ca",          "fr":   "whois.nic.fr",
    "it":  "whois.nic.it",           "br":   "whois.registro.br",
    "in":  "whois.registry.in",      "kr":   "whois.kr",
    "mx":  "whois.mx",               "se":   "whois.iis.se",
    "no":  "whois.norid.no",         "pl":   "whois.dns.pl",
    "es":  "whois.nic.es",
}

_DATE_PATTERNS = [
    r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})',
    r'(\d{4}-\d{2}-\d{2})',
    r'(\d{2}-\w{3}-\d{4})',
    r'(\d{2}\.\d{2}\.\d{4})',
    r'(\w+ \d{1,2},? \d{4})',
    r'(\d{4}\.\d{2}\.\d{2})',
]

_DATE_FORMATS = [
    "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d", "%d-%b-%Y",
    "%d.%m.%Y", "%B %d, %Y", "%B %d %Y", "%b %d, %Y", "%Y.%m.%d",
]

_CREATION_FIELDS = [
    "creation date", "created", "registered", "domain registered",
    "record created", "registration time", "created on",
    "domain create date", "registered on", "created date",
]
_REGISTRAR_FIELDS = ["registrar", "registrar name", "registrant organization", "sponsoring registrar"]
_EXPIRY_FIELDS    = ["expiry date", "registry expiry date", "expiration date", "expires", "expire date"]

def _whois_raw(domain: str, server: str, timeout: int = 8) -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((server, 43))
        s.send((domain + "\r\n").encode("utf-8"))
        chunks = []
        while True:
            try:
                chunk = s.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
            except socket.timeout:
                break
        s.close()
        return b"".join(chunks).decode("utf-8", errors="replace")
    except Exception as e:
        return f"WHOIS_ERROR: {e}"

def _find_referral_server(raw: str) -> Optional[str]:
    for line in raw.splitlines():
        lower = line.lower().strip()
        for prefix in ("whois server:", "refer:", "registrar whois server:"):
            if lower.startswith(prefix):
                val = line.split(":", 1)[-1].strip().lower()
                if val and "." in val and not val.startswith("WHOIS_ERROR"):
                    return val
    return None

def _parse_date(date_str: str) -> Optional[datetime]:
    date_str = date_str.strip().split("[")[0].strip()
    for fmt in _DATE_FORMATS:
        try:
            return datetime.strptime(date_str[:len(fmt)], fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None

def _extract_whois_field(raw: str, field_names: list) -> Optional[str]:
    for line in raw.splitlines():
        lower = line.lower().strip()
        for fname in field_names:
            if lower.startswith(fname + ":") or lower.startswith(fname.replace(" ", "") + ":"):
                parts = line.split(":", 1)
                if len(parts) == 2:
                    val = parts[1].strip()
                    if val and val.lower() not in ("", "not disclosed", "redacted for privacy",
                                                   "data not available", "n/a"):
                        return val
    return None

def _extract_creation_date(raw: str) -> Optional[datetime]:
    val = _extract_whois_field(raw, _CREATION_FIELDS)
    if not val:
        for line in raw.splitlines():
            if any(f in line.lower() for f in ("creat", "registered", "inception")):
                for pattern in _DATE_PATTERNS:
                    m = re.search(pattern, line)
                    if m:
                        dt = _parse_date(m.group(1))
                        if dt:
                            return dt
        return None
    for pattern in _DATE_PATTERNS:
        m = re.search(pattern, val)
        if m:
            dt = _parse_date(m.group(1))
            if dt:
                return dt
    return None

def whois_lookup(domain: str, stop_event: threading.Event = None) -> dict:
    """Perform a WHOIS lookup. Uses stdlib socket only — no external dependencies."""
    parts = domain.rstrip(".").lower().split(".")
    if len(parts) < 2:
        return {"indicator": domain, "error": "Invalid domain", "source": "WHOIS"}

    tld        = parts[-1]
    registrable = ".".join(parts[-2:])

    cached = _whois_cache.get(registrable)
    if cached is not None:
        return cached

    _whois_limiter.wait(stop_event)
    if stop_event and stop_event.is_set():
        return {"indicator": domain, "source": "WHOIS", "error": "Stopped"}

    result = {
        "indicator":    domain,
        "registrable":  registrable,
        "source":       "WHOIS",
        "error":        None,
        "creation_date": None,
        "expiry_date":   None,
        "registrar":     None,
        "domain_age_days": None,
        "is_new_domain": False,
        "new_domain_threshold_days": get_whois_age_days(),
        "verdict":       None,
        "raw_server":    None,
    }

    server = _WHOIS_SERVERS.get(tld)
    if not server:
        iana_raw = _whois_raw(tld, "whois.iana.org")
        if "WHOIS_ERROR" in iana_raw:
            result["error"] = f"IANA lookup failed: {iana_raw}"
            _whois_cache.set(registrable, result)
            return result
        server = _find_referral_server(iana_raw)
        if not server:
            result["error"] = f"No WHOIS server found for .{tld}"
            _whois_cache.set(registrable, result)
            return result

    result["raw_server"] = server
    raw = _whois_raw(registrable, server)
    if "WHOIS_ERROR" in raw:
        result["error"] = raw
        _whois_cache.set(registrable, result)
        return result

    referral = _find_referral_server(raw)
    if referral and referral != server:
        _whois_limiter.wait(stop_event)
        if not (stop_event and stop_event.is_set()):
            detailed = _whois_raw(registrable, referral)
            if "WHOIS_ERROR" not in detailed and len(detailed) > len(raw):
                raw = detailed
                result["raw_server"] = referral

    creation_dt = _extract_creation_date(raw)
    if creation_dt:
        result["creation_date"] = creation_dt.strftime("%Y-%m-%d")
        age = (datetime.now(timezone.utc) - creation_dt).days
        result["domain_age_days"] = age
        threshold = get_whois_age_days()
        result["is_new_domain"] = age < threshold
        result["verdict"] = "NEW_DOMAIN" if age < threshold else "ESTABLISHED"

    expiry_val = _extract_whois_field(raw, _EXPIRY_FIELDS)
    if expiry_val:
        for pattern in _DATE_PATTERNS:
            m = re.search(pattern, expiry_val)
            if m:
                dt = _parse_date(m.group(1))
                if dt:
                    result["expiry_date"] = dt.strftime("%Y-%m-%d")
                    break

    registrar = _extract_whois_field(raw, _REGISTRAR_FIELDS)
    if registrar:
        result["registrar"] = registrar[:80]

    if not creation_dt and not result.get("error"):
        result["error"] = "Creation date not found (may be redacted by privacy proxy)"

    _whois_cache.set(registrable, result)
    return result


# ─────────────────────────────────────────────────────────────────────────────
# MAIN ENRICHER CLASS
# ─────────────────────────────────────────────────────────────────────────────

class ThreatIntelEnricher:
    """
    Threat intel enrichment for the NEATLABS PCAP Analyzer.

    Enriches IPs and domains with:
      - VirusTotal reputation  (requires API key)
      - AbuseIPDB score        (requires API key)
      - WHOIS domain age       (always available, no key needed)
    """

    def __init__(self):
        self.vt_key     = get_vt_key()
        self.abuse_key  = get_abuseipdb_key()
        self.whois_days = get_whois_age_days()
        self.available  = enrichment_available()
        self.results: Dict[str, Any] = {}
        self._progress_cb = None

    def set_progress_callback(self, cb):
        """Optional callback: cb(current, total, message)"""
        self._progress_cb = cb

    def _progress(self, current, total, msg):
        if self._progress_cb:
            try:
                self._progress_cb(current, total, msg)
            except Exception:
                pass

    def enrich(self, analyzer_results: dict,
               on_ip_done=None, on_domain_done=None,
               stop_event: threading.Event = None) -> dict:
        """
        Run enrichment on all IOCs — fully parallelized.

        stop_event: threading.Event — set it to request cancellation.
        on_ip_done(ip, result_dict)         — called immediately per IP
        on_domain_done(domain, result_dict) — called immediately per domain
        """
        from concurrent.futures import ThreadPoolExecutor

        ips_to_check     = self._collect_ips(analyzer_results)
        domains_to_check = self._collect_domains(analyzer_results, analyzer_results, analyzer_results)

        enrichment = {
            "meta": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "services_used": {k: v for k, v in self.available.items() if v},
                "whois_new_domain_threshold_days": self.whois_days,
                "ips_checked": 0,
                "domains_checked": 0,
            },
            "ip_enrichment":     {},
            "domain_enrichment": {},
            "high_risk_ips":     [],
            "new_domains":       [],
            "malicious_domains": [],
            "summary":           {},
        }

        total      = len(ips_to_check) + len(domains_to_check)
        done_lock  = threading.Lock()
        done_count = [0]

        def tick(label):
            with done_lock:
                done_count[0] += 1
                self._progress(done_count[0], total, label)

        def enrich_ip(ip):
            if stop_event and stop_event.is_set():
                return ip, {"ip": ip, "combined_verdict": "STOPPED"}

            result = {"ip": ip, "virustotal": None, "abuseipdb": None}
            with ThreadPoolExecutor(max_workers=2) as ex2:
                futures = {}
                if self.vt_key:
                    futures["vt"]    = ex2.submit(_vt_lookup_ip, ip, self.vt_key, stop_event)
                if self.abuse_key:
                    futures["abuse"] = ex2.submit(_abuseipdb_lookup, ip, self.abuse_key, stop_event)
            if "vt"    in futures: result["virustotal"] = futures["vt"].result()
            if "abuse" in futures: result["abuseipdb"]  = futures["abuse"].result()
            result["combined_verdict"] = self._combined_ip_verdict(result)
            tick(f"IP done: {ip}  [{result['combined_verdict']}]")
            if on_ip_done:
                try:
                    on_ip_done(ip, result)
                except Exception:
                    pass
            return ip, result

        def enrich_domain(domain):
            if stop_event and stop_event.is_set():
                return domain, {"domain": domain, "combined_verdict": "STOPPED"}

            result = {"domain": domain, "virustotal": None, "whois": None}
            with ThreadPoolExecutor(max_workers=2) as ex2:
                futures = {}
                futures["whois"] = ex2.submit(whois_lookup, domain, stop_event)
                if self.vt_key:
                    futures["vt"] = ex2.submit(_vt_lookup_domain, domain, self.vt_key, stop_event)
            result["whois"]      = futures["whois"].result()
            if "vt" in futures:
                result["virustotal"] = futures["vt"].result()
            result["combined_verdict"] = self._combined_domain_verdict(result)
            tick(f"Domain done: {domain}  [{result['combined_verdict']}]")
            if on_domain_done:
                try:
                    on_domain_done(domain, result)
                except Exception:
                    pass
            return domain, result

        ip_workers = min(8, max(1, len(ips_to_check)))
        with ThreadPoolExecutor(max_workers=ip_workers) as pool:
            for ip, ip_result in pool.map(enrich_ip, ips_to_check):
                if stop_event and stop_event.is_set():
                    break
                enrichment["ip_enrichment"][ip] = ip_result
                if ip_result.get("combined_verdict") in ("MALICIOUS", "LIKELY_MALICIOUS", "HIGH_RISK"):
                    enrichment["high_risk_ips"].append({
                        "ip":          ip,
                        "verdict":     ip_result["combined_verdict"],
                        "vt_ratio":    (ip_result.get("virustotal") or {}).get("detection_ratio", ""),
                        "abuse_score": (ip_result.get("abuseipdb")  or {}).get("abuse_score", ""),
                    })

        enrichment["meta"]["ips_checked"] = len(enrichment["ip_enrichment"])

        dom_workers = min(4, max(1, len(domains_to_check)))
        with ThreadPoolExecutor(max_workers=dom_workers) as pool:
            for domain, dom_result in pool.map(enrich_domain, domains_to_check):
                if stop_event and stop_event.is_set():
                    break
                enrichment["domain_enrichment"][domain] = dom_result
                whois_r = dom_result.get("whois") or {}
                if whois_r.get("is_new_domain"):
                    enrichment["new_domains"].append({
                        "domain":    domain,
                        "created":   whois_r.get("creation_date", "unknown"),
                        "age_days":  whois_r.get("domain_age_days", "unknown"),
                        "registrar": whois_r.get("registrar", "unknown"),
                        "vt_verdict": (dom_result.get("virustotal") or {}).get("verdict", ""),
                    })
                if dom_result.get("combined_verdict") in ("MALICIOUS", "LIKELY_MALICIOUS"):
                    enrichment["malicious_domains"].append({
                        "domain":   domain,
                        "verdict":  dom_result["combined_verdict"],
                        "vt_ratio": (dom_result.get("virustotal") or {}).get("detection_ratio", ""),
                    })

        enrichment["meta"]["domains_checked"] = len(enrichment["domain_enrichment"])
        enrichment["summary"] = {
            "total_indicators":       len(enrichment["ip_enrichment"]) + len(enrichment["domain_enrichment"]),
            "high_risk_ip_count":     len(enrichment["high_risk_ips"]),
            "new_domain_count":       len(enrichment["new_domains"]),
            "malicious_domain_count": len(enrichment["malicious_domains"]),
            "overall_risk":           self._overall_risk(enrichment),
        }
        self.results = enrichment
        return enrichment

    # ── Verdict helpers ────────────────────────────────────────────────────────

    def _combined_ip_verdict(self, ip_result: dict) -> str:
        verdicts = []
        if ip_result.get("virustotal"):
            verdicts.append(ip_result["virustotal"].get("verdict", "CLEAN"))
        if ip_result.get("abuseipdb"):
            verdicts.append(ip_result["abuseipdb"].get("verdict", "CLEAN"))
        severity = {"MALICIOUS": 4, "LIKELY_MALICIOUS": 3, "HIGH_RISK": 3,
                    "SUSPICIOUS": 2, "LOW_RISK": 1, "CLEAN": 0}
        if not verdicts:
            return "UNCHECKED"
        return max(verdicts, key=lambda v: severity.get(v, 0))

    def _combined_domain_verdict(self, domain_result: dict) -> str:
        vt = domain_result.get("virustotal")
        if vt and vt.get("verdict") in ("MALICIOUS", "LIKELY_MALICIOUS"):
            return vt["verdict"]
        whois_r = domain_result.get("whois", {})
        if whois_r.get("is_new_domain"):
            if vt and vt.get("verdict") == "SUSPICIOUS":
                return "LIKELY_MALICIOUS"
            return "NEW_DOMAIN"
        if vt:
            return vt.get("verdict", "CLEAN")
        return "CHECKED"

    def _overall_risk(self, enrichment: dict) -> str:
        if enrichment["high_risk_ips"] or enrichment["malicious_domains"]:
            return "HIGH"
        if enrichment["new_domains"]:
            return "MEDIUM"
        return "LOW"

    # ── IOC collection ─────────────────────────────────────────────────────────

    def _collect_ips(self, results: dict) -> List[str]:
        import ipaddress
        _IP_RE = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')

        def is_private(ip: str) -> bool:
            try:
                return ipaddress.ip_address(ip).is_private
            except ValueError:
                return True

        def is_valid_ip(ip: str) -> bool:
            try:
                ipaddress.ip_address(ip)
                return True
            except ValueError:
                return False

        seen: set = set()

        def walk(obj, depth=0):
            if depth > 12: return
            if isinstance(obj, str):
                for m in _IP_RE.findall(obj):
                    if is_valid_ip(m) and not is_private(m):
                        seen.add(m)
            elif isinstance(obj, dict):
                for v in obj.values(): walk(v, depth + 1)
            elif isinstance(obj, (list, tuple)):
                for item in obj: walk(item, depth + 1)

        walk(results)
        return sorted(seen)[:50]

    def _collect_domains(self, iocs: dict, tls: dict, dns: dict) -> List[str]:
        _DOM_RE = re.compile(
            r'\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.'
            r'(?:[a-zA-Z0-9\-]{1,63}\.)*[a-zA-Z]{2,63})\b'
        )
        _SKIP_SUFFIXES    = (".local", ".internal", ".arpa", ".lan", ".home",
                             ".corp", ".example", ".test", ".invalid", ".localhost")
        _SKIP_EXTENSIONS  = (
            ".xml", ".html", ".htm", ".json", ".txt", ".log", ".cfg", ".conf",
            ".php", ".asp", ".aspx", ".jsp", ".js", ".css", ".png", ".jpg",
            ".gif", ".ico", ".svg", ".pdf", ".zip", ".gz", ".tar", ".exe",
            ".dll", ".so", ".py", ".sh", ".bat", ".cmd", ".ini", ".yaml", ".yml",
        )
        _SKIP_EXACT = {"localhost"}

        seen: set = set()

        def looks_like_domain(s: str) -> bool:
            if len(s) > 253 or len(s) < 4: return False
            if s in _SKIP_EXACT: return False
            if any(s.endswith(sx) for sx in _SKIP_SUFFIXES): return False
            if any(s.endswith(sx) for sx in _SKIP_EXTENSIONS): return False
            parts = s.rsplit(".", 1)
            if len(parts) < 2 or not parts[-1].isalpha() or not (2 <= len(parts[-1]) <= 24):
                return False
            import ipaddress
            try:
                ipaddress.ip_address(s)
                return False
            except ValueError:
                pass
            return True

        def walk(obj, depth=0):
            if depth > 12: return
            if isinstance(obj, str):
                for m in _DOM_RE.findall(obj):
                    d = m.lower().rstrip(".")
                    if looks_like_domain(d):
                        seen.add(d)
            elif isinstance(obj, dict):
                for v in obj.values(): walk(v, depth + 1)
            elif isinstance(obj, (list, tuple)):
                for item in obj: walk(item, depth + 1)

        walk(iocs)
        walk(tls)
        walk(dns)
        return sorted(seen)[:60]


# ─────────────────────────────────────────────────────────────────────────────
# HTML REPORT SECTION GENERATOR
# ─────────────────────────────────────────────────────────────────────────────

def render_enrichment_html(enrichment: dict) -> str:
    """Generate the HTML report section for threat intel enrichment."""
    if not enrichment:
        return ""

    meta    = enrichment.get("meta", {})
    summary = enrichment.get("summary", {})
    services = meta.get("services_used", {})

    services_html = " ".join(
        f'<span class="tag">{s}</span>'
        for s, active in services.items() if active
    )
    risk_color = {"HIGH": "#ef4444", "MEDIUM": "#eab308", "LOW": "#22c55e"}.get(
        summary.get("overall_risk", ""), "#94a3b8"
    )

    hr_ip_rows = ""
    for entry in enrichment.get("high_risk_ips", []):
        hr_ip_rows += f"""<tr>
            <td><code>{entry['ip']}</code></td>
            <td style="color:#ef4444;font-weight:700">{entry['verdict']}</td>
            <td>{entry.get('vt_ratio', '—')}</td>
            <td>{entry.get('abuse_score', '—')}</td>
        </tr>"""

    hr_ip_section = ""
    if hr_ip_rows:
        hr_ip_section = f"""
        <h3 style="color:#ef4444;margin:16px 0 8px">⚠ High Risk IPs</h3>
        <table><thead><tr>
            <th>IP Address</th><th>Verdict</th><th>VT Detections</th><th>Abuse Score</th>
        </tr></thead><tbody>{hr_ip_rows}</tbody></table>"""

    new_dom_rows = ""
    for entry in enrichment.get("new_domains", []):
        age = entry.get("age_days", "?")
        new_dom_rows += f"""<tr>
            <td>{entry['domain']}</td>
            <td style="color:#eab308;font-weight:600">{age} days</td>
            <td>{entry.get('created', '—')}</td>
            <td>{entry.get('registrar', '—')[:50]}</td>
            <td>{entry.get('vt_verdict', '—')}</td>
        </tr>"""

    new_dom_section = ""
    if new_dom_rows:
        threshold = meta.get("whois_new_domain_threshold_days", 60)
        new_dom_section = f"""
        <h3 style="color:#eab308;margin:16px 0 8px">🕐 Newly Registered Domains (under {threshold} days)</h3>
        <table><thead><tr>
            <th>Domain</th><th>Age</th><th>Created</th><th>Registrar</th><th>VT Verdict</th>
        </tr></thead><tbody>{new_dom_rows}</tbody></table>"""

    ip_rows = ""
    for ip, data in sorted(enrichment.get("ip_enrichment", {}).items()):
        vt     = data.get("virustotal") or {}
        abuse  = data.get("abuseipdb")  or {}
        verdict = data.get("combined_verdict", "—")
        vcol   = {"MALICIOUS": "#ef4444", "LIKELY_MALICIOUS": "#f97316",
                  "HIGH_RISK": "#f97316", "SUSPICIOUS": "#eab308"}.get(verdict, "#94a3b8")
        vt_cell    = f"{vt.get('detection_ratio','—')} ({vt.get('country','')})" if vt.get("detection_ratio") else "—"
        abuse_cell = f"{abuse.get('abuse_score','—')}% ({abuse.get('total_reports','—')} reports)" \
                     if abuse.get("abuse_score") is not None else "—"
        vt_link    = f"<a href='{vt.get('vt_link','')}' target='_blank' style='color:#5ca0ff'>VT ↗</a>" \
                     if vt.get("vt_link") else ""
        abuse_link = f"<a href='{abuse.get('abuseipdb_link','')}' target='_blank' style='color:#5ca0ff'>AIPDB ↗</a>" \
                     if abuse.get("abuseipdb_link") else ""
        ip_rows += f"""<tr>
            <td><code>{ip}</code></td>
            <td style="color:{vcol};font-weight:600">{verdict}</td>
            <td>{vt_cell}</td>
            <td>{abuse_cell}</td>
            <td>{vt_link} {abuse_link}</td>
        </tr>"""

    domain_rows = ""
    for domain, data in sorted(enrichment.get("domain_enrichment", {}).items()):
        vt    = data.get("virustotal") or {}
        whois = data.get("whois")      or {}
        verdict = data.get("combined_verdict", "—")
        vcol  = {"MALICIOUS": "#ef4444", "LIKELY_MALICIOUS": "#f97316",
                 "NEW_DOMAIN": "#eab308", "SUSPICIOUS": "#eab308"}.get(verdict, "#94a3b8")
        age_cell = (f"{whois.get('domain_age_days','?')}d ({whois.get('creation_date','?')})"
                    if whois.get("creation_date") else whois.get("error", "—"))
        vt_cell  = vt.get("detection_ratio", "—") if vt.get("detection_ratio") else "—"
        vt_link  = f"<a href='{vt.get('vt_link','')}' target='_blank' style='color:#5ca0ff'>VT ↗</a>" \
                   if vt.get("vt_link") else ""
        domain_rows += f"""<tr>
            <td>{domain}</td>
            <td style="color:{vcol};font-weight:600">{verdict}</td>
            <td>{age_cell}</td>
            <td>{vt_cell}</td>
            <td>{(whois.get('registrar') or '—')[:40]}</td>
            <td>{vt_link}</td>
        </tr>"""

    return f"""
<div class="section" style="border-color:#8b5cf6">
    <h2 style="color:#bb88ff">Threat Intel Enrichment</h2>
    <div style="display:flex;gap:20px;margin-bottom:16px;flex-wrap:wrap">
        <div><span style="color:#94a3b8;font-size:12px">SERVICES ACTIVE</span><br>
             {services_html or '<span class="tag">WHOIS only</span>'}</div>
        <div><span style="color:#94a3b8;font-size:12px">OVERALL RISK</span><br>
             <span style="color:{risk_color};font-weight:700;font-size:16px">{summary.get('overall_risk','—')}</span></div>
        <div><span style="color:#94a3b8;font-size:12px">IPs CHECKED</span><br>
             <span style="font-weight:700">{meta.get('ips_checked',0)}</span></div>
        <div><span style="color:#94a3b8;font-size:12px">DOMAINS CHECKED</span><br>
             <span style="font-weight:700">{meta.get('domains_checked',0)}</span></div>
        <div><span style="color:#94a3b8;font-size:12px">HIGH RISK IPs</span><br>
             <span style="color:#ef4444;font-weight:700">{summary.get('high_risk_ip_count',0)}</span></div>
        <div><span style="color:#94a3b8;font-size:12px">NEW DOMAINS</span><br>
             <span style="color:#eab308;font-weight:700">{summary.get('new_domain_count',0)}</span></div>
    </div>
    {hr_ip_section}
    {new_dom_section}
    <h3 style="color:#94a3b8;font-size:14px;margin:20px 0 8px">All IP Enrichment</h3>
    <div style="max-height:350px;overflow-y:auto">
    <table><thead><tr>
        <th>IP Address</th><th>Verdict</th><th>VT Detections</th><th>AbuseIPDB</th><th>Links</th>
    </tr></thead><tbody>{ip_rows or '<tr><td colspan="5" style="color:#94a3b8">No IPs enriched</td></tr>'}</tbody></table>
    </div>
    <h3 style="color:#94a3b8;font-size:14px;margin:20px 0 8px">All Domain Enrichment</h3>
    <div style="max-height:400px;overflow-y:auto">
    <table><thead><tr>
        <th>Domain</th><th>Verdict</th><th>Domain Age</th><th>VT Detections</th><th>Registrar</th><th>Links</th>
    </tr></thead><tbody>{domain_rows or '<tr><td colspan="6" style="color:#94a3b8">No domains enriched</td></tr>'}</tbody></table>
    </div>
</div>"""


# ─────────────────────────────────────────────────────────────────────────────
# UTILITIES
# ─────────────────────────────────────────────────────────────────────────────

def _ts_to_iso(ts) -> Optional[str]:
    if not ts:
        return None
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d")
    except Exception:
        return None

def generate_sample_config():
    """Write a sample neatlabs_config.json to the tool directory."""
    sample = {
        "_comment": "NEATLABS Threat Intel Config. Add your API keys and save. "
                    "DO NOT commit this file to version control.",
        "virustotal_api_key":    "",
        "abuseipdb_api_key":     "",
        "whois_new_domain_days": 60
    }
    path = _CONFIG_FILE
    if os.path.exists(path):
        print(f"[!] Config already exists: {path}")
        return path
    with open(path, "w") as f:
        json.dump(sample, f, indent=4)
    print(f"[+] Sample config written: {path}")
    return path


# ═════════════════════════════════════════════════════════════════════════════
# INLINE PCAP / PCAPng PARSER  (stdlib only — struct + socket)
# Supports: pcap (LE/BE timestamps, nanosecond variant), pcapng
# Extracts: external IPs, DNS query names, TLS SNI, HTTP Host headers
# ═════════════════════════════════════════════════════════════════════════════

import struct
import ipaddress as _ipaddress

class _InlinePcapParser:
    """
    Zero-dependency PCAP/PCAPng parser.
    Walks every packet and extracts external IPs and domain names.
    """

    # Link-layer types we handle
    _LINKTYPE_ETHERNET  = 1
    _LINKTYPE_RAW_IP    = 101
    _LINKTYPE_NULL      = 0    # BSD loopback
    _LINKTYPE_LINUX_SLL = 113  # Linux cooked capture

    def __init__(self, progress_cb=None):
        self._ips: set     = set()
        self._domains: set = set()
        self._errors: list = []
        self._pkts_total   = 0
        self._pkts_parsed  = 0
        self._progress_cb  = progress_cb   # optional: cb(msg: str)
        self._linktype     = self._LINKTYPE_ETHERNET
        self._interfaces: dict = {}  # pcapng interface id → linktype

    # ── Public API ────────────────────────────────────────────────────────────

    def parse_file(self, filepath: str) -> dict:
        """Parse file, return synthetic analyzer-results dict."""
        with open(filepath, "rb") as fh:
            raw = fh.read()

        if len(raw) < 4:
            raise ValueError("File is too small to be a PCAP/PCAPng")

        magic = struct.unpack("<I", raw[:4])[0]

        if magic == 0x0A0D0D0A:
            self._parse_pcapng(raw)
        elif magic in (0xa1b2c3d4, 0xd4c3b2a1,   # pcap LE/BE standard
                       0xa1b23c4d, 0x4d3cb2a1):   # pcap LE/BE nanosecond
            self._parse_pcap(raw, magic)
        else:
            raise ValueError(
                f"Unrecognised file format (magic bytes: {magic:#010x}). "
                "Expected .pcap or .pcapng.")

        return self._build_results()

    # ── PCAP ──────────────────────────────────────────────────────────────────

    def _parse_pcap(self, raw: bytes, magic: int):
        le = magic in (0xa1b2c3d4, 0xa1b23c4d)
        endian = "<" if le else ">"

        if len(raw) < 24:
            raise ValueError("Truncated PCAP global header")

        _, _, _, _, _, _, linktype = struct.unpack(endian + "IHHiIII", raw[:24])
        self._linktype = linktype
        offset = 24

        while offset + 16 <= len(raw):
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
                endian + "IIII", raw[offset:offset + 16])
            offset += 16
            if offset + incl_len > len(raw):
                break
            pkt = raw[offset: offset + incl_len]
            offset += incl_len
            self._pkts_total += 1
            self._dispatch(pkt, self._linktype)

        self._log(f"Parsed {self._pkts_total} packets (pcap)")

    # ── PCAPng ────────────────────────────────────────────────────────────────

    def _parse_pcapng(self, raw: bytes):
        offset = 0
        endian = "<"  # determined from SHB byte-order magic

        while offset + 12 <= len(raw):
            block_type   = struct.unpack("<I", raw[offset:offset + 4])[0]
            block_len_le = struct.unpack("<I", raw[offset + 4:offset + 8])[0]
            block_len_be = struct.unpack(">I", raw[offset + 4:offset + 8])[0]

            # Section Header Block — establishes byte order
            if block_type == 0x0A0D0D0A:
                bom = struct.unpack("<I", raw[offset + 8:offset + 12])[0]
                endian = "<" if bom == 0x1A2B3C4D else ">"
                block_len = struct.unpack(endian + "I", raw[offset + 4:offset + 8])[0]
                self._interfaces = {}
            else:
                block_len = struct.unpack(endian + "I", raw[offset + 4:offset + 8])[0]

            if block_len < 12 or offset + block_len > len(raw):
                break

            body = raw[offset + 8: offset + block_len - 4]

            # Interface Description Block
            if block_type == 0x00000001 and len(body) >= 4:
                link_type = struct.unpack(endian + "H", body[:2])[0]
                iface_id  = len(self._interfaces)
                self._interfaces[iface_id] = link_type

            # Enhanced Packet Block
            elif block_type == 0x00000006 and len(body) >= 20:
                iface_id = struct.unpack(endian + "I", body[:4])[0]
                cap_len  = struct.unpack(endian + "I", body[12:16])[0]
                pkt_data = body[20: 20 + cap_len]
                lt       = self._interfaces.get(iface_id, self._LINKTYPE_ETHERNET)
                self._pkts_total += 1
                self._dispatch(pkt_data, lt)

            # Obsolete Packet Block (type 2) / Simple Packet Block (type 3)
            elif block_type == 0x00000002 and len(body) >= 16:
                iface_id = struct.unpack(endian + "H", body[:2])[0]
                cap_len  = struct.unpack(endian + "I", body[8:12])[0]
                pkt_data = body[16: 16 + cap_len]
                lt       = self._interfaces.get(iface_id, self._LINKTYPE_ETHERNET)
                self._pkts_total += 1
                self._dispatch(pkt_data, lt)

            elif block_type == 0x00000003 and len(body) >= 4:
                orig_len = struct.unpack(endian + "I", body[:4])[0]
                pkt_data = body[4:]
                self._pkts_total += 1
                self._dispatch(pkt_data, self._interfaces.get(0, self._LINKTYPE_ETHERNET))

            offset += block_len

        self._log(f"Parsed {self._pkts_total} packets (pcapng)")

    # ── Link layer dispatch ───────────────────────────────────────────────────

    def _dispatch(self, pkt: bytes, linktype: int):
        try:
            if linktype == self._LINKTYPE_ETHERNET:
                self._parse_ethernet(pkt)
            elif linktype == self._LINKTYPE_RAW_IP:
                self._parse_ipv4(pkt, 0)
            elif linktype == self._LINKTYPE_NULL:
                if len(pkt) >= 4:
                    self._parse_ipv4(pkt, 4)
            elif linktype == self._LINKTYPE_LINUX_SLL:
                if len(pkt) >= 16:
                    etype = struct.unpack(">H", pkt[14:16])[0]
                    self._handle_ethertype(etype, pkt, 16)
        except Exception:
            pass

    def _parse_ethernet(self, pkt: bytes):
        if len(pkt) < 14:
            return
        etype = struct.unpack(">H", pkt[12:14])[0]
        self._handle_ethertype(etype, pkt, 14)

    def _handle_ethertype(self, etype: int, pkt: bytes, offset: int):
        # 802.1Q VLAN tag
        if etype == 0x8100:
            if len(pkt) < offset + 4:
                return
            etype = struct.unpack(">H", pkt[offset + 2:offset + 4])[0]
            offset += 4
        if etype == 0x0800:
            self._parse_ipv4(pkt, offset)
        elif etype == 0x86DD:
            self._parse_ipv6(pkt, offset)

    # ── Network layer ─────────────────────────────────────────────────────────

    def _parse_ipv4(self, pkt: bytes, offset: int):
        if len(pkt) < offset + 20:
            return
        ihl     = (pkt[offset] & 0x0F) * 4
        proto   = pkt[offset + 9]
        src_raw = pkt[offset + 12:offset + 16]
        dst_raw = pkt[offset + 16:offset + 20]
        ip_end  = offset + ihl

        src = socket.inet_ntoa(src_raw)
        dst = socket.inet_ntoa(dst_raw)
        self._record_ip(src)
        self._record_ip(dst)

        self._parse_transport(pkt, ip_end, proto)

    def _parse_ipv6(self, pkt: bytes, offset: int):
        if len(pkt) < offset + 40:
            return
        proto   = pkt[offset + 6]
        src_raw = pkt[offset + 8:offset + 24]
        dst_raw = pkt[offset + 24:offset + 40]
        try:
            self._record_ip(str(_ipaddress.IPv6Address(src_raw)))
            self._record_ip(str(_ipaddress.IPv6Address(dst_raw)))
        except Exception:
            pass
        self._parse_transport(pkt, offset + 40, proto)

    def _record_ip(self, ip: str):
        try:
            addr = _ipaddress.ip_address(ip)
            if not addr.is_private and not addr.is_loopback and not addr.is_multicast \
               and not addr.is_link_local and not addr.is_reserved:
                self._ips.add(str(addr))
        except Exception:
            pass

    # ── Transport layer ───────────────────────────────────────────────────────

    def _parse_transport(self, pkt: bytes, offset: int, proto: int):
        if proto == 17:   # UDP
            self._parse_udp(pkt, offset)
        elif proto == 6:  # TCP
            self._parse_tcp(pkt, offset)

    def _parse_udp(self, pkt: bytes, offset: int):
        if len(pkt) < offset + 8:
            return
        sport = struct.unpack(">H", pkt[offset:offset + 2])[0]
        dport = struct.unpack(">H", pkt[offset + 2:offset + 4])[0]
        payload = pkt[offset + 8:]
        if sport == 53 or dport == 53:
            self._parse_dns(payload)

    def _parse_tcp(self, pkt: bytes, offset: int):
        if len(pkt) < offset + 20:
            return
        sport      = struct.unpack(">H", pkt[offset:offset + 2])[0]
        dport      = struct.unpack(">H", pkt[offset + 2:offset + 4])[0]
        data_off   = ((pkt[offset + 12] >> 4) & 0xF) * 4
        payload    = pkt[offset + data_off:]
        if not payload:
            return
        if dport == 443 or sport == 443:
            self._parse_tls_sni(payload)
        if dport == 80 or sport == 80:
            self._parse_http_host(payload)

    # ── Application layer ─────────────────────────────────────────────────────

    def _parse_dns(self, data: bytes):
        """Extract DNS query names from a raw DNS payload."""
        if len(data) < 12:
            return
        qdcount = struct.unpack(">H", data[4:6])[0]
        offset  = 12
        for _ in range(min(qdcount, 8)):
            name, offset = self._dns_decode_name(data, offset)
            if name:
                self._record_domain(name)
            offset += 4  # skip QTYPE + QCLASS

    def _dns_decode_name(self, data: bytes, offset: int):
        """Decode a DNS label-encoded name, handling compression pointers."""
        labels = []
        visited = set()
        while offset < len(data):
            if offset in visited:
                break
            visited.add(offset)
            length = data[offset]
            if length == 0:
                offset += 1
                break
            elif (length & 0xC0) == 0xC0:
                if offset + 2 > len(data):
                    break
                ptr = struct.unpack(">H", data[offset:offset + 2])[0] & 0x3FFF
                sub, _ = self._dns_decode_name(data, ptr)
                if sub:
                    labels.append(sub)
                offset += 2
                break
            else:
                offset += 1
                if offset + length > len(data):
                    break
                labels.append(data[offset:offset + length].decode("ascii", errors="replace"))
                offset += length
        return ".".join(labels), offset

    def _parse_tls_sni(self, data: bytes):
        """Extract SNI hostname from a TLS ClientHello record."""
        try:
            if len(data) < 5 or data[0] != 0x16:
                return  # not TLS handshake
            rec_len = struct.unpack(">H", data[3:5])[0]
            if len(data) < 5 + rec_len or data[5] != 0x01:
                return  # not ClientHello
            # Skip: handshake type(1) + length(3) + client_version(2) + random(32)
            pos = 5 + 1 + 3 + 2 + 32
            if pos >= len(data):
                return
            sess_len = data[pos]; pos += 1 + sess_len
            if pos + 2 > len(data):
                return
            cs_len = struct.unpack(">H", data[pos:pos + 2])[0]; pos += 2 + cs_len
            if pos + 1 > len(data):
                return
            comp_len = data[pos]; pos += 1 + comp_len
            if pos + 2 > len(data):
                return
            ext_total = struct.unpack(">H", data[pos:pos + 2])[0]; pos += 2
            end = pos + ext_total
            while pos + 4 <= end and pos + 4 <= len(data):
                ext_type = struct.unpack(">H", data[pos:pos + 2])[0]
                ext_len  = struct.unpack(">H", data[pos + 2:pos + 4])[0]
                pos += 4
                if ext_type == 0x0000:  # SNI
                    if pos + 5 <= len(data):
                        name_len = struct.unpack(">H", data[pos + 3:pos + 5])[0]
                        if pos + 5 + name_len <= len(data):
                            sni = data[pos + 5:pos + 5 + name_len].decode("ascii", errors="ignore")
                            self._record_domain(sni)
                pos += ext_len
        except Exception:
            pass

    def _parse_http_host(self, data: bytes):
        """Extract Host header from an HTTP/1.x request."""
        try:
            text = data[:2048].decode("latin-1", errors="ignore")
            for line in text.splitlines():
                if line.lower().startswith("host:"):
                    host = line.split(":", 1)[1].strip().split(":")[0]
                    self._record_domain(host)
                    break
        except Exception:
            pass

    def _record_domain(self, name: str):
        name = name.strip().lower().rstrip(".")
        if not name or len(name) < 4 or "." not in name:
            return
        parts = name.rsplit(".", 1)
        if not parts[-1].isalpha() or not (2 <= len(parts[-1]) <= 24):
            return
        bad = (".local", ".arpa", ".internal", ".lan", ".home", ".corp",
               ".test", ".invalid", ".example", ".localhost")
        if any(name.endswith(b) for b in bad):
            return
        try:
            _ipaddress.ip_address(name)
            return
        except ValueError:
            pass
        self._domains.add(name)

    # ── Results ───────────────────────────────────────────────────────────────

    def _build_results(self) -> dict:
        """Return a synthetic dict matching what the enricher's collectors expect."""
        ips     = sorted(self._ips)
        domains = sorted(self._domains)
        self._log(f"Extracted {len(ips)} external IPs, {len(domains)} domains")
        return {
            "iocs": {
                "suspicious_ips":     ips,
                "suspicious_domains": domains,
            },
            "top_talkers": {
                "by_total_bytes": [{"ip": ip} for ip in ips],
            },
            "tls": {
                "sni_list": domains,
            },
            "dns": {
                "top_domains":  {d: 1 for d in domains},
                "dga_suspects": [],
            },
            "anomalies": [],
            "_pcap_meta": {
                "packets_total":    self._pkts_total,
                "external_ips":     len(ips),
                "domains_observed": len(domains),
                "parse_errors":     len(self._errors),
            },
        }

    def _log(self, msg: str):
        if self._progress_cb:
            try:
                self._progress_cb(msg)
            except Exception:
                pass

VERSION   = "1.1.0"
TOOL_NAME = "Threat Intel Enricher"
BRAND     = "NEATLABS"

# ═════════════════════════════════════════════════════════════════════════════
# COLOR PALETTE
# ═════════════════════════════════════════════════════════════════════════════

C = {
    "bg":           "#1e1e2e",
    "bg_alt":       "#252538",
    "surface":      "#2d2d44",
    "surface_hi":   "#363652",
    "border":       "#44446a",
    "border_light": "#55558a",
    "fg":           "#f0f0f5",
    "fg_dim":       "#b0b0cc",
    "fg_muted":     "#8888aa",
    "accent":       "#5ca0ff",
    "accent_hover": "#7db8ff",
    "green":        "#50e890",
    "yellow":       "#ffe066",
    "orange":       "#ffaa44",
    "red":          "#ff5566",
    "cyan":         "#44ddcc",
    "purple":       "#bb88ff",
    "row_even":     "#282840",
    "row_odd":      "#2e2e4a",
    "row_select":   "#3a4a70",
    "text_bg":      "#1a1a2e",
    "text_fg":      "#e8e8f0",
}

FONT_BODY       = ("Segoe UI", 11)
FONT_BODY_BOLD  = ("Segoe UI", 11, "bold")
FONT_HEADER     = ("Segoe UI", 14, "bold")
FONT_TITLE      = ("Segoe UI", 18, "bold")
FONT_SMALL      = ("Segoe UI", 10)
FONT_MONO       = ("Cascadia Code", 11)
FONT_MONO_SM    = ("Cascadia Code", 10)
FONT_TREE       = ("Cascadia Code", 10)
FONT_TREE_HEAD  = ("Segoe UI", 10, "bold")
FONT_TAB        = ("Segoe UI", 11, "bold")
FONT_BTN        = ("Segoe UI", 11)
FONT_BTN_ACCENT = ("Segoe UI", 11, "bold")

VERDICT_COLORS = {
    "MALICIOUS":        C["red"],
    "LIKELY_MALICIOUS": C["orange"],
    "HIGH_RISK":        C["orange"],
    "SUSPICIOUS":       C["yellow"],
    "NEW_DOMAIN":       C["yellow"],
    "LOW_RISK":         C["cyan"],
    "CLEAN":            C["green"],
    "CHECKED":          C["green"],
    "ESTABLISHED":      C["green"],
    "UNCHECKED":        C["fg_muted"],
}


# ═════════════════════════════════════════════════════════════════════════════
# MAIN APPLICATION
# ═════════════════════════════════════════════════════════════════════════════

class ThreatIntelGUI:
    def __init__(self, root: tk.Tk, preload_file: str = None):
        self.root = root
        self.root.title(f"{BRAND} — {TOOL_NAME} v{VERSION}")
        self.root.geometry("1440x900")
        self.root.minsize(1100, 700)
        self.root.configure(bg=C["bg"])

        self._enrichment_results: dict = {}
        self._partial_enrichment: dict = {}
        self._running = False
        self._stop_event = threading.Event()
        self._ip_row_idx  = [0]
        self._dom_row_idx = [0]

        self._setup_styles()
        self._build_ui()

        if preload_file:
            ext = os.path.splitext(preload_file)[1].lower()
            if ext in (".pcap", ".pcapng", ".cap"):
                self.root.after(300, lambda: self._load_pcap_file(preload_file))
            else:
                self.root.after(300, lambda: self._load_analyzer_results(preload_file))

        self._refresh_service_status()

    # ─────────────────────────────────────────────────────────────────────────
    # STYLES
    # ─────────────────────────────────────────────────────────────────────────

    def _setup_styles(self):
        s = ttk.Style()
        s.theme_use("clam")

        s.configure(".", background=C["bg"], foreground=C["fg"],
                    borderwidth=0, font=FONT_BODY, fieldbackground=C["surface"])
        s.configure("TFrame",         background=C["bg"])
        s.configure("TLabel",         background=C["bg"], foreground=C["fg"], font=FONT_BODY)
        s.configure("Dim.TLabel",     background=C["bg"], foreground=C["fg_dim"], font=FONT_SMALL)
        s.configure("Title.TLabel",   background=C["bg"], foreground=C["accent"], font=FONT_TITLE)
        s.configure("Header.TLabel",  background=C["bg"], foreground=C["fg"], font=FONT_HEADER)
        s.configure("Surface.TLabel", background=C["surface"], foreground=C["fg"], font=FONT_BODY)

        s.configure("TButton", font=FONT_BTN, padding=(14, 7),
                    background=C["surface"], foreground=C["fg"],
                    bordercolor=C["border"], borderwidth=1, relief="raised")
        s.map("TButton",
              background=[("active", C["surface_hi"]), ("pressed", C["accent"])],
              foreground=[("active", C["fg"]), ("pressed", "#ffffff")])

        s.configure("Accent.TButton", font=FONT_BTN_ACCENT, padding=(16, 8),
                    background=C["accent"], foreground="#ffffff",
                    bordercolor=C["accent"], borderwidth=1, relief="raised")
        s.map("Accent.TButton",
              background=[("active", C["accent_hover"]), ("pressed", "#4888dd")],
              foreground=[("active", "#ffffff"), ("pressed", "#ffffff")],
              state=[("disabled", C["surface"])])

        s.configure("TNotebook", background=C["bg"], borderwidth=0)
        s.configure("TNotebook.Tab", font=FONT_TAB, padding=(16, 9),
                    background=C["surface"], foreground=C["fg_dim"], borderwidth=0)
        s.map("TNotebook.Tab",
              background=[("selected", C["accent"]), ("!selected", C["surface"])],
              foreground=[("selected", "#ffffff"), ("!selected", C["fg_dim"])])

        s.configure("Treeview", background=C["row_even"], foreground=C["fg"],
                    fieldbackground=C["row_even"], font=FONT_TREE,
                    rowheight=28, borderwidth=1, relief="solid")
        s.configure("Treeview.Heading", background=C["surface_hi"],
                    foreground=C["accent"], font=FONT_TREE_HEAD,
                    borderwidth=1, relief="raised", padding=(6, 6))
        s.map("Treeview",
              background=[("selected", C["row_select"])],
              foreground=[("selected", "#ffffff")])

        s.configure("TEntry", font=FONT_MONO, fieldbackground=C["surface"],
                    foreground=C["fg"], insertcolor=C["fg"],
                    bordercolor=C["border"], borderwidth=1, padding=(8, 6))
        s.map("TEntry", bordercolor=[("focus", C["accent"])],
              fieldbackground=[("focus", C["bg_alt"])])

        s.configure("TProgressbar", troughcolor=C["surface"],
                    background=C["accent"], borderwidth=0, thickness=6)

        s.configure("Vertical.TScrollbar", background=C["surface"],
                    troughcolor=C["bg_alt"], borderwidth=0, arrowsize=14, width=14)
        s.map("Vertical.TScrollbar",
              background=[("active", C["border_light"]), ("!active", C["border"])])

        s.configure("TLabelframe", background=C["bg"], foreground=C["fg"],
                    bordercolor=C["border"], font=FONT_BODY_BOLD)
        s.configure("TLabelframe.Label", background=C["bg"],
                    foreground=C["accent"], font=FONT_BODY_BOLD)

        s.configure("TCheckbutton", background=C["bg"], foreground=C["fg"], font=FONT_BODY)
        s.map("TCheckbutton",
              background=[("active", C["bg"])],
              foreground=[("active", C["fg"])])

    # ─────────────────────────────────────────────────────────────────────────
    # UI BUILD
    # ─────────────────────────────────────────────────────────────────────────

    def _build_ui(self):
        # ── Header ──
        header = tk.Frame(self.root, bg=C["surface"], height=60, padx=20, pady=10)
        header.pack(fill="x")
        header.pack_propagate(False)

        tk.Label(header, text=f"◆ {BRAND}", bg=C["surface"],
                 fg=C["purple"], font=FONT_TITLE).pack(side="left")
        tk.Label(header, text=f"   {TOOL_NAME} v{VERSION}",
                 bg=C["surface"], fg=C["fg_dim"], font=FONT_BODY).pack(side="left", pady=(6, 0))

        self._svc_frame = tk.Frame(header, bg=C["surface"])
        self._svc_frame.pack(side="right")
        self._svc_labels = {}
        for svc in ("VirusTotal", "AbuseIPDB", "WHOIS"):
            f = tk.Frame(self._svc_frame, bg=C["surface"])
            f.pack(side="left", padx=8)
            dot = tk.Label(f, text="●", bg=C["surface"], fg=C["fg_muted"], font=("Segoe UI", 14))
            dot.pack(side="left")
            tk.Label(f, text=svc, bg=C["surface"], fg=C["fg_dim"],
                     font=FONT_SMALL).pack(side="left", padx=(2, 0))
            self._svc_labels[svc] = dot

        # ── Toolbar ──
        toolbar = tk.Frame(self.root, bg=C["bg_alt"], padx=16, pady=8)
        toolbar.pack(fill="x")

        btn_row = ttk.Frame(toolbar)
        btn_row.pack(side="left")

        ttk.Button(btn_row, text="  Load File (.pcap / .json)  ",
                   command=self._load_results_dialog,
                   style="Accent.TButton").pack(side="left", padx=(0, 6))
        ttk.Button(btn_row, text="  Run Enrichment  ",
                   command=self._run_enrichment,
                   style="Accent.TButton").pack(side="left", padx=(0, 6))
        ttk.Button(btn_row, text="  Stop  ",
                   command=self._stop_enrichment).pack(side="left", padx=3)
        ttk.Button(btn_row, text="  HTML Report  ",
                   command=self._export_html).pack(side="left", padx=3)
        ttk.Button(btn_row, text="  Export JSON  ",
                   command=self._export_json).pack(side="left", padx=3)
        ttk.Button(btn_row, text="  API Config  ",
                   command=self._show_config).pack(side="left", padx=3)
        ttk.Button(btn_row, text="  Clear  ",
                   command=self._clear_all).pack(side="left", padx=3)

        self._status_var = tk.StringVar(value="Ready — Load a PCAP or results JSON, or enter indicators manually")
        tk.Label(toolbar, textvariable=self._status_var,
                 bg=C["bg_alt"], fg=C["fg_dim"], font=("Segoe UI", 10),
                 anchor="e").pack(side="right", fill="x", expand=True, padx=(20, 0))

        # ── Progress bar ──
        self._progress = ttk.Progressbar(self.root, mode="indeterminate")
        self._progress.pack(fill="x")

        # ── Main notebook ──
        self._nb = ttk.Notebook(self.root)
        self._nb.pack(fill="both", expand=True, padx=12, pady=(8, 0))

        self._build_input_tab()
        self._build_ip_tab()
        self._build_domain_tab()
        self._build_whois_tab()
        self._build_summary_tab()
        self._build_config_tab()

        # ── Status bar ──
        bottom = tk.Frame(self.root, bg=C["surface"], height=30, padx=16, pady=4)
        bottom.pack(fill="x", side="bottom")
        bottom.pack_propagate(False)
        tk.Label(bottom, text=f"{BRAND} — {TOOL_NAME} v{VERSION}",
                 bg=C["surface"], fg=C["fg_muted"], font=("Segoe UI", 9)).pack(side="left")
        self._bottom_right = tk.Label(bottom, text="",
                                       bg=C["surface"], fg=C["fg_muted"],
                                       font=("Segoe UI", 9, "bold"))
        self._bottom_right.pack(side="right")

    # ─────────────────────────────────────────────────────────────────────────
    # TAB: INPUT
    # ─────────────────────────────────────────────────────────────────────────

    def _build_input_tab(self):
        frame = ttk.Frame(self._nb)
        self._nb.add(frame, text="  Input  ")

        cols = tk.Frame(frame, bg=C["bg"])
        cols.pack(fill="both", expand=True, padx=12, pady=10)

        # ── Left: IP input ──
        ip_frame = ttk.LabelFrame(cols, text=" IP Addresses ", padding=12)
        ip_frame.pack(side="left", fill="both", expand=True, padx=(0, 6))

        tk.Label(ip_frame, text="Enter IPs to enrich (one per line):",
                 bg=C["bg"], fg=C["fg_dim"], font=FONT_SMALL).pack(anchor="w", pady=(0, 4))

        self._ip_input = scrolledtext.ScrolledText(
            ip_frame, bg=C["text_bg"], fg=C["text_fg"],
            font=FONT_MONO, height=16, width=35,
            insertbackground=C["accent"], wrap="none",
            relief="flat", borderwidth=0, padx=10, pady=8)
        self._ip_input.pack(fill="both", expand=True)

        ip_btn_row = tk.Frame(ip_frame, bg=C["bg"])
        ip_btn_row.pack(fill="x", pady=(6, 0))
        ttk.Button(ip_btn_row, text="Parse from Results",
                   command=self._parse_ips_from_results).pack(side="left", padx=(0, 4))
        ttk.Button(ip_btn_row, text="Clear",
                   command=lambda: self._ip_input.delete("1.0", "end")).pack(side="left")

        self._ip_count_var = tk.StringVar(value="0 IPs")
        tk.Label(ip_btn_row, textvariable=self._ip_count_var,
                 bg=C["bg"], fg=C["fg_muted"], font=FONT_SMALL).pack(side="right")

        # ── Right: Domain input ──
        dom_frame = ttk.LabelFrame(cols, text=" Domains / FQDNs ", padding=12)
        dom_frame.pack(side="left", fill="both", expand=True, padx=(6, 0))

        tk.Label(dom_frame, text="Enter domains to enrich (one per line):",
                 bg=C["bg"], fg=C["fg_dim"], font=FONT_SMALL).pack(anchor="w", pady=(0, 4))

        self._dom_input = scrolledtext.ScrolledText(
            dom_frame, bg=C["text_bg"], fg=C["text_fg"],
            font=FONT_MONO, height=16, width=35,
            insertbackground=C["accent"], wrap="none",
            relief="flat", borderwidth=0, padx=10, pady=8)
        self._dom_input.pack(fill="both", expand=True)

        dom_btn_row = tk.Frame(dom_frame, bg=C["bg"])
        dom_btn_row.pack(fill="x", pady=(6, 0))
        ttk.Button(dom_btn_row, text="Parse from Results",
                   command=self._parse_domains_from_results).pack(side="left", padx=(0, 4))
        ttk.Button(dom_btn_row, text="Clear",
                   command=lambda: self._dom_input.delete("1.0", "end")).pack(side="left")

        self._dom_count_var = tk.StringVar(value="0 domains")
        tk.Label(dom_btn_row, textvariable=self._dom_count_var,
                 bg=C["bg"], fg=C["fg_muted"], font=FONT_SMALL).pack(side="right")

        # ── Options ──
        opts_frame = ttk.LabelFrame(frame, text=" Enrichment Options ", padding=12)
        opts_frame.pack(fill="x", padx=12, pady=(0, 8))

        opts_row = tk.Frame(opts_frame, bg=C["bg"])
        opts_row.pack(fill="x")

        self._use_vt_var    = tk.BooleanVar(value=bool(get_vt_key()))
        self._use_abuse_var = tk.BooleanVar(value=bool(get_abuseipdb_key()))
        self._use_whois_var = tk.BooleanVar(value=True)

        for var, label, always in [
            (self._use_vt_var,    "VirusTotal", False),
            (self._use_abuse_var, "AbuseIPDB",  False),
            (self._use_whois_var, "WHOIS",      True),
        ]:
            tk.Checkbutton(opts_row, text=label, variable=var,
                           bg=C["bg"], fg=C["fg"] if not always else C["green"],
                           selectcolor=C["surface"], activebackground=C["bg"],
                           activeforeground=C["fg"], font=FONT_BODY,
                           state="disabled" if always else "normal").pack(side="left", padx=12)

        tk.Label(opts_row, text="   New domain threshold:",
                 bg=C["bg"], fg=C["fg_dim"], font=FONT_BODY).pack(side="left", padx=(16, 4))
        self._whois_days_var = tk.StringVar(value=str(get_whois_age_days()))
        ttk.Entry(opts_row, textvariable=self._whois_days_var,
                  width=6, font=FONT_MONO).pack(side="left")
        tk.Label(opts_row, text="days", bg=C["bg"],
                 fg=C["fg_dim"], font=FONT_BODY).pack(side="left", padx=(4, 0))

        # ── Info bar ──
        info = tk.Frame(frame, bg=C["bg_alt"], padx=16, pady=8)
        info.pack(fill="x", padx=12, pady=(0, 4))
        self._loaded_file_var = tk.StringVar(
            value="No file loaded — load a .pcap or results JSON, or enter indicators manually")
        tk.Label(info, textvariable=self._loaded_file_var,
                 bg=C["bg_alt"], fg=C["fg_dim"], font=FONT_SMALL).pack(side="left")

        self._ip_input.bind("<KeyRelease>",  lambda e: self._update_counts())
        self._dom_input.bind("<KeyRelease>", lambda e: self._update_counts())

    # ─────────────────────────────────────────────────────────────────────────
    # TAB: IP ENRICHMENT
    # ─────────────────────────────────────────────────────────────────────────

    def _build_ip_tab(self):
        frame = ttk.Frame(self._nb)
        self._nb.add(frame, text="  IP Results  ")

        self._ip_stats_bar = tk.Frame(frame, bg=C["bg_alt"], padx=12, pady=6)
        self._ip_stats_bar.pack(fill="x", padx=8, pady=(6, 0))
        self._ip_stats_var = tk.StringVar(value="No results yet")
        tk.Label(self._ip_stats_bar, textvariable=self._ip_stats_var,
                 bg=C["bg_alt"], fg=C["fg_dim"], font=FONT_SMALL).pack(side="left")

        cols   = ("IP", "Verdict", "VT Ratio", "VT Country", "ASN",
                  "Abuse Score", "Abuse Reports", "ISP", "Tor")
        widths = [150, 120, 90, 80, 180, 90, 100, 200, 50]
        self._ip_tree = self._make_treeview(frame, cols, widths)
        self._ip_tree.bind("<<TreeviewSelect>>", self._show_ip_detail)

    # ─────────────────────────────────────────────────────────────────────────
    # TAB: DOMAIN ENRICHMENT
    # ─────────────────────────────────────────────────────────────────────────

    def _build_domain_tab(self):
        frame = ttk.Frame(self._nb)
        self._nb.add(frame, text="  Domain Results  ")

        self._dom_stats_bar = tk.Frame(frame, bg=C["bg_alt"], padx=12, pady=6)
        self._dom_stats_bar.pack(fill="x", padx=8, pady=(6, 0))
        self._dom_stats_var = tk.StringVar(value="No results yet")
        tk.Label(self._dom_stats_bar, textvariable=self._dom_stats_var,
                 bg=C["bg_alt"], fg=C["fg_dim"], font=FONT_SMALL).pack(side="left")

        cols   = ("Domain", "Verdict", "Age (days)", "Created", "Registrar",
                  "VT Ratio", "VT Categories", "Expiry")
        widths = [200, 130, 80, 100, 200, 90, 180, 100]
        self._dom_tree = self._make_treeview(frame, cols, widths)
        self._dom_tree.bind("<<TreeviewSelect>>", self._show_domain_detail)

    # ─────────────────────────────────────────────────────────────────────────
    # TAB: WHOIS DETAIL
    # ─────────────────────────────────────────────────────────────────────────

    def _build_whois_tab(self):
        frame = ttk.Frame(self._nb)
        self._nb.add(frame, text="  WHOIS  ")

        lookup_bar = tk.Frame(frame, bg=C["bg_alt"], padx=12, pady=8)
        lookup_bar.pack(fill="x", padx=8, pady=(6, 0))

        tk.Label(lookup_bar, text="Quick Lookup:",
                 bg=C["bg_alt"], fg=C["fg"], font=FONT_BODY_BOLD).pack(side="left")
        self._whois_lookup_var = tk.StringVar()
        entry = ttk.Entry(lookup_bar, textvariable=self._whois_lookup_var,
                          width=40, font=FONT_MONO)
        entry.pack(side="left", padx=(8, 6))
        entry.bind("<Return>", lambda e: self._quick_whois_lookup())
        ttk.Button(lookup_bar, text="Lookup",
                   command=self._quick_whois_lookup,
                   style="Accent.TButton").pack(side="left")

        self._whois_status_var = tk.StringVar(value="")
        tk.Label(lookup_bar, textvariable=self._whois_status_var,
                 bg=C["bg_alt"], fg=C["fg_dim"], font=FONT_SMALL).pack(side="right")

        self._new_dom_frame = ttk.LabelFrame(frame, text=" ⚠  Newly Registered Domains ", padding=10)
        self._new_dom_frame.pack(fill="x", padx=12, pady=(8, 0))
        self._new_dom_text = tk.Label(self._new_dom_frame, text="None detected",
                                      bg=C["bg"], fg=C["fg_muted"], font=FONT_MONO_SM,
                                      anchor="w", justify="left")
        self._new_dom_text.pack(fill="x")

        self._whois_text = scrolledtext.ScrolledText(
            frame, bg=C["text_bg"], fg=C["text_fg"],
            font=FONT_MONO, wrap="word",
            insertbackground=C["accent"],
            selectbackground=C["row_select"],
            relief="flat", borderwidth=0, padx=12, pady=10)
        self._whois_text.pack(fill="both", expand=True, padx=8, pady=(8, 8))
        self._whois_text.insert("1.0",
            "    Select a domain from the Domain Results tab\n"
            "    or use Quick Lookup above to view WHOIS detail.\n")

    # ─────────────────────────────────────────────────────────────────────────
    # TAB: SUMMARY
    # ─────────────────────────────────────────────────────────────────────────

    def _build_summary_tab(self):
        frame = ttk.Frame(self._nb)
        self._nb.add(frame, text="  Summary  ")
        self._summary_text = scrolledtext.ScrolledText(
            frame, bg=C["text_bg"], fg=C["text_fg"],
            font=FONT_MONO, wrap="word",
            insertbackground=C["accent"],
            selectbackground=C["row_select"],
            relief="flat", borderwidth=0, padx=12, pady=10)
        self._summary_text.pack(fill="both", expand=True, padx=8, pady=8)
        self._summary_text.insert("1.0", self._summary_placeholder())

    def _summary_placeholder(self) -> str:
        return f"""
    ╔═══════════════════════════════════════════════════════════════════════╗
    ║  {BRAND} — {TOOL_NAME} v{VERSION}                                 ║
    ║  Threat Intelligence Enrichment for the NEATLABS Security Suite      ║
    ╚═══════════════════════════════════════════════════════════════════════╝

    WORKFLOW:
      1. Load a .pcap file directly  OR  load a PCAP analyzer results JSON
      2. Configure API keys in the Config tab  (VT + AbuseIPDB are optional)
      3. Click Run Enrichment
      4. Review findings in IP Results, Domain Results, and WHOIS tabs
      5. Export HTML report or JSON

    ENRICHMENT SERVICES:
      ✦ VirusTotal    — IP + domain reputation, detection ratio, categories
                         Free tier: 4 req/min, 500/day
                         Get a key: https://www.virustotal.com/gui/sign-in

      ✦ AbuseIPDB     — IP abuse confidence score, report history, tor node check
                         Free tier: 1,000 req/day
                         Get a key: https://www.abuseipdb.com/register

      ✦ WHOIS         — Domain age, registrar, creation/expiry dates
                         Always available — no key needed
                         Flags domains registered within your threshold

    WHAT TO LOOK FOR:
      • High VT detection ratios on endpoint IPs
      • IPs with >80 AbuseIPDB confidence scores
      • Domains registered within the last 30-60 days (common for C2)
      • New domains + suspicious TLDs (.xyz, .top, .icu) = high confidence
      • Domains with DGA scores + new registration = very high confidence
"""

    # ─────────────────────────────────────────────────────────────────────────
    # TAB: CONFIG
    # ─────────────────────────────────────────────────────────────────────────

    def _build_config_tab(self):
        frame = ttk.Frame(self._nb)
        self._nb.add(frame, text="  Config  ")

        center = tk.Frame(frame, bg=C["bg"])
        center.place(relx=0.5, rely=0.5, anchor="center")

        title = ttk.LabelFrame(center, text=" API Configuration ", padding=24)
        title.pack(fill="both", expand=True, padx=20, pady=20)

        tk.Label(title,
            text="Keys are stored in neatlabs_config.json in the tool directory.\n"
                 "You can also set environment variables: NEATLABS_VT_KEY, NEATLABS_ABUSEIPDB_KEY\n"
                 "Do NOT commit neatlabs_config.json to version control.",
            bg=C["bg"], fg=C["fg_dim"], font=FONT_SMALL, justify="left").pack(anchor="w", pady=(0, 16))

        # ── VirusTotal ──
        vt_section = ttk.LabelFrame(title, text=" VirusTotal (optional) ", padding=12)
        vt_section.pack(fill="x", pady=(0, 12))

        vt_row = tk.Frame(vt_section, bg=C["bg"])
        vt_row.pack(fill="x")
        tk.Label(vt_row, text="API Key:", bg=C["bg"], fg=C["fg"],
                 font=FONT_BODY_BOLD, width=14, anchor="w").pack(side="left")
        self._vt_key_var = tk.StringVar(value=get_vt_key() or "")
        vt_entry = ttk.Entry(vt_row, textvariable=self._vt_key_var,
                             width=55, font=FONT_MONO, show="●")
        vt_entry.pack(side="left", padx=(0, 8))

        self._vt_show_var = tk.BooleanVar(value=False)
        tk.Checkbutton(vt_row, text="Show", variable=self._vt_show_var,
                       bg=C["bg"], fg=C["fg_dim"], selectcolor=C["surface"],
                       activebackground=C["bg"],
                       command=lambda: vt_entry.configure(
                           show="" if self._vt_show_var.get() else "●")).pack(side="left")

        self._vt_status = tk.Label(vt_section, text="Not configured",
                                    bg=C["bg"], fg=C["fg_muted"], font=FONT_SMALL)
        self._vt_status.pack(anchor="w", pady=(4, 0))
        tk.Label(vt_section, text="Get a free key: https://www.virustotal.com/gui/sign-in",
                 bg=C["bg"], fg=C["accent"], font=FONT_SMALL).pack(anchor="w")

        # ── AbuseIPDB ──
        abuse_section = ttk.LabelFrame(title, text=" AbuseIPDB (optional) ", padding=12)
        abuse_section.pack(fill="x", pady=(0, 12))

        abuse_row = tk.Frame(abuse_section, bg=C["bg"])
        abuse_row.pack(fill="x")
        tk.Label(abuse_row, text="API Key:", bg=C["bg"], fg=C["fg"],
                 font=FONT_BODY_BOLD, width=14, anchor="w").pack(side="left")
        self._abuse_key_var = tk.StringVar(value=get_abuseipdb_key() or "")
        abuse_entry = ttk.Entry(abuse_row, textvariable=self._abuse_key_var,
                                width=55, font=FONT_MONO, show="●")
        abuse_entry.pack(side="left", padx=(0, 8))

        self._abuse_show_var = tk.BooleanVar(value=False)
        tk.Checkbutton(abuse_row, text="Show", variable=self._abuse_show_var,
                       bg=C["bg"], fg=C["fg_dim"], selectcolor=C["surface"],
                       activebackground=C["bg"],
                       command=lambda: abuse_entry.configure(
                           show="" if self._abuse_show_var.get() else "●")).pack(side="left")

        self._abuse_status = tk.Label(abuse_section, text="Not configured",
                                       bg=C["bg"], fg=C["fg_muted"], font=FONT_SMALL)
        self._abuse_status.pack(anchor="w", pady=(4, 0))
        tk.Label(abuse_section, text="Get a free key: https://www.abuseipdb.com/register",
                 bg=C["bg"], fg=C["accent"], font=FONT_SMALL).pack(anchor="w")

        # ── WHOIS ──
        whois_section = ttk.LabelFrame(title, text=" WHOIS Domain Age (always enabled) ", padding=12)
        whois_section.pack(fill="x", pady=(0, 12))

        whois_row = tk.Frame(whois_section, bg=C["bg"])
        whois_row.pack(fill="x")
        tk.Label(whois_row, text="Flag domains newer than:",
                 bg=C["bg"], fg=C["fg"], font=FONT_BODY_BOLD).pack(side="left")
        self._cfg_whois_days_var = tk.StringVar(value=str(get_whois_age_days()))
        ttk.Entry(whois_row, textvariable=self._cfg_whois_days_var,
                  width=6, font=FONT_MONO).pack(side="left", padx=(8, 4))
        tk.Label(whois_row, text="days", bg=C["bg"], fg=C["fg_dim"],
                 font=FONT_BODY).pack(side="left")
        tk.Label(whois_section,
                 text="No API key required — uses direct WHOIS registry queries",
                 bg=C["bg"], fg=C["green"], font=FONT_SMALL).pack(anchor="w", pady=(4, 0))

        # ── Buttons ──
        btn_row = tk.Frame(title, bg=C["bg"])
        btn_row.pack(fill="x", pady=(16, 0))
        ttk.Button(btn_row, text="  Save Config  ",
                   command=self._save_config,
                   style="Accent.TButton").pack(side="left", padx=(0, 8))
        ttk.Button(btn_row, text="  Test VT Key  ",
                   command=self._test_vt_key).pack(side="left", padx=(0, 6))
        ttk.Button(btn_row, text="  Test AbuseIPDB Key  ",
                   command=self._test_abuse_key).pack(side="left", padx=(0, 6))
        ttk.Button(btn_row, text="  Generate Config File  ",
                   command=lambda: generate_sample_config() or messagebox.showinfo(
                       "Config Created", f"Sample config written to:\n{_CONFIG_FILE}")).pack(side="left")

        self._config_msg = tk.Label(title, text="", bg=C["bg"], fg=C["green"], font=FONT_SMALL)
        self._config_msg.pack(anchor="w", pady=(8, 0))

    # ─────────────────────────────────────────────────────────────────────────
    # WIDGET HELPERS
    # ─────────────────────────────────────────────────────────────────────────

    def _make_treeview(self, parent, columns, widths=None):
        container = ttk.Frame(parent)
        container.pack(fill="both", expand=True, padx=8, pady=6)

        tree = ttk.Treeview(container, columns=columns, show="headings",
                             selectmode="browse")
        for i, col in enumerate(columns):
            w = widths[i] if widths and i < len(widths) else 100
            tree.heading(col, text=col)
            tree.column(col, width=w, minwidth=40)

        tree.tag_configure("even",            background=C["row_even"], foreground=C["fg"])
        tree.tag_configure("odd",             background=C["row_odd"],  foreground=C["fg"])
        tree.tag_configure("MALICIOUS",       background="#4a1a22", foreground=C["red"])
        tree.tag_configure("LIKELY_MALICIOUS",background="#4a2a18", foreground=C["orange"])
        tree.tag_configure("HIGH_RISK",       background="#4a3018", foreground=C["orange"])
        tree.tag_configure("SUSPICIOUS",      background="#4a4418", foreground=C["yellow"])
        tree.tag_configure("NEW_DOMAIN",      background="#3a3a18", foreground=C["yellow"])
        tree.tag_configure("CLEAN",           background="#1a3a2e", foreground=C["green"])

        vsb = ttk.Scrollbar(container, orient="vertical",   command=tree.yview)
        hsb = ttk.Scrollbar(container, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        container.rowconfigure(0, weight=1)
        container.columnconfigure(0, weight=1)
        return tree

    # ─────────────────────────────────────────────────────────────────────────
    # ACTIONS
    # ─────────────────────────────────────────────────────────────────────────

    def _load_results_dialog(self):
        filetypes = [("Supported files", "*.pcap *.pcapng *.cap *.json"),
                     ("PCAP files",      "*.pcap *.pcapng *.cap"),
                     ("JSON results",    "*.json"),
                     ("All files",       "*.*")]
        fp = filedialog.askopenfilename(
            title="Load PCAP File or Analyzer Results JSON",
            filetypes=filetypes)
        if not fp:
            return
        ext = os.path.splitext(fp)[1].lower()
        if ext in (".pcap", ".pcapng", ".cap"):
            self._load_pcap_file(fp)
        else:
            self._load_analyzer_results(fp)

    def _load_pcap_file(self, filepath: str):
        fname = os.path.basename(filepath)
        self._loaded_file_var.set(f"Parsing: {fname} ...")
        self._set_status(f"Parsing {fname}...", C["yellow"])
        self._progress.start(15)

        def run():
            try:
                def on_prog(msg):
                    self.root.after(0, lambda m=msg:
                        self._set_status(f"{fname}: {m}", C["yellow"]))

                parser = _InlinePcapParser(progress_cb=on_prog)
                data   = parser.parse_file(filepath)
                self.root.after(0, lambda: self._on_pcap_analyzed(filepath, data))
            except Exception as e:
                err = str(e)
                self.root.after(0, lambda m=err:
                    messagebox.showerror("Parse Error", f"PCAP parsing failed:\n{m}"))
                self.root.after(0, lambda: self._set_status("PCAP parse failed", C["red"]))
            finally:
                self.root.after(0, lambda: self._progress.stop())

        threading.Thread(target=run, daemon=True).start()

    def _on_pcap_analyzed(self, filepath: str, data: dict):
        fname  = os.path.basename(filepath)
        meta   = data.get("_pcap_meta", {})
        self._analyzer_results = data
        self._loaded_file_var.set(f"Loaded: {fname}")
        self._parse_ips_from_results()
        self._parse_domains_from_results()
        ip_ct  = len(self._get_ip_list())
        dom_ct = len(self._get_domain_list())
        pkts   = meta.get("packets_total", "?")
        self._set_status(
            f"Parsed {fname} — {pkts} packets → {ip_ct} external IPs, {dom_ct} domains",
            C["green"])
        self._nb.select(0)

    def _load_analyzer_results(self, filepath: str):
        try:
            with open(filepath) as f:
                data = json.load(f)
            self._analyzer_results = data
            self._loaded_file_var.set(f"Loaded: {os.path.basename(filepath)}")
            self._parse_ips_from_results()
            self._parse_domains_from_results()
            self._set_status(
                f"Loaded {os.path.basename(filepath)} — "
                f"{len(self._get_ip_list())} IPs, {len(self._get_domain_list())} domains ready",
                C["cyan"])
        except Exception as e:
            messagebox.showerror("Load Error", f"Could not load results file:\n{e}")

    def _parse_ips_from_results(self):
        if not hasattr(self, "_analyzer_results"):
            return
        try:
            ips = ThreatIntelEnricher()._collect_ips(self._analyzer_results)
            self._ip_input.delete("1.0", "end")
            self._ip_input.insert("1.0", "\n".join(ips))
            self._update_counts()
        except Exception as e:
            messagebox.showerror("Parse Error", str(e))

    def _parse_domains_from_results(self):
        if not hasattr(self, "_analyzer_results"):
            return
        try:
            r = self._analyzer_results
            domains = ThreatIntelEnricher()._collect_domains(r, r, r)
            self._dom_input.delete("1.0", "end")
            self._dom_input.insert("1.0", "\n".join(domains))
            self._update_counts()
        except Exception as e:
            messagebox.showerror("Parse Error", str(e))

    def _get_ip_list(self) -> List[str]:
        raw = self._ip_input.get("1.0", "end").strip()
        if not raw:
            return []
        seen, result = set(), []
        for line in raw.splitlines():
            ip = line.strip()
            if ip and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip) and ip not in seen:
                seen.add(ip)
                result.append(ip)
        return result

    def _get_domain_list(self) -> List[str]:
        raw = self._dom_input.get("1.0", "end").strip()
        if not raw:
            return []
        seen, result = set(), []
        for line in raw.splitlines():
            d = line.strip().lower().rstrip(".")
            if d and "." in d and len(d) < 255 and d not in seen:
                seen.add(d)
                result.append(d)
        return result

    def _update_counts(self):
        self._ip_count_var.set(f"{len(self._get_ip_list())} IPs")
        self._dom_count_var.set(f"{len(self._get_domain_list())} domains")

    def _run_enrichment(self):
        ips     = self._get_ip_list()
        domains = self._get_domain_list()

        if not ips and not domains:
            messagebox.showinfo("Nothing to Enrich",
                "Add IP addresses or domains to the Input tab first.")
            return

        if self._running:
            messagebox.showinfo("Running", "Enrichment is already in progress.")
            return

        self._running = True
        self._stop_event.clear()
        self._progress.start(15)
        self._set_status(
            f"Running enrichment: {len(ips)} IPs, {len(domains)} domains...", C["yellow"])

        self._ip_tree.delete(*self._ip_tree.get_children())
        self._dom_tree.delete(*self._dom_tree.get_children())
        self._partial_enrichment = {
            "meta": {
                "services_used": {}, "ips_checked": 0, "domains_checked": 0,
                "whois_new_domain_threshold_days": get_whois_age_days(),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
            "ip_enrichment": {}, "domain_enrichment": {},
            "high_risk_ips": [], "new_domains": [], "malicious_domains": [],
            "summary": {},
        }
        self._ip_row_idx  = [0]
        self._dom_row_idx = [0]

        def on_ip_done(ip, result):
            self._partial_enrichment["ip_enrichment"][ip] = result
            self.root.after(0, lambda i=ip, r=result: self._insert_ip_row(i, r))

        def on_domain_done(domain, result):
            self._partial_enrichment["domain_enrichment"][domain] = result
            w = result.get("whois") or {}
            if w.get("is_new_domain"):
                self._partial_enrichment["new_domains"].append({
                    "domain":    domain,
                    "created":   w.get("creation_date", "unknown"),
                    "age_days":  w.get("domain_age_days", "unknown"),
                    "registrar": w.get("registrar", "unknown"),
                    "vt_verdict": (result.get("virustotal") or {}).get("verdict", ""),
                })
            if result.get("combined_verdict") in ("MALICIOUS", "LIKELY_MALICIOUS"):
                self._partial_enrichment["malicious_domains"].append({
                    "domain":   domain,
                    "verdict":  result["combined_verdict"],
                    "vt_ratio": (result.get("virustotal") or {}).get("detection_ratio", ""),
                })
            self.root.after(0, lambda d=domain, r=result: self._insert_domain_row(d, r))

        def run():
            try:
                synthetic = {
                    "iocs":        {"suspicious_ips": ips, "suspicious_domains": domains},
                    "top_talkers": {"by_total_bytes": [{"ip": ip} for ip in ips]},
                    "tls":         {"sni_list": domains},
                    "dns":         {"top_domains": {d: 1 for d in domains}, "dga_suspects": []},
                    "anomalies":   [],
                }
                enricher = ThreatIntelEnricher()
                enricher.set_progress_callback(self._on_progress)

                if not self._use_vt_var.get():
                    enricher.vt_key = ""
                if not self._use_abuse_var.get():
                    enricher.abuse_key = ""
                try:
                    os.environ["NEATLABS_WHOIS_AGE_DAYS"] = self._whois_days_var.get()
                except Exception:
                    pass

                results = enricher.enrich(
                    synthetic,
                    on_ip_done=on_ip_done,
                    on_domain_done=on_domain_done,
                    stop_event=self._stop_event,
                )
                self._enrichment_results = results
                self.root.after(0, lambda: self._finalize_results(results))

            except Exception as e:
                err = str(e)
                self.root.after(0, lambda m=err:
                    messagebox.showerror("Enrichment Error", m))
                self.root.after(0, lambda:
                    self._set_status("Enrichment failed", C["red"]))
            finally:
                self._running = False
                self.root.after(0, lambda: self._progress.stop())

        threading.Thread(target=run, daemon=True).start()

    def _on_progress(self, current, total, message):
        self.root.after(0, lambda: self._set_status(
            f"[{current}/{total}] {message}", C["cyan"]))

    def _stop_enrichment(self):
        if not self._running:
            return
        self._stop_event.set()
        self._set_status("Stop requested — finishing in-flight requests...", C["yellow"])
        # Finalize with partial results once the thread winds down
        partial = self._partial_enrichment
        if partial.get("ip_enrichment") or partial.get("domain_enrichment"):
            self._enrichment_results = partial
            self._finalize_results(partial, stopped=True)
        else:
            self._set_status("Stopped — no results collected yet", C["yellow"])

    # ─────────────────────────────────────────────────────────────────────────
    # POPULATE RESULTS
    # ─────────────────────────────────────────────────────────────────────────

    def _finalize_results(self, results: dict, stopped: bool = False):
        """Rebuild summary metrics, update status bar, switch to results tab."""
        ip_data  = results.get("ip_enrichment", {})
        dom_data = results.get("domain_enrichment", {})

        if not results.get("summary"):
            high_risk = [d for d in ip_data.values()
                         if d.get("combined_verdict") in ("MALICIOUS", "LIKELY_MALICIOUS", "HIGH_RISK")]
            new_doms  = [d for d in dom_data.values()
                         if (d.get("whois") or {}).get("is_new_domain")]
            mal_doms  = [d for d in dom_data.values()
                         if d.get("combined_verdict") in ("MALICIOUS", "LIKELY_MALICIOUS")]
            results["summary"] = {
                "total_indicators":       len(ip_data) + len(dom_data),
                "high_risk_ip_count":     len(high_risk),
                "new_domain_count":       len(new_doms),
                "malicious_domain_count": len(mal_doms),
                "overall_risk":           "HIGH" if high_risk or mal_doms
                                          else ("MEDIUM" if new_doms else "LOW"),
            }
            if not results.get("high_risk_ips"):
                results["high_risk_ips"] = [
                    {"ip": d["ip"], "verdict": d["combined_verdict"],
                     "vt_ratio":    (d.get("virustotal") or {}).get("detection_ratio", ""),
                     "abuse_score": (d.get("abuseipdb")  or {}).get("abuse_score", ""),
                    } for d in high_risk]
            if not results.get("new_domains"):
                results["new_domains"] = [
                    {"domain":    k,
                     "created":   (v.get("whois") or {}).get("creation_date", "unknown"),
                     "age_days":  (v.get("whois") or {}).get("domain_age_days", "unknown"),
                     "registrar": (v.get("whois") or {}).get("registrar", "unknown"),
                     "vt_verdict":(v.get("virustotal") or {}).get("verdict", ""),
                    } for k, v in dom_data.items()
                    if (v.get("whois") or {}).get("is_new_domain")]

        self._populate_summary(results)
        self._update_new_domains_panel(results)

        summary    = results.get("summary", {})
        risk       = summary.get("overall_risk", "?")
        risk_color = {"HIGH": C["red"], "MEDIUM": C["yellow"], "LOW": C["green"]}.get(risk, C["fg"])
        prefix     = "Stopped — partial results" if stopped else "Enrichment complete"

        self._set_status(
            f"{prefix} — Risk: {risk}  |  "
            f"IPs: {len(ip_data)}  |  "
            f"High-risk: {summary.get('high_risk_ip_count', 0)}  |  "
            f"New domains: {summary.get('new_domain_count', 0)}  |  "
            f"Malicious: {summary.get('malicious_domain_count', 0)}",
            risk_color)
        self._bottom_right.configure(
            text=f"{'PARTIAL — ' if stopped else ''}Risk: {risk}", fg=risk_color)

        target_tab = "IP Results" if ip_data else "Summary"
        for i in range(self._nb.index("end")):
            if target_tab in self._nb.tab(i, "text"):
                self._nb.select(i)
                break

    def _populate_summary(self, results: dict):
        self._summary_text.delete("1.0", "end")
        meta    = results.get("meta", {})
        summary = results.get("summary", {})
        risk    = summary.get("overall_risk", "?")
        risk_chars = {"HIGH": "⚠⚠⚠", "MEDIUM": "⚠⚠ ", "LOW": "✓  "}.get(risk, "   ")

        out = f"""
    ╔═══════════════════════════════════════════════════════════════════════╗
    ║  ENRICHMENT COMPLETE  {risk_chars}  OVERALL RISK: {risk:<10}           ║
    ╚═══════════════════════════════════════════════════════════════════════╝

    Completed:       {meta.get('timestamp', '')}
    Services used:   {', '.join(k for k, v in meta.get('services_used', {}).items() if v) or 'WHOIS only'}
    IPs checked:     {meta.get('ips_checked', 0)}
    Domains checked: {meta.get('domains_checked', 0)}
    New domain threshold: {meta.get('whois_new_domain_threshold_days', 60)} days

    ─────────────────────────────────────────────────────────────────────────
     FINDINGS
    ─────────────────────────────────────────────────────────────────────────

    High-risk IPs:        {summary.get('high_risk_ip_count', 0)}
    New domains:          {summary.get('new_domain_count', 0)}
    Malicious domains:    {summary.get('malicious_domain_count', 0)}
    Total IOCs enriched:  {summary.get('total_indicators', 0)}

"""
        for entry in results.get("high_risk_ips", []):
            out += f"    ⚠  {entry['ip']:<18}  Verdict: {entry['verdict']:<20}"
            if entry.get("vt_ratio"):    out += f"  VT: {entry['vt_ratio']}"
            if entry.get("abuse_score"): out += f"  Abuse: {entry['abuse_score']}%"
            out += "\n"

        new_doms = results.get("new_domains", [])
        if new_doms:
            out += "\n    ─────────────────────────────────────────────────────────────────────────\n"
            out += "     NEWLY REGISTERED DOMAINS\n"
            out += "    ─────────────────────────────────────────────────────────────────────────\n\n"
            for entry in new_doms:
                out += f"    🕐  {entry['domain']:<35}  Age: {entry.get('age_days','?')} days"
                if entry.get("created"):    out += f"  Created: {entry['created']}"
                if entry.get("vt_verdict"): out += f"  VT: {entry['vt_verdict']}"
                out += "\n"

        mal_doms = results.get("malicious_domains", [])
        if mal_doms:
            out += "\n    ─────────────────────────────────────────────────────────────────────────\n"
            out += "     MALICIOUS DOMAINS\n"
            out += "    ─────────────────────────────────────────────────────────────────────────\n\n"
            for entry in mal_doms:
                out += f"    🔴  {entry['domain']:<35}  Verdict: {entry['verdict']}"
                if entry.get("vt_ratio"): out += f"  VT: {entry['vt_ratio']}"
                out += "\n"

        self._summary_text.insert("1.0", out)

    def _update_new_domains_panel(self, results: dict):
        new_doms = results.get("new_domains", [])
        if not new_doms:
            self._new_dom_text.configure(text="None detected", fg=C["fg_muted"])
            return
        lines = []
        for d in new_doms[:8]:
            line = f"  {d['domain']:<40}  {d.get('age_days','?')} days old"
            if d.get("created"): line += f"  (created {d['created']})"
            lines.append(line)
        self._new_dom_text.configure(text="\n".join(lines), fg=C["yellow"])

    def _insert_ip_row(self, ip: str, data: dict):
        try:
            self._ip_tree.delete(ip)
        except Exception:
            pass

        vt     = data.get("virustotal") or {}
        abuse  = data.get("abuseipdb")  or {}
        verdict = data.get("combined_verdict", "UNCHECKED")
        tag     = verdict if verdict in ("MALICIOUS", "LIKELY_MALICIOUS", "HIGH_RISK",
                                          "SUSPICIOUS", "CLEAN") else (
            "even" if self._ip_row_idx[0] % 2 == 0 else "odd")

        vt_ratio    = vt.get("detection_ratio", "—") if vt.get("detection_ratio") else "—"
        vt_country  = vt.get("country", "—") if vt else "—"
        asn         = f"{vt.get('asn','')} {vt.get('as_owner','')[:30]}".strip() if vt else "—"
        abuse_score = f"{abuse.get('abuse_score','—')}%" \
                      if abuse and abuse.get("abuse_score") is not None else "—"
        abuse_rpts  = str(abuse.get("total_reports", "—")) if abuse else "—"
        isp         = abuse.get("isp", "—") if abuse else "—"
        tor         = "✓" if abuse and abuse.get("is_tor") else ""

        self._ip_tree.insert("", "end", iid=ip, values=(
            ip, verdict, vt_ratio, vt_country, asn[:40],
            abuse_score, abuse_rpts, isp[:40], tor
        ), tags=(tag,))
        self._ip_row_idx[0] += 1

        total     = len(self._ip_tree.get_children())
        high_risk = sum(1 for iid in self._ip_tree.get_children()
                        if self._ip_tree.item(iid)["values"][1]
                        in ("MALICIOUS", "LIKELY_MALICIOUS", "HIGH_RISK"))
        self._ip_stats_var.set(f"Total: {total}  |  High-risk: {high_risk}  |  Live updating...")

    def _insert_domain_row(self, domain: str, data: dict):
        try:
            self._dom_tree.delete(domain)
        except Exception:
            pass

        vt    = data.get("virustotal") or {}
        whois = data.get("whois")      or {}
        verdict = data.get("combined_verdict", "—")
        tag     = verdict if verdict in ("MALICIOUS", "LIKELY_MALICIOUS", "NEW_DOMAIN",
                                          "SUSPICIOUS", "CLEAN") else (
            "even" if self._dom_row_idx[0] % 2 == 0 else "odd")

        age      = str(whois.get("domain_age_days", "—")) \
                   if whois.get("domain_age_days") is not None else "—"
        created   = whois.get("creation_date", "—")
        registrar = (whois.get("registrar") or "—")[:40]
        vt_ratio  = vt.get("detection_ratio", "—") if vt.get("detection_ratio") else "—"
        cats      = ", ".join(vt.get("categories", [])[:2]) if vt else "—"
        expiry    = whois.get("expiry_date", "—")

        self._dom_tree.insert("", "end", iid=domain, values=(
            domain, verdict, age, created, registrar, vt_ratio, cats, expiry
        ), tags=(tag,))
        self._dom_row_idx[0] += 1

        total  = len(self._dom_tree.get_children())
        new_ct = sum(1 for iid in self._dom_tree.get_children()
                     if self._dom_tree.item(iid)["values"][1] == "NEW_DOMAIN")
        self._dom_stats_var.set(f"Total: {total}  |  New domains: {new_ct}  |  Live updating...")

    # ─────────────────────────────────────────────────────────────────────────
    # DETAIL VIEWS
    # ─────────────────────────────────────────────────────────────────────────

    def _show_ip_detail(self, event):
        sel = self._ip_tree.selection()
        if not sel:
            return
        ip = sel[0]
        ip_data = self._enrichment_results.get("ip_enrichment", {}).get(ip)
        if not ip_data:
            return

        win = self._make_detail_window(f"IP Detail — {ip}")
        txt = self._make_detail_text(win)

        vt    = ip_data.get("virustotal") or {}
        abuse = ip_data.get("abuseipdb")  or {}
        verdict = ip_data.get("combined_verdict", "—")

        out  = f"  IP Address:  {ip}\n"
        out += f"  Verdict:     {verdict}\n\n"

        if vt and not vt.get("error"):
            out += "  ── VirusTotal ──────────────────────────────────────────\n"
            out += f"  Detections:    {vt.get('detection_ratio','—')}  ({vt.get('total_engines','—')} engines)\n"
            out += f"  Country:       {vt.get('country','—')}\n"
            out += f"  ASN:           {vt.get('asn','—')}  {vt.get('as_owner','')}\n"
            out += f"  Reputation:    {vt.get('reputation','—')}\n"
            if vt.get("categories"):
                out += f"  Categories:    {', '.join(vt['categories'])}\n"
            out += f"  Link:          {vt.get('vt_link','')}\n\n"
        elif vt.get("error"):
            out += f"  VirusTotal:   Error — {vt['error']}\n\n"
        else:
            out += "  VirusTotal:   Not configured (add key in Config tab)\n\n"

        if abuse and not abuse.get("error"):
            out += "  ── AbuseIPDB ────────────────────────────────────────────\n"
            out += f"  Abuse Score:   {abuse.get('abuse_score','—')}%\n"
            out += f"  Total Reports: {abuse.get('total_reports','—')} from {abuse.get('distinct_users','—')} users\n"
            out += f"  Country:       {abuse.get('country','—')}\n"
            out += f"  ISP:           {abuse.get('isp','—')}\n"
            out += f"  Domain:        {abuse.get('domain','—')}\n"
            out += f"  Tor Node:      {'Yes ⚠' if abuse.get('is_tor') else 'No'}\n"
            out += f"  Last Reported: {abuse.get('last_reported','—')}\n"
            out += f"  Link:          {abuse.get('abuseipdb_link','')}\n"
        elif abuse.get("error"):
            out += f"  AbuseIPDB:    Error — {abuse['error']}\n"
        else:
            out += "  AbuseIPDB:    Not configured (add key in Config tab)\n"

        txt.insert("1.0", out)

    def _show_domain_detail(self, event):
        sel = self._dom_tree.selection()
        if not sel:
            return
        domain = sel[0]
        dom_data = self._enrichment_results.get("domain_enrichment", {}).get(domain)
        if not dom_data:
            return

        win = self._make_detail_window(f"Domain Detail — {domain}")
        txt = self._make_detail_text(win)

        vt    = dom_data.get("virustotal") or {}
        whois = dom_data.get("whois")      or {}
        verdict = dom_data.get("combined_verdict", "—")

        out  = f"  Domain:    {domain}\n"
        out += f"  Verdict:   {verdict}\n\n"
        out += "  ── WHOIS ───────────────────────────────────────────────\n"
        if whois.get("error") and not whois.get("creation_date"):
            out += f"  Error:         {whois['error']}\n"
        else:
            out += f"  Registrable:   {whois.get('registrable','—')}\n"
            out += f"  Created:       {whois.get('creation_date','—')}\n"
            out += f"  Expires:       {whois.get('expiry_date','—')}\n"
            out += f"  Age:           {whois.get('domain_age_days','—')} days\n"
            out += f"  Registrar:     {whois.get('registrar','—')}\n"
            out += f"  New domain:    {'YES ⚠' if whois.get('is_new_domain') else 'No'}\n"
            out += f"  Threshold:     {whois.get('new_domain_threshold_days','—')} days\n"
            out += f"  WHOIS server:  {whois.get('raw_server','—')}\n"
            if whois.get("error"):
                out += f"  Note:          {whois['error']}\n"
        out += "\n"

        if vt and not vt.get("error"):
            out += "  ── VirusTotal ──────────────────────────────────────────\n"
            out += f"  Detections:    {vt.get('detection_ratio','—')}  ({vt.get('total_engines','—')} engines)\n"
            out += f"  Reputation:    {vt.get('reputation','—')}\n"
            out += f"  Registrar:     {vt.get('registrar','—')}\n"
            if vt.get("categories"):
                out += f"  Categories:    {', '.join(vt['categories'])}\n"
            out += f"  Link:          {vt.get('vt_link','')}\n"
        elif vt.get("error"):
            out += f"  VirusTotal:   Error — {vt['error']}\n"
        else:
            out += "  VirusTotal:   Not configured (add key in Config tab)\n"

        txt.insert("1.0", out)

        self._whois_text.delete("1.0", "end")
        self._whois_text.insert("1.0", self._format_whois_detail(domain, whois))
        for i in range(self._nb.index("end")):
            if "WHOIS" in self._nb.tab(i, "text"):
                self._nb.select(i)
                break

    def _format_whois_detail(self, domain: str, whois: dict) -> str:
        out = f"  WHOIS — {domain}\n  {'─' * 60}\n\n"
        if not whois:
            return out + "  No WHOIS data available.\n"
        fields = [
            ("Registrable domain",    "registrable"),
            ("WHOIS server",          "raw_server"),
            ("Creation date",         "creation_date"),
            ("Expiry date",           "expiry_date"),
            ("Domain age",            "domain_age_days"),
            ("Registrar",             "registrar"),
            ("Is new domain",         "is_new_domain"),
            ("New domain threshold",  "new_domain_threshold_days"),
            ("Verdict",               "verdict"),
            ("Error",                 "error"),
        ]
        for label, key in fields:
            val = whois.get(key)
            if val is not None and val != "":
                if key == "domain_age_days":   val = f"{val} days"
                elif key == "is_new_domain":   val = "YES ⚠  — newly registered domain" if val else "No"
                out += f"  {label:<28}  {val}\n"
        return out

    def _quick_whois_lookup(self):
        domain = self._whois_lookup_var.get().strip().lower().rstrip(".")
        if not domain:
            return
        self._whois_status_var.set(f"Looking up {domain}...")
        self.root.update()

        def run():
            result = whois_lookup(domain)
            self.root.after(0, lambda: self._display_whois_result(domain, result))

        threading.Thread(target=run, daemon=True).start()

    def _display_whois_result(self, domain: str, result: dict):
        self._whois_status_var.set(
            f"Done — {result.get('verdict', '—')}"
            + (f"  Age: {result.get('domain_age_days','?')} days" if result.get("domain_age_days") else ""))
        self._whois_text.delete("1.0", "end")
        self._whois_text.insert("1.0", self._format_whois_detail(domain, result))

    # ─────────────────────────────────────────────────────────────────────────
    # CONFIG ACTIONS
    # ─────────────────────────────────────────────────────────────────────────

    def _save_config(self):
        cfg = {}
        if os.path.isfile(_CONFIG_FILE):
            try:
                with open(_CONFIG_FILE) as f:
                    cfg = json.load(f)
            except Exception:
                pass

        vt_key    = self._vt_key_var.get().strip()
        abuse_key = self._abuse_key_var.get().strip()
        days      = self._cfg_whois_days_var.get().strip()

        if vt_key:    cfg["virustotal_api_key"] = vt_key
        if abuse_key: cfg["abuseipdb_api_key"]  = abuse_key
        try:
            cfg["whois_new_domain_days"] = int(days)
        except ValueError:
            pass

        try:
            with open(_CONFIG_FILE, "w") as f:
                json.dump(cfg, f, indent=4)

            # Propagate to environment and invalidate config cache
            if vt_key:    os.environ["NEATLABS_VT_KEY"] = vt_key
            if abuse_key: os.environ["NEATLABS_ABUSEIPDB_KEY"] = abuse_key
            _invalidate_config_cache()

            self._config_msg.configure(text=f"✓  Saved to {_CONFIG_FILE}", fg=C["green"])
            self._refresh_service_status()
            self._set_status("Config saved — services updated", C["green"])
        except Exception as e:
            self._config_msg.configure(text=f"Error: {e}", fg=C["red"])

    def _test_vt_key(self):
        key = self._vt_key_var.get().strip()
        if not key:
            messagebox.showinfo("No Key", "Enter a VirusTotal API key first.")
            return
        self._vt_status.configure(text="Testing...", fg=C["yellow"])
        self.root.update()

        def run():
            result = _vt_lookup_ip("8.8.8.8", key)
            if result.get("error"):
                msg, color = f"✗  Error: {result['error']}", C["red"]
            else:
                msg  = f"✓  Key valid — Google DNS: {result.get('detection_ratio','—')} detections"
                color = C["green"]
            self.root.after(0, lambda: self._vt_status.configure(text=msg, fg=color))

        threading.Thread(target=run, daemon=True).start()

    def _test_abuse_key(self):
        key = self._abuse_key_var.get().strip()
        if not key:
            messagebox.showinfo("No Key", "Enter an AbuseIPDB API key first.")
            return
        self._abuse_status.configure(text="Testing...", fg=C["yellow"])
        self.root.update()

        def run():
            result = _abuseipdb_lookup("8.8.8.8", key)
            if result.get("error"):
                msg, color = f"✗  Error: {result['error']}", C["red"]
            else:
                msg  = f"✓  Key valid — Google DNS abuse score: {result.get('abuse_score','—')}%"
                color = C["green"]
            self.root.after(0, lambda: self._abuse_status.configure(text=msg, fg=color))

        threading.Thread(target=run, daemon=True).start()

    def _show_config(self):
        for i in range(self._nb.index("end")):
            if "Config" in self._nb.tab(i, "text"):
                self._nb.select(i)
                break

    # ─────────────────────────────────────────────────────────────────────────
    # EXPORTS
    # ─────────────────────────────────────────────────────────────────────────

    def _export_html(self):
        if not self._enrichment_results:
            messagebox.showinfo("No Results", "Run enrichment first.")
            return
        fp = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML", "*.html")],
            initialfile=f"threat_intel_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
        if not fp:
            return

        html_section = render_enrichment_html(self._enrichment_results)
        full_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{BRAND} — Threat Intel Report</title>
<style>
:root {{
    --bg:#0a0e17;--surface:#111827;--surface2:#1e293b;--border:#334155;
    --text:#e2e8f0;--text2:#94a3b8;--accent:#3b82f6;--accent2:#8b5cf6;
    --green:#22c55e;--yellow:#eab308;--orange:#f97316;--red:#ef4444;
    --cyan:#06b6d4;
}}
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:var(--bg);color:var(--text);font-family:-apple-system,'Segoe UI',Roboto,monospace;line-height:1.6;padding:20px}}
.container{{max-width:1400px;margin:0 auto}}
.header{{text-align:center;padding:40px 20px;border-bottom:1px solid var(--border);margin-bottom:30px}}
.brand{{font-size:14px;letter-spacing:6px;color:var(--accent2);text-transform:uppercase;margin-bottom:8px}}
.header h1{{font-size:28px;font-weight:700;color:var(--text)}}
.section{{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:24px;margin:20px 0}}
.section h2{{font-size:18px;color:var(--accent);margin-bottom:16px;display:flex;align-items:center;gap:8px}}
.section h2::before{{content:"";display:inline-block;width:4px;height:20px;background:var(--accent);border-radius:2px}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th{{background:var(--surface2);color:var(--accent);padding:10px 12px;text-align:left;font-weight:600;border-bottom:2px solid var(--accent)}}
td{{padding:8px 12px;border-bottom:1px solid var(--border);color:var(--text)}}
tr:hover td{{background:rgba(59,130,246,0.05)}}
.tag{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;margin:1px;background:var(--surface2);color:var(--text2)}}
.footer{{text-align:center;padding:30px;color:var(--text2);font-size:12px;border-top:1px solid var(--border);margin-top:40px}}
</style>
</head>
<body>
<div class="container">
<div class="header">
    <div class="brand">{BRAND}</div>
    <h1>Threat Intelligence Enrichment Report</h1>
    <div style="color:var(--text2);font-size:14px">{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</div>
</div>
{html_section}
<div class="footer">Generated by {BRAND} {TOOL_NAME} v{VERSION}</div>
</div>
</body>
</html>"""

        with open(fp, "w", encoding="utf-8") as f:
            f.write(full_html)
        messagebox.showinfo("Saved", f"HTML report saved to:\n{fp}")
        import webbrowser
        webbrowser.open(f"file://{os.path.abspath(fp)}")

    def _export_json(self):
        if not self._enrichment_results:
            messagebox.showinfo("No Results", "Run enrichment first.")
            return
        fp = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON", "*.json")],
            initialfile=f"threat_intel_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        if fp:
            with open(fp, "w") as f:
                json.dump(self._enrichment_results, f, indent=2, default=str)
            messagebox.showinfo("Saved", f"JSON exported to:\n{fp}")

    def _clear_all(self):
        if messagebox.askyesno("Clear All", "Clear all inputs and results?"):
            self._ip_input.delete("1.0", "end")
            self._dom_input.delete("1.0", "end")
            self._ip_tree.delete(*self._ip_tree.get_children())
            self._dom_tree.delete(*self._dom_tree.get_children())
            self._whois_text.delete("1.0", "end")
            self._enrichment_results = {}
            self._summary_text.delete("1.0", "end")
            self._summary_text.insert("1.0", self._summary_placeholder())
            self._new_dom_text.configure(text="None detected", fg=C["fg_muted"])
            self._update_counts()
            self._set_status("Cleared", C["fg_muted"])
            self._bottom_right.configure(text="")
            if hasattr(self, "_analyzer_results"):
                del self._analyzer_results
            self._loaded_file_var.set("No results file loaded — manual input only")

    # ─────────────────────────────────────────────────────────────────────────
    # HELPERS
    # ─────────────────────────────────────────────────────────────────────────

    def _refresh_service_status(self):
        avail = enrichment_available()
        colors = {
            "VirusTotal": C["green"] if avail.get("virustotal") else C["fg_muted"],
            "AbuseIPDB":  C["green"] if avail.get("abuseipdb")  else C["fg_muted"],
            "WHOIS":      C["green"],
        }
        for svc, dot in self._svc_labels.items():
            dot.configure(fg=colors.get(svc, C["fg_muted"]))

        self._use_vt_var.set(bool(get_vt_key()))
        self._use_abuse_var.set(bool(get_abuseipdb_key()))

        if hasattr(self, "_vt_status"):
            vk = get_vt_key()
            self._vt_status.configure(
                text="✓  Key configured" if vk else "✗  Not configured — free key at virustotal.com",
                fg=C["green"] if vk else C["fg_muted"])
        if hasattr(self, "_abuse_status"):
            ak = get_abuseipdb_key()
            self._abuse_status.configure(
                text="✓  Key configured" if ak else "✗  Not configured — free key at abuseipdb.com",
                fg=C["green"] if ak else C["fg_muted"])

    def _set_status(self, text: str, color=None):
        self._status_var.set(text)

    def _make_detail_window(self, title: str) -> tk.Toplevel:
        win = tk.Toplevel(self.root)
        win.title(f"{BRAND} — {title}")
        win.geometry("680x480")
        win.configure(bg=C["bg"])
        hdr = tk.Frame(win, bg=C["surface"], padx=12, pady=8)
        hdr.pack(fill="x")
        tk.Label(hdr, text=title, bg=C["surface"],
                 fg=C["purple"], font=FONT_HEADER).pack(side="left")
        return win

    def _make_detail_text(self, parent: tk.Toplevel) -> scrolledtext.ScrolledText:
        t = scrolledtext.ScrolledText(
            parent, bg=C["text_bg"], fg=C["text_fg"],
            font=FONT_MONO, wrap="word",
            insertbackground=C["accent"],
            selectbackground=C["row_select"],
            relief="flat", borderwidth=0, padx=12, pady=10)
        t.pack(fill="both", expand=True, padx=8, pady=(4, 8))
        return t


# ═════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def main():
    preload = sys.argv[1] if len(sys.argv) > 1 else None
    try:
        root = tk.Tk()
    except Exception as e:
        import traceback
        traceback.print_exc()
        sys.exit(1)

    try:
        app = ThreatIntelGUI(root, preload_file=preload)
        root.mainloop()
    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        print(tb)
        _write_crash_log(tb)
        try:
            messagebox.showerror("Fatal Error",
                f"The application encountered a startup error:\n\n{e}\n\n"
                "See neatlabs_crash.log for details.")
        except Exception:
            pass

if __name__ == "__main__":
    main()
