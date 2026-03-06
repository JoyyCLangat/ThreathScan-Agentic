"""
ThreatScan Recon Tools
======================
Real integrations for Shadow agent:
  - HTTP probing (httpx or requests)
  - Certificate Transparency log queries (crt.sh)
  - Shodan asset intelligence
  - VirusTotal domain reputation
  - NVD/OSV dependency vulnerability lookups
  - CISA KEV / GreyNoise threat intel

All functions check settings flags and fall back to simulation
when keys are absent or real probing is disabled.
"""

import asyncio
import json
import logging
import random
import time
from typing import Optional
from urllib.parse import urlparse

from ..config import settings

logger = logging.getLogger("threatscan.recon")

# ── Optional HTTP clients ─────────────────────────────────────────────────────
try:
    import httpx as _httpx
    _HTTPX_AVAILABLE = True
except ImportError:
    _HTTPX_AVAILABLE = False

try:
    import requests as _requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False


# ── HTTP Probe ────────────────────────────────────────────────────────────────

async def http_probe(url: str, method: str = "GET", timeout: Optional[int] = None) -> dict:
    """
    Probe a URL and return response metadata.
    Falls back to simulation if real probing is disabled.
    """
    timeout = timeout or settings.http_probe_timeout

    if not settings.enable_real_http_probing:
        return _simulate_probe(url)

    headers = {"User-Agent": settings.http_user_agent}

    try:
        if _HTTPX_AVAILABLE:
            async with _httpx.AsyncClient(
                timeout=timeout, follow_redirects=True,
                verify=False, headers=headers
            ) as client:
                start = time.time()
                r = await client.request(method, url)
                latency = (time.time() - start) * 1000
                return {
                    "url": url, "status": r.status_code,
                    "latency_ms": round(latency, 1),
                    "headers": dict(r.headers),
                    "content_length": len(r.content),
                    "redirect_url": str(r.url) if str(r.url) != url else None,
                    "real": True,
                }
        elif _REQUESTS_AVAILABLE:
            loop = asyncio.get_event_loop()
            def _sync():
                start = time.time()
                r = _requests.request(
                    method, url, timeout=timeout,
                    headers=headers, verify=False,
                    allow_redirects=True
                )
                latency = (time.time() - start) * 1000
                return {
                    "url": url, "status": r.status_code,
                    "latency_ms": round(latency, 1),
                    "headers": dict(r.headers),
                    "content_length": len(r.content),
                    "redirect_url": r.url if r.url != url else None,
                    "real": True,
                }
            return await loop.run_in_executor(None, _sync)
        else:
            logger.warning("No HTTP client available — falling back to simulation")
            return _simulate_probe(url)

    except Exception as e:
        logger.debug(f"Probe failed for {url}: {e}")
        return {"url": url, "status": 0, "error": str(e), "real": True}


def _simulate_probe(url: str) -> dict:
    """Simulate an HTTP probe response for testing without network access."""
    path = urlparse(url).path or "/"
    auth_paths = {"/admin", "/api/v1/users", "/api/internal", "/settings", "/dashboard"}
    active_paths = {"/api", "/health", "/status", "/login", "/docs", "/graphql", "/.env", "/robots.txt"}

    for ap in auth_paths:
        if path.startswith(ap):
            status = random.choice([401, 403])
            return {"url": url, "status": status, "latency_ms": random.gauss(150, 40), "real": False}

    for ap in active_paths:
        if path.startswith(ap):
            return {"url": url, "status": 200, "latency_ms": random.gauss(120, 30), "real": False}

    status = random.choices([404, 200, 301, 403], weights=[0.70, 0.15, 0.10, 0.05])[0]
    return {"url": url, "status": status, "latency_ms": random.gauss(150, 50), "real": False}


# ── Certificate Transparency ──────────────────────────────────────────────────

async def enumerate_subdomains_ct(domain: str) -> list[str]:
    """
    Query crt.sh for subdomains via Certificate Transparency logs.
    Falls back to simulation when network is unavailable.
    """
    if not settings.enable_real_http_probing:
        return _simulate_subdomains(domain)

    url = f"{settings.ct_log_url}/?q=%.{domain}&output=json"
    try:
        if _HTTPX_AVAILABLE:
            async with _httpx.AsyncClient(timeout=15) as client:
                r = await client.get(url)
                data = r.json()
        elif _REQUESTS_AVAILABLE:
            loop = asyncio.get_event_loop()
            data = await loop.run_in_executor(
                None, lambda: _requests.get(url, timeout=15).json()
            )
        else:
            return _simulate_subdomains(domain)

        subs = set()
        for entry in data:
            name = entry.get("name_value", "")
            for sub in name.split("\n"):
                sub = sub.strip().lstrip("*.")
                if sub.endswith(domain) and sub != domain:
                    subs.add(sub)
        logger.info(f"CT logs found {len(subs)} subdomains for {domain}")
        return list(subs)[:50]

    except Exception as e:
        logger.warning(f"CT log query failed for {domain}: {e} — using simulation")
        return _simulate_subdomains(domain)


def _simulate_subdomains(domain: str) -> list[str]:
    prefixes = ["api", "staging", "dev", "admin", "mail", "vpn", "cdn", "ws", "app", "beta"]
    return [f"{p}.{domain}" for p in random.sample(prefixes, min(5, len(prefixes)))]


# ── Shodan ────────────────────────────────────────────────────────────────────

async def shodan_host_lookup(ip: str) -> dict:
    """Query Shodan for host intelligence."""
    if not settings.has_shodan:
        logger.debug("Shodan not configured — skipping")
        return {"ip": ip, "simulated": True, "ports": [80, 443, 8080], "tags": []}

    url = f"https://api.shodan.io/shodan/host/{ip}?key={settings.shodan_api_key}"
    try:
        if _HTTPX_AVAILABLE:
            async with _httpx.AsyncClient(timeout=15) as client:
                r = await client.get(url)
                return r.json()
        elif _REQUESTS_AVAILABLE:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(
                None, lambda: _requests.get(url, timeout=15).json()
            )
    except Exception as e:
        logger.warning(f"Shodan lookup failed for {ip}: {e}")
        return {"ip": ip, "error": str(e)}


async def shodan_domain_search(domain: str) -> dict:
    """Query Shodan DNS for domain info."""
    if not settings.has_shodan:
        return {"domain": domain, "simulated": True}

    url = f"https://api.shodan.io/dns/domain/{domain}?key={settings.shodan_api_key}"
    try:
        if _HTTPX_AVAILABLE:
            async with _httpx.AsyncClient(timeout=15) as client:
                r = await client.get(url)
                return r.json()
        elif _REQUESTS_AVAILABLE:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(
                None, lambda: _requests.get(url, timeout=15).json()
            )
    except Exception as e:
        logger.warning(f"Shodan domain search failed: {e}")
        return {"domain": domain, "error": str(e)}


# ── VirusTotal ────────────────────────────────────────────────────────────────

async def virustotal_url_scan(url_or_domain: str) -> dict:
    """Check URL/domain reputation via VirusTotal."""
    if not settings.has_virustotal:
        return {"item": url_or_domain, "simulated": True, "malicious": 0, "suspicious": 0}

    import base64
    url_id = base64.urlsafe_b64encode(url_or_domain.encode()).decode().rstrip("=")
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": settings.virustotal_api_key}

    try:
        if _HTTPX_AVAILABLE:
            async with _httpx.AsyncClient(timeout=15) as client:
                r = await client.get(api_url, headers=headers)
                data = r.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return {
                    "item": url_or_domain,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "reputation": data.get("data", {}).get("attributes", {}).get("reputation", 0),
                }
        elif _REQUESTS_AVAILABLE:
            loop = asyncio.get_event_loop()
            def _sync():
                r = _requests.get(api_url, headers=headers, timeout=15)
                data = r.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return {
                    "item": url_or_domain,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                }
            return await loop.run_in_executor(None, _sync)
    except Exception as e:
        logger.warning(f"VirusTotal scan failed: {e}")
        return {"item": url_or_domain, "error": str(e)}


# ── NVD Dependency Lookup ─────────────────────────────────────────────────────

async def nvd_lookup_package(package_name: str, version: str = "") -> list[dict]:
    """
    Query NVD for CVEs affecting a package.
    Falls back to a local known-vuln dict without network.
    """
    # Always try local lookup first (fast, no rate limits)
    local = _local_vuln_lookup(package_name, version)

    if not settings.enable_threat_intel:
        return local

    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"keywordSearch": package_name, "resultsPerPage": 5}
    headers = {}
    if settings.has_nvd_key:
        headers["apiKey"] = settings.nvd_api_key

    try:
        if _HTTPX_AVAILABLE:
            async with _httpx.AsyncClient(timeout=15) as client:
                r = await client.get(base_url, params=params, headers=headers)
                data = r.json()
                cves = []
                for item in data.get("vulnerabilities", []):
                    cve = item.get("cve", {})
                    metrics = cve.get("metrics", {})
                    cvss_v3 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {}) if metrics.get("cvssMetricV31") else {}
                    cves.append({
                        "cve_id": cve.get("id"),
                        "description": cve.get("descriptions", [{}])[0].get("value", ""),
                        "cvss_score": cvss_v3.get("baseScore", 0),
                        "severity": cvss_v3.get("baseSeverity", "UNKNOWN"),
                        "published": cve.get("published", ""),
                        "source": "NVD",
                    })
                logger.info(f"NVD found {len(cves)} CVEs for {package_name}")
                return cves if cves else local
        else:
            return local
    except Exception as e:
        logger.warning(f"NVD lookup failed for {package_name}: {e}")
        return local


def _local_vuln_lookup(package: str, version: str = "") -> list[dict]:
    """Fast local CVE lookup from built-in known vulnerabilities."""
    KNOWN = {
        "log4j-core": [{"cve_id": "CVE-2021-44228", "cvss_score": 10.0, "severity": "CRITICAL", "name": "Log4Shell", "source": "local"}],
        "spring-core": [{"cve_id": "CVE-2022-22965", "cvss_score": 9.8, "severity": "CRITICAL", "name": "Spring4Shell", "source": "local"}],
        "lodash": [{"cve_id": "CVE-2020-28500", "cvss_score": 7.4, "severity": "HIGH", "name": "Prototype Pollution", "source": "local"}],
        "jsonwebtoken": [{"cve_id": "CVE-2022-23529", "cvss_score": 7.6, "severity": "HIGH", "name": "JWT Insecure Verification", "source": "local"}],
        "axios": [{"cve_id": "CVE-2023-45857", "cvss_score": 6.5, "severity": "MEDIUM", "name": "SSRF via proxy config", "source": "local"}],
        "express": [{"cve_id": "CVE-2024-29041", "cvss_score": 6.1, "severity": "MEDIUM", "name": "Open Redirect", "source": "local"}],
        "shelljs": [{"cve_id": "CVE-2022-0144", "cvss_score": 7.8, "severity": "HIGH", "name": "Improper Privilege Management", "source": "local"}],
        "minimist": [{"cve_id": "CVE-2021-44906", "cvss_score": 9.8, "severity": "CRITICAL", "name": "Prototype Pollution", "source": "local"}],
    }
    return KNOWN.get(package.lower(), [])


# ── OSV Dependency Lookup ─────────────────────────────────────────────────────

async def osv_lookup(package_name: str, version: str, ecosystem: str = "npm") -> list[dict]:
    """Query OSV.dev for vulnerabilities in a package version."""
    if not settings.enable_threat_intel:
        return _local_vuln_lookup(package_name, version)

    url = f"{settings.osv_api_url}/v1/query"
    payload = {
        "version": version,
        "package": {"name": package_name, "ecosystem": ecosystem}
    }

    try:
        if _HTTPX_AVAILABLE:
            async with _httpx.AsyncClient(timeout=10) as client:
                r = await client.post(url, json=payload)
                data = r.json()
                vulns = []
                for v in data.get("vulns", []):
                    severity = "UNKNOWN"
                    score = 0.0
                    for sev in v.get("severity", []):
                        if sev.get("type") == "CVSS_V3":
                            score = _parse_cvss_score(sev.get("score", ""))
                            severity = _cvss_to_severity(score)
                    vulns.append({
                        "cve_id": v.get("id"),
                        "description": v.get("summary", ""),
                        "cvss_score": score,
                        "severity": severity,
                        "source": "OSV",
                    })
                return vulns if vulns else _local_vuln_lookup(package_name, version)
        else:
            return _local_vuln_lookup(package_name, version)
    except Exception as e:
        logger.warning(f"OSV lookup failed for {package_name}@{version}: {e}")
        return _local_vuln_lookup(package_name, version)


def _parse_cvss_score(cvss_vector: str) -> float:
    """Extract base score from CVSS vector string."""
    try:
        parts = cvss_vector.split("/")
        for p in parts:
            if p.startswith("Base Score:") or p.startswith("BS:"):
                return float(p.split(":")[1])
    except Exception:
        pass
    return 0.0


def _cvss_to_severity(score: float) -> str:
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    if score > 0.0: return "LOW"
    return "UNKNOWN"


# ── CISA KEV ──────────────────────────────────────────────────────────────────

_kev_cache: dict = {}
_kev_loaded_at: float = 0.0
_KEV_TTL = 3600  # 1 hour


async def get_cisa_kev() -> list[dict]:
    """
    Fetch the CISA Known Exploited Vulnerabilities catalog.
    Cached for 1 hour. Falls back to a small built-in list.
    """
    global _kev_cache, _kev_loaded_at

    if _kev_cache and (time.time() - _kev_loaded_at) < _KEV_TTL:
        return _kev_cache.get("vulnerabilities", [])

    if not settings.enable_threat_intel:
        return _builtin_kev()

    try:
        if _HTTPX_AVAILABLE:
            async with _httpx.AsyncClient(timeout=20) as client:
                r = await client.get(settings.cisa_kev_url)
                data = r.json()
                _kev_cache = data
                _kev_loaded_at = time.time()
                vulns = data.get("vulnerabilities", [])
                logger.info(f"Loaded {len(vulns)} entries from CISA KEV")
                return vulns
        elif _REQUESTS_AVAILABLE:
            loop = asyncio.get_event_loop()
            def _sync():
                r = _requests.get(settings.cisa_kev_url, timeout=20)
                return r.json()
            data = await loop.run_in_executor(None, _sync)
            _kev_cache = data
            _kev_loaded_at = time.time()
            return data.get("vulnerabilities", [])
        else:
            return _builtin_kev()
    except Exception as e:
        logger.warning(f"CISA KEV fetch failed: {e} — using builtin list")
        return _builtin_kev()


def _builtin_kev() -> list[dict]:
    return [
        {"cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j2", "vulnerabilityName": "Log4Shell"},
        {"cveID": "CVE-2022-22965", "vendorProject": "VMware", "product": "Spring Framework", "vulnerabilityName": "Spring4Shell"},
        {"cveID": "CVE-2021-26855", "vendorProject": "Microsoft", "product": "Exchange Server", "vulnerabilityName": "ProxyLogon"},
        {"cveID": "CVE-2023-44487", "vendorProject": "IETF", "product": "HTTP/2", "vulnerabilityName": "Rapid Reset Attack"},
    ]


async def is_in_kev(cve_id: str) -> bool:
    """Check if a CVE is in the CISA Known Exploited Vulnerabilities list."""
    kev = await get_cisa_kev()
    return any(v.get("cveID") == cve_id for v in kev)


# ── GreyNoise ─────────────────────────────────────────────────────────────────

async def greynoise_ip_context(ip: str) -> dict:
    """Check if an IP is a known scanner/attacker via GreyNoise."""
    if not settings.has_greynoise:
        return {"ip": ip, "simulated": True, "noise": False, "riot": False}

    url = f"https://api.greynoise.io/v3/community/{ip}"
    headers = {"key": settings.greynoise_api_key}

    try:
        if _HTTPX_AVAILABLE:
            async with _httpx.AsyncClient(timeout=10) as client:
                r = await client.get(url, headers=headers)
                return r.json()
        elif _REQUESTS_AVAILABLE:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(
                None, lambda: _requests.get(url, headers=headers, timeout=10).json()
            )
    except Exception as e:
        logger.warning(f"GreyNoise lookup failed for {ip}: {e}")
        return {"ip": ip, "error": str(e)}
