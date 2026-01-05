#!/usr/bin/env python3
"""
MakassarScan - Advanced Vulnerability Assessment & Reconnaissance Toolkit

A comprehensive security assessment tool featuring:
- Multi-threaded port scanning with service detection
- CVE lookup via NVD API
- Web crawler with form/script analysis
- Subdomain enumeration via Certificate Transparency
- Technology fingerprinting
- AI-powered analysis (OpenAI, Claude, Gemini)
- Cross-platform GUI and CLI interfaces
- Export to JSON, HTML, Markdown, CSV

GitHub: https://github.com/Masriyan/Makassarscan
Author: Masriyan
License: MIT
"""

from __future__ import annotations

__version__ = "2.0.0"
__author__ = "Masriyan"
__license__ = "MIT"

import argparse
import csv
import hashlib
import io
import json
import logging
import os
import platform
import queue
import random
import re
import shutil
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import webbrowser
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import parse_qsl, parse_qs, urlencode, urljoin, urlparse, urlunparse, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed

# Cross-platform detection
PLATFORM = platform.system().lower()
IS_WINDOWS = PLATFORM == "windows"
IS_LINUX = PLATFORM == "linux"
IS_MACOS = PLATFORM == "darwin"

# Handle Tkinter import for headless environments
_GUI_AVAILABLE = True
try:
    import tkinter as tk
    from tkinter import messagebox, ttk, filedialog
    from tkinter.font import Font
except ImportError:
    _GUI_AVAILABLE = False
    tk = None  # type: ignore

try:
    import requests
except ImportError as exc:
    raise SystemExit("The 'requests' package is required to run MakassarScan.\nInstall with: pip install requests") from exc

# Optional dependencies
try:
    from PIL import Image, ImageDraw, ImageFont
    _PIL_AVAILABLE = True
except ImportError:
    _PIL_AVAILABLE = False

try:
    import dns.resolver
    _DNS_AVAILABLE = True
except ImportError:
    _DNS_AVAILABLE = False

# Requests warns when SSL verification is disabled; suppress to keep the UI clean.
requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]

DEFAULT_USER_AGENT = "MakassarScan/1.0 (+https://security-life.org/tools/makassarscan)"

TRANSLATIONS: Dict[str, Dict[str, str]] = {
    "en": {
        "app_title": "MakassarScan - Vulnerability Toolkit",
        "target_label": "Target host / URL",
        "vendor_label": "Vendor (optional)",
        "product_label": "Product or keyword",
        "keyword_label": "Keyword (vendor, product, CVE id)",
        "user_agent_label": "Custom User-Agent",
        "user_agent_placeholder": "e.g. Mozilla/5.0 (MakassarScan)",
        "level_label": "Scan depth",
        "language_label": "Language",
        "debug_label": "Debug logging",
        "debug_tooltip": "Logs verbose details to the console panel.",
        "waf_label": "WAF evasion",
        "waf_tooltip": "Rotates headers, jitter, and cache-busting tokens to dodge light WAF rules.",
        "crawl_label": "Crawl target site",
        "crawl_depth_label": "Crawl depth",
        "crawl_keywords_label": "Crawl keywords",
        "doc_ext_label": "Document extensions",
        "start_button": "Start Scan",
        "status_idle": "Status: Idle",
        "status_running": "Status: Scanning...",
        "status_done": "Status: Completed",
        "placeholder_results": "Awaiting scan results...",
        "log_tab": "Activity",
        "cve_tab": "CVE Matches",
        "port_open": "Port {port}/tcp is OPEN ({service})",
        "port_closed": "Port {port}/tcp is closed or filtered",
        "http_summary": "HTTP {status} ({url}) - Server: {server}",
        "tls_summary": "TLS: {version} | Cipher: {cipher}",
        "metadata_title": "Service metadata",
        "banner_label": "Server banner",
        "powered_by_label": "Powered by",
        "tls_subject_label": "Subject",
        "tls_issuer_label": "Issuer",
        "tls_expiry_label": "Valid until",
        "scan_intro": "Scan level: {level} | Duration: {seconds:.1f}s | Host: {host}",
        "insights_title": "Insights",
        "insights_none": "No additional insights for this target.",
        "detected_section": "Detected identifiers",
        "detected_vendor": "Vendor: {vendor}",
        "detected_product": "Product: {product}",
        "detected_runtime": "Runtime: {runtime}",
        "detected_missing": "No automatic fingerprint identified.",
        "runtime_php": "PHP {version}",
        "runtime_unknown": "Unknown runtime",
        "docs_title": "Document leads",
        "docs_entry": "{ext} -> {url} ({source})",
        "docs_none": "No candidate documents discovered.",
        "doc_source_crawler": "Crawler",
        "doc_source_duckduckgo": "DuckDuckGo",
        "doc_source_cloud": "Cloud search",
        "doc_source_linkhub": "Link hub",
        "social_section": "Social media monitors",
        "social_api_key": "API key / token",
        "social_api_secret": "Secret / session",
        "social_handle": "Handle / URL",
        "social_note": "Provide official handles + API tokens to enable social intelligence.",
        "social_status_disabled": "No social media sources selected.",
        "social_status_ready": "Social media sources configured (experimental).",
        "social_x_label": "X (Twitter)",
        "social_facebook_label": "Facebook",
        "social_instagram_label": "Instagram",
        "social_threads_label": "Threads",
        "social_telegram_label": "Telegram",
        "crawl_title": "Crawler",
        "crawl_summary": "Crawler visited {pages} pages (max depth {depth}).",
        "crawl_entry": "{url} | status {status} | title: {title} | forms {forms} | scripts {scripts}",
        "crawl_disabled": "Crawler disabled or no HTML responses for this host.",
        "crawl_error": "Crawler error: {error}",
        "ai_tab": "AI Analysis",
        "ai_label": "AI provider",
        "ai_key_label": "AI API key",
        "ai_detail_label": "AI detail",
        "ai_detail_short": "Brief",
        "ai_detail_standard": "Standard",
        "ai_detail_verbose": "Verbose",
        "ai_placeholder": "Provide an API key and provider to enable AI triage.",
        "ai_status_wait": "AI analysis in progress...",
        "ai_status_disabled": "AI analysis disabled.",
        "ai_status_missing_key": "Select a provider and add an API key to enable AI analysis.",
        "ai_error": "AI analysis failed: {error}",
        "ai_provider_none": "Disabled",
        "ai_provider_openai": "ChatGPT (OpenAI)",
        "ai_provider_claude": "Claude (Anthropic)",
        "ai_provider_gemini": "Gemini (Google)",
        "cve_title": "Top CVE matches",
        "cve_loading": "Fetching CVE data...",
        "no_cves": "No CVEs found for the supplied keyword.",
        "cve_error": "Unable to load CVE data. Check your network connection.",
        "scan_failed": "Scan failed",
        "input_error": "Enter a target host or CVE keyword before scanning.",
        "waf_enabled_status": "WAF evasion heuristics enabled.",
        "waf_disabled_status": "WAF evasion disabled.",
        "language_en": "English",
        "language_id": "Bahasa Indonesia",
        "level_basic": "Basic",
        "level_medium": "Medium",
        "level_deep": "Deep",
        "level_deeper": "Deeper",
        "insight_telnet": "Legacy Telnet service (23/tcp) is open; disable it if possible.",
        "insight_rdp": "Remote Desktop (3389/tcp) is reachable from here; ensure MFA and network ACLs.",
        "insight_https": "HTTPS port is closed while HTTP is open; consider enforcing TLS.",
        "insight_banner": "The HTTP banner discloses software details; hide version strings where possible.",
        "insight_error_rate": "The service returned HTTP errors (>399); review server logs.",
    },
    "id": {
        "app_title": "MakassarScan - Perangkat Pemindai",
        "target_label": "Host / URL target",
        "vendor_label": "Vendor (opsional)",
        "product_label": "Produk atau kata kunci",
        "keyword_label": "Kata kunci (vendor, produk, id CVE)",
        "user_agent_label": "User-Agent kustom",
        "user_agent_placeholder": "contoh: Mozilla/5.0 (MakassarScan)",
        "level_label": "Tingkat pemindaian",
        "language_label": "Bahasa",
        "debug_label": "Mode debug",
        "debug_tooltip": "Menuliskan detail tambahan ke panel konsol.",
        "waf_label": "Bypass WAF",
        "waf_tooltip": "Memutar header, jeda, dan token acak untuk melewati aturan WAF sederhana.",
        "crawl_label": "Rayapi situs target",
        "crawl_depth_label": "Kedalaman perayapan",
        "crawl_keywords_label": "Kata kunci perayapan",
        "doc_ext_label": "Ekstensi dokumen",
        "start_button": "Mulai Pindai",
        "status_idle": "Status: Siap",
        "status_running": "Status: Memindai...",
        "status_done": "Status: Selesai",
        "placeholder_results": "Menunggu hasil pemindaian...",
        "log_tab": "Aktivitas",
        "cve_tab": "Kecocokan CVE",
        "port_open": "Port {port}/tcp TERBUKA ({service})",
        "port_closed": "Port {port}/tcp tertutup atau terfilter",
        "http_summary": "HTTP {status} ({url}) - Server: {server}",
        "tls_summary": "TLS: {version} | Cipher: {cipher}",
        "metadata_title": "Metadata layanan",
        "banner_label": "Banner server",
        "powered_by_label": "Menggunakan",
        "tls_subject_label": "Subjek",
        "tls_issuer_label": "Penerbit",
        "tls_expiry_label": "Berlaku hingga",
        "scan_intro": "Level: {level} | Durasi: {seconds:.1f} dtk | Host: {host}",
        "insights_title": "Analisis",
        "insights_none": "Tidak ada wawasan tambahan untuk target ini.",
        "detected_section": "Identitas terdeteksi",
        "detected_vendor": "Vendor: {vendor}",
        "detected_product": "Produk: {product}",
        "detected_runtime": "Platform: {runtime}",
        "detected_missing": "Tidak ada sidik jari otomatis terdeteksi.",
        "runtime_php": "PHP {version}",
        "runtime_unknown": "Platform tidak diketahui",
        "docs_title": "Jejak dokumen",
        "docs_entry": "{ext} -> {url} ({source})",
        "docs_none": "Tidak ada dokumen yang ditemukan.",
        "doc_source_crawler": "Perayap",
        "doc_source_duckduckgo": "DuckDuckGo",
        "doc_source_cloud": "Penyimpanan awan",
        "doc_source_linkhub": "Link hub",
        "social_section": "Monitoring media sosial",
        "social_api_key": "API key / token",
        "social_api_secret": "Secret / sesi",
        "social_handle": "Akun / URL",
        "social_note": "Isi akun resmi dan token API untuk menyalakan intel media sosial.",
        "social_status_disabled": "Tidak ada sumber media sosial.",
        "social_status_ready": "Sumber media sosial siap (eksperimental).",
        "social_x_label": "X (Twitter)",
        "social_facebook_label": "Facebook",
        "social_instagram_label": "Instagram",
        "social_threads_label": "Threads",
        "social_telegram_label": "Telegram",
        "crawl_title": "Perayap",
        "crawl_summary": "Perayap mengunjungi {pages} halaman (kedalaman maks {depth}).",
        "crawl_entry": "{url} | status {status} | judul: {title} | form {forms} | skrip {scripts}",
        "crawl_disabled": "Perayapan dimatikan atau tidak ada halaman HTML.",
        "crawl_error": "Galat perayapan: {error}",
        "ai_tab": "Analisis AI",
        "ai_label": "Penyedia AI",
        "ai_key_label": "API key AI",
        "ai_detail_label": "Detail AI",
        "ai_detail_short": "Ringkas",
        "ai_detail_standard": "Standar",
        "ai_detail_verbose": "Lengkap",
        "ai_placeholder": "Masukkan API key dan pilih penyedia untuk mengaktifkan analisis AI.",
        "ai_status_wait": "Analisis AI sedang berjalan...",
        "ai_status_disabled": "Analisis AI dimatikan.",
        "ai_status_missing_key": "Pilih penyedia dan isi API key untuk mengaktifkan analisis AI.",
        "ai_error": "Analisis AI gagal: {error}",
        "ai_provider_none": "Nonaktif",
        "ai_provider_openai": "ChatGPT (OpenAI)",
        "ai_provider_claude": "Claude (Anthropic)",
        "ai_provider_gemini": "Gemini (Google)",
        "cve_title": "Daftar CVE teratas",
        "cve_loading": "Mengambil data CVE...",
        "no_cves": "Tidak ada CVE untuk kata kunci tersebut.",
        "cve_error": "Gagal memuat data CVE. Periksa koneksi jaringan.",
        "scan_failed": "Pemindaian gagal",
        "input_error": "Isi host target atau kata kunci CVE sebelum memindai.",
        "waf_enabled_status": "Heuristik bypass WAF aktif.",
        "waf_disabled_status": "Bypass WAF dimatikan.",
        "language_en": "English",
        "language_id": "Bahasa Indonesia",
        "level_basic": "Dasar",
        "level_medium": "Menengah",
        "level_deep": "Mendalam",
        "level_deeper": "Sangat Dalam",
        "insight_telnet": "Layanan Telnet (23/tcp) terbuka; nonaktifkan jika tidak perlu.",
        "insight_rdp": "Remote Desktop (3389/tcp) dapat dijangkau; pastikan MFA dan pembatasan jaringan.",
        "insight_https": "HTTPS tertutup sementara HTTP terbuka; sebaiknya paksa koneksi TLS.",
        "insight_banner": "Banner HTTP menampilkan detail perangkat lunak; sembunyikan versi jika memungkinkan.",
        "insight_error_rate": "Layanan mengembalikan HTTP error (>399); periksa log server.",
    },
}


class Translator:
    """Minimal helper for bilingual UI copy."""

    def __init__(self, translations: Dict[str, Dict[str, str]], default: str = "en") -> None:
        self._translations = translations
        self._default = default
        self._current = default

    @property
    def current(self) -> str:
        return self._current

    def set_language(self, lang: str) -> None:
        if lang in self._translations:
            self._current = lang

    def get(self, key: str) -> str:
        lang_map = self._translations.get(self._current, {})
        default_map = self._translations.get(self._default, {})
        return lang_map.get(key) or default_map.get(key, key)

    __call__ = get


class DebugLogger:
    """Broadcasts log lines to the UI and (optionally) standard logging."""

    def __init__(self) -> None:
        self._enabled = False
        self._subscribers: List[Any] = []
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    def set_enabled(self, enabled: bool) -> None:
        self._enabled = enabled

    def subscribe(self, callback) -> None:
        self._subscribers.append(callback)

    def info(self, message: str) -> None:
        self._emit("INFO", message)

    def debug(self, message: str) -> None:
        if self._enabled:
            self._emit("DEBUG", message, log_to_python=True)

    def warning(self, message: str) -> None:
        self._emit("WARN", message, log_to_python=True)

    def error(self, message: str) -> None:
        self._emit("ERROR", message, log_to_python=True)

    def _emit(self, level: str, message: str, log_to_python: bool = False) -> None:
        payload = f"[{level}] {message}"
        if log_to_python:
            getattr(logging, level.lower(), logging.info)(message)
        for subscriber in self._subscribers:
            subscriber(payload)


class ScanLevel(Enum):
    BASIC = "basic"
    MEDIUM = "medium"
    DEEP = "deep"
    DEEPER = "deeper"

    @property
    def label_key(self) -> str:
        return f"level_{self.value}"


COMMON_PORTS = [
    (21, "ftp"),
    (22, "ssh"),
    (23, "telnet"),
    (25, "smtp"),
    (53, "dns"),
    (80, "http"),
    (110, "pop3"),
    (143, "imap"),
    (443, "https"),
    (445, "smb"),
    (465, "smtps"),
    (587, "submission"),
    (993, "imaps"),
    (995, "pop3s"),
    (135, "rpc"),
    (139, "netbios"),
    (1433, "mssql"),
    (1521, "oracle"),
    (2049, "nfs"),
    (2375, "docker"),
    (3306, "mysql"),
    (3389, "rdp"),
    (5000, "http-alt"),
    (5432, "postgresql"),
    (5900, "vnc"),
    (6379, "redis"),
    (8080, "http-alt"),
    (8443, "https-alt"),
]

PORT_PROFILES: Dict[ScanLevel, List[tuple[int, str]]] = {
    ScanLevel.BASIC: COMMON_PORTS[:8],
    ScanLevel.MEDIUM: COMMON_PORTS[:15],
    ScanLevel.DEEP: COMMON_PORTS[:22],
    ScanLevel.DEEPER: COMMON_PORTS,
}

PORT_TIMEOUTS = {
    ScanLevel.BASIC: 0.8,
    ScanLevel.MEDIUM: 1.2,
    ScanLevel.DEEP: 1.8,
    ScanLevel.DEEPER: 2.5,
}

WAF_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
]

WAF_ACCEPT_LANGS = [
    "en-US,en;q=0.9",
    "en-US,en;q=0.9,id;q=0.7",
    "id-ID,id;q=0.9,en-US;q=0.8",
]

HTML_CONTENT_HINTS = ("text/html", "application/xhtml+xml")

DEFAULT_DOCUMENT_EXTENSIONS = ("pdf", "doc", "docx", "ppt", "pptx", "txt")
DEFAULT_CRAWL_KEYWORDS = ["admin", "login", "signin", "upload", "backup", "config", "manage", "test", "staging", "dev", "portal", "secret", "private"]
DUCKDUCKGO_ENDPOINT = "https://duckduckgo.com/html/"
DOCUMENT_SEARCH_LIMIT = 9999
SOCIAL_PLATFORMS = ["x", "facebook", "instagram", "threads", "telegram"]
LINK_AGGREGATOR_DOMAINS = ["linktr.ee", "beacons.ai", "campsite.bio", "solo.to", "bio.site", "tap.bio"]
DOCUMENT_KEYWORDS = ["password", "confidential", "internal use", "restricted", "secret", "credential", "account", "login", "exposure"]
AI_PROVIDER_DEFAULT_MODELS = {
    "openai": "gpt-4o-mini",
    "claude": "claude-3-sonnet-20240229",
    "gemini": "gemini-2.5-flash",
}

SERVER_SIGNATURES = [
    ("cloudflare", ("Cloudflare", "Cloudflare Edge")),
    ("akamai", ("Akamai", "Akamai Edge")),
    ("incapsula", ("Imperva", "Incapsula WAF")),
    ("sucuri", ("Sucuri", "Sucuri Firewall")),
    ("nginx", ("F5", "nginx")),
    ("openresty", ("OpenResty", "OpenResty")),
    ("apache", ("Apache", "Apache HTTP Server")),
    ("coyote", ("Apache", "Tomcat/Coyote")),
    ("microsoft-iis", ("Microsoft", "IIS")),
    ("microsoft-httpapi", ("Microsoft", "HTTP.SYS")),
    ("asp.net", ("Microsoft", "ASP.NET")),
    ("express", ("Node.js", "Express")),
    ("gunicorn", ("Gunicorn", "Gunicorn WSGI")),
    ("liteSpeed", ("LiteSpeed", "LiteSpeed Web Server")),
    ("php", ("PHP", "PHP Application")),
    ("wordpress", ("Automattic", "WordPress")),
    ("joomla", ("Joomla", "Joomla CMS")),
    ("drupal", ("Drupal", "Drupal CMS")),
    ("weblogic", ("Oracle", "WebLogic")),
    ("websphere", ("IBM", "WebSphere")),
    ("oracle-application-server", ("Oracle", "Oracle Application Server")),
    ("jboss", ("Red Hat", "JBoss / WildFly")),
]

# Technology fingerprinting patterns
TECH_FINGERPRINTS = {
    "wordpress": {
        "headers": ["x-powered-by: wp"],
        "html_patterns": [r"/wp-content/", r"/wp-includes/", r"wp-json", r"wordpress"],
        "meta_generators": ["WordPress"],
    },
    "drupal": {
        "headers": ["x-drupal-cache", "x-generator: drupal"],
        "html_patterns": [r"/sites/default/files/", r"drupal.js", r"Drupal\.settings"],
        "meta_generators": ["Drupal"],
    },
    "joomla": {
        "headers": [],
        "html_patterns": [r"/components/com_", r"/modules/mod_", r"joomla"],
        "meta_generators": ["Joomla"],
    },
    "laravel": {
        "headers": ["x-powered-by: php"],
        "html_patterns": [r"laravel", r"csrf-token"],
        "cookies": ["laravel_session"],
    },
    "django": {
        "headers": [],
        "html_patterns": [r"csrfmiddlewaretoken", r"django"],
        "cookies": ["csrftoken", "sessionid"],
    },
    "react": {
        "html_patterns": [r"react", r"_reactRootContainer", r"data-reactroot"],
    },
    "vue": {
        "html_patterns": [r"vue", r"v-cloak", r"data-v-"],
    },
    "angular": {
        "html_patterns": [r"ng-app", r"ng-controller", r"angular", r"ng-version"],
    },
    "nextjs": {
        "headers": ["x-powered-by: next.js"],
        "html_patterns": [r"__NEXT_DATA__", r"_next/static"],
    },
    "nuxt": {
        "html_patterns": [r"__NUXT__", r"_nuxt/"],
    },
    "shopify": {
        "html_patterns": [r"cdn.shopify.com", r"Shopify.theme"],
    },
    "wix": {
        "html_patterns": [r"wix.com", r"wixstatic.com"],
    },
    "squarespace": {
        "html_patterns": [r"squarespace.com", r"static.squarespace"],
    },
}

# Scan profiles
SCAN_PROFILES = {
    "quick": {
        "level": ScanLevel.BASIC,
        "crawl": False,
        "waf_evasion": False,
        "description": "Fast scan - top 8 ports, no crawling",
    },
    "standard": {
        "level": ScanLevel.MEDIUM,
        "crawl": True,
        "waf_evasion": False,
        "description": "Standard scan - 15 ports, basic crawling",
    },
    "full": {
        "level": ScanLevel.DEEP,
        "crawl": True,
        "waf_evasion": True,
        "description": "Full scan - 22 ports, deep crawling, WAF evasion",
    },
    "stealth": {
        "level": ScanLevel.DEEPER,
        "crawl": True,
        "waf_evasion": True,
        "description": "Stealth scan - all ports, slow timing, full evasion",
    },
}


def get_config_dir() -> Path:
    """Get cross-platform configuration directory."""
    if IS_WINDOWS:
        base = Path(os.environ.get("APPDATA", Path.home()))
    elif IS_MACOS:
        base = Path.home() / "Library" / "Application Support"
    else:  # Linux and other Unix-like
        xdg_config = os.environ.get("XDG_CONFIG_HOME")
        base = Path(xdg_config) if xdg_config else Path.home() / ".config"
    
    config_dir = base / "makassarscan"
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir


def get_cache_dir() -> Path:
    """Get cross-platform cache directory."""
    if IS_WINDOWS:
        base = Path(os.environ.get("LOCALAPPDATA", Path.home()))
    elif IS_MACOS:
        base = Path.home() / "Library" / "Caches"
    else:
        xdg_cache = os.environ.get("XDG_CACHE_HOME")
        base = Path(xdg_cache) if xdg_cache else Path.home() / ".cache"
    
    cache_dir = base / "makassarscan"
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir


def get_reports_dir() -> Path:
    """Get cross-platform reports directory."""
    reports_dir = get_config_dir() / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    return reports_dir


# Cross-platform styling
DARK_THEME = {
    "bg": "#1e1e2e",
    "fg": "#cdd6f4",
    "accent": "#89b4fa",
    "success": "#a6e3a1",
    "warning": "#f9e2af",
    "error": "#f38ba8",
    "surface": "#313244",
    "overlay": "#45475a",
    "text": "#cdd6f4",
    "subtext": "#a6adc8",
}

LIGHT_THEME = {
    "bg": "#eff1f5",
    "fg": "#4c4f69",
    "accent": "#1e66f5",
    "success": "#40a02b",
    "warning": "#df8e1d",
    "error": "#d20f39",
    "surface": "#dce0e8",
    "overlay": "#ccd0da",
    "text": "#4c4f69",
    "subtext": "#6c6f85",
}

# HTTP Security Headers to check
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "HSTS - Forces HTTPS connections",
        "severity": "high",
        "recommendation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'",
    },
    "Content-Security-Policy": {
        "description": "CSP - Prevents XSS and data injection",
        "severity": "high",
        "recommendation": "Implement a strict Content-Security-Policy header",
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME type sniffing",
        "severity": "medium",
        "recommendation": "Add 'X-Content-Type-Options: nosniff'",
    },
    "X-Frame-Options": {
        "description": "Prevents clickjacking attacks",
        "severity": "medium",
        "recommendation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN'",
    },
    "X-XSS-Protection": {
        "description": "Legacy XSS filter (deprecated but still useful)",
        "severity": "low",
        "recommendation": "Add 'X-XSS-Protection: 1; mode=block'",
    },
    "Referrer-Policy": {
        "description": "Controls referrer information leakage",
        "severity": "low",
        "recommendation": "Add 'Referrer-Policy: strict-origin-when-cross-origin'",
    },
    "Permissions-Policy": {
        "description": "Controls browser features access",
        "severity": "low",
        "recommendation": "Add appropriate Permissions-Policy header",
    },
    "X-Permitted-Cross-Domain-Policies": {
        "description": "Controls Flash/PDF cross-domain access",
        "severity": "low",
        "recommendation": "Add 'X-Permitted-Cross-Domain-Policies: none'",
    },
}


# =============================================================================
# CONCURRENT PORT SCANNER (10x FASTER)
# =============================================================================

class ConcurrentPortScanner:
    """High-performance multi-threaded port scanner."""

    def __init__(self, logger: DebugLogger, max_workers: int = 50) -> None:
        self.logger = logger
        self.max_workers = max_workers

    def scan_ports(
        self,
        host: str,
        ports: List[Tuple[int, str]],
        timeout: float = 1.5,
    ) -> List[Dict[str, Any]]:
        """Scan multiple ports concurrently for 10x speed improvement."""
        results: List[Dict[str, Any]] = []
        
        self.logger.info(f"🚀 Concurrent port scan: {len(ports)} ports with {self.max_workers} threads")
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self._scan_single_port, host, port, service, timeout): (port, service)
                for port, service in ports
            }
            
            for future in as_completed(futures):
                port, service = futures[future]
                try:
                    is_open, banner = future.result()
                    results.append({
                        "port": port,
                        "service": service,
                        "open": is_open,
                        "banner": banner,
                    })
                except Exception as exc:
                    self.logger.debug(f"Port {port} scan error: {exc}")
                    results.append({
                        "port": port,
                        "service": service,
                        "open": False,
                        "banner": None,
                    })
        
        # Sort by port number
        results.sort(key=lambda x: x["port"])
        
        open_count = sum(1 for r in results if r["open"])
        self.logger.info(f"✅ Scan complete: {open_count}/{len(ports)} ports open")
        
        return results

    def _scan_single_port(
        self,
        host: str,
        port: int,
        service: str,
        timeout: float,
    ) -> Tuple[bool, Optional[str]]:
        """Scan a single port and optionally grab banner."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            
            if result == 0:
                banner = None
                # Try banner grab for certain services
                if service in ("ftp", "ssh", "smtp", "http", "pop3", "imap"):
                    try:
                        sock.settimeout(1.0)
                        banner = sock.recv(1024).decode(errors="ignore").strip()[:200]
                    except Exception:
                        pass
                sock.close()
                return True, banner
            
            sock.close()
            return False, None
            
        except Exception:
            return False, None


# =============================================================================
# HTTP SECURITY HEADERS ANALYZER
# =============================================================================

@dataclass
class SecurityHeaderResult:
    """Result of security header analysis."""
    header: str
    present: bool
    value: Optional[str]
    description: str
    severity: str
    recommendation: str
    score: int  # 0-100


class SecurityHeadersAnalyzer:
    """Analyzes HTTP security headers for vulnerabilities."""

    def __init__(self, logger: DebugLogger) -> None:
        self.logger = logger

    def analyze(self, url: str, timeout: int = 10) -> Dict[str, Any]:
        """Analyze security headers for a given URL."""
        self.logger.info(f"🔒 Analyzing security headers for: {url}")
        
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"
        
        try:
            response = requests.head(
                url,
                timeout=timeout,
                verify=False,
                allow_redirects=True,
                headers={"User-Agent": DEFAULT_USER_AGENT}
            )
            headers = {k.lower(): v for k, v in response.headers.items()}
        except requests.RequestException as exc:
            self.logger.warning(f"Failed to fetch headers: {exc}")
            return {"error": str(exc), "headers": [], "score": 0, "grade": "F"}
        
        results: List[SecurityHeaderResult] = []
        total_score = 0
        max_score = 0
        
        for header_name, info in SECURITY_HEADERS.items():
            header_lower = header_name.lower()
            present = header_lower in headers
            value = headers.get(header_lower)
            
            # Calculate score weight based on severity
            weight = {"high": 20, "medium": 10, "low": 5}.get(info["severity"], 5)
            max_score += weight
            
            if present:
                total_score += weight
                score = 100
            else:
                score = 0
            
            results.append(SecurityHeaderResult(
                header=header_name,
                present=present,
                value=value,
                description=info["description"],
                severity=info["severity"],
                recommendation=info["recommendation"] if not present else "Header is properly configured",
                score=score,
            ))
        
        # Calculate overall score and grade
        overall_score = int((total_score / max_score) * 100) if max_score > 0 else 0
        grade = self._calculate_grade(overall_score)
        
        # Check for dangerous headers
        dangerous = []
        if "server" in headers:
            dangerous.append(f"Server header exposes: {headers['server']}")
        if "x-powered-by" in headers:
            dangerous.append(f"X-Powered-By exposes: {headers['x-powered-by']}")
        if "x-aspnet-version" in headers:
            dangerous.append(f"ASP.NET version exposed: {headers['x-aspnet-version']}")
        
        present_count = sum(1 for r in results if r.present)
        self.logger.info(f"📊 Security headers: {present_count}/{len(results)} present (Grade: {grade})")
        
        return {
            "url": url,
            "headers": results,
            "score": overall_score,
            "grade": grade,
            "dangerous_headers": dangerous,
            "present_count": present_count,
            "total_count": len(results),
        }

    def _calculate_grade(self, score: int) -> str:
        """Calculate letter grade from score."""
        if score >= 90:
            return "A+"
        elif score >= 80:
            return "A"
        elif score >= 70:
            return "B"
        elif score >= 60:
            return "C"
        elif score >= 50:
            return "D"
        else:
            return "F"


# =============================================================================
# DNS RECORD ENUMERATOR
# =============================================================================

@dataclass
class DNSRecord:
    """DNS record information."""
    record_type: str
    value: str
    ttl: Optional[int] = None


class DNSEnumerator:
    """Enumerate DNS records for a domain."""

    RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "PTR"]

    def __init__(self, logger: DebugLogger) -> None:
        self.logger = logger

    def enumerate(self, domain: str) -> Dict[str, Any]:
        """Enumerate all DNS record types for a domain."""
        self.logger.info(f"🌐 Enumerating DNS records for: {domain}")
        
        domain = domain.strip().lower()
        if domain.startswith("www."):
            domain = domain[4:]
        
        records: Dict[str, List[DNSRecord]] = {}
        
        for record_type in self.RECORD_TYPES:
            try:
                found = self._query_record(domain, record_type)
                if found:
                    records[record_type] = found
            except Exception as exc:
                self.logger.debug(f"DNS {record_type} query failed: {exc}")
        
        # Extract useful information
        analysis = self._analyze_records(records, domain)
        
        total_records = sum(len(v) for v in records.values())
        self.logger.info(f"📋 Found {total_records} DNS records across {len(records)} types")
        
        return {
            "domain": domain,
            "records": records,
            "analysis": analysis,
            "total_records": total_records,
        }

    def _query_record(self, domain: str, record_type: str) -> List[DNSRecord]:
        """Query a specific DNS record type."""
        results: List[DNSRecord] = []
        
        if _DNS_AVAILABLE:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                for rdata in answers:
                    value = str(rdata)
                    if record_type == "MX":
                        value = f"{rdata.preference} {rdata.exchange}"
                    elif record_type == "SOA":
                        value = f"{rdata.mname} {rdata.rname}"
                    results.append(DNSRecord(
                        record_type=record_type,
                        value=value,
                        ttl=answers.rrset.ttl if answers.rrset else None,
                    ))
            except Exception:
                pass
        else:
            # Fallback to socket for A records
            if record_type == "A":
                try:
                    ip = socket.gethostbyname(domain)
                    results.append(DNSRecord(record_type="A", value=ip))
                except socket.gaierror:
                    pass
        
        return results

    def _analyze_records(self, records: Dict[str, List[DNSRecord]], domain: str) -> Dict[str, Any]:
        """Analyze DNS records for security insights."""
        analysis = {
            "mail_providers": [],
            "cloud_providers": [],
            "cdn_detected": False,
            "spf_record": None,
            "dmarc_record": None,
            "dnssec_enabled": False,
        }
        
        # Analyze MX records
        for mx in records.get("MX", []):
            value = mx.value.lower()
            if "google" in value or "gmail" in value:
                analysis["mail_providers"].append("Google Workspace")
            elif "outlook" in value or "microsoft" in value:
                analysis["mail_providers"].append("Microsoft 365")
            elif "protonmail" in value:
                analysis["mail_providers"].append("ProtonMail")
            elif "zoho" in value:
                analysis["mail_providers"].append("Zoho Mail")
        
        # Analyze TXT records
        for txt in records.get("TXT", []):
            value = txt.value.lower()
            if "v=spf1" in value:
                analysis["spf_record"] = txt.value
            if "v=dmarc1" in value:
                analysis["dmarc_record"] = txt.value
        
        # Analyze A records for CDN/Cloud
        for a in records.get("A", []):
            ip = a.value
            # Simple CDN detection (could be expanded)
            if ip.startswith(("104.", "172.", "13.", "52.")):
                analysis["cloud_providers"].append("Possible AWS/Cloudflare")
                analysis["cdn_detected"] = True
        
        # Analyze NS records for cloud hosting
        for ns in records.get("NS", []):
            value = ns.value.lower()
            if "cloudflare" in value:
                analysis["cloud_providers"].append("Cloudflare")
                analysis["cdn_detected"] = True
            elif "awsdns" in value:
                analysis["cloud_providers"].append("AWS Route53")
            elif "google" in value:
                analysis["cloud_providers"].append("Google Cloud DNS")
        
        return analysis


# =============================================================================
# WAYBACK MACHINE INTEGRATION
# =============================================================================

@dataclass
class WaybackSnapshot:
    """Wayback Machine snapshot information."""
    url: str
    timestamp: str
    status_code: str
    mime_type: str
    archive_url: str


class WaybackMachine:
    """Fetch historical URLs from the Wayback Machine."""

    API_URL = "https://web.archive.org/cdx/search/cdx"

    def __init__(self, logger: DebugLogger) -> None:
        self.logger = logger
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": DEFAULT_USER_AGENT})

    def get_snapshots(
        self,
        domain: str,
        limit: int = 100,
        collapse: str = "urlkey",
    ) -> Dict[str, Any]:
        """Fetch historical snapshots from Wayback Machine."""
        self.logger.info(f"📜 Fetching Wayback Machine data for: {domain}")
        
        domain = domain.strip().lower()
        if domain.startswith("www."):
            domain = domain[4:]
        
        params = {
            "url": f"*.{domain}/*",
            "output": "json",
            "limit": limit,
            "collapse": collapse,
            "fl": "original,timestamp,statuscode,mimetype",
        }
        
        try:
            response = self._session.get(self.API_URL, params=params, timeout=30)
            response.raise_for_status()
            data = response.json()
        except Exception as exc:
            self.logger.warning(f"Wayback Machine query failed: {exc}")
            return {"error": str(exc), "snapshots": [], "unique_urls": []}
        
        if not data or len(data) < 2:
            return {"snapshots": [], "unique_urls": [], "total": 0}
        
        # Parse snapshots (first row is headers)
        snapshots: List[WaybackSnapshot] = []
        unique_urls: Set[str] = set()
        
        for row in data[1:]:
            if len(row) >= 4:
                url = row[0]
                timestamp = row[1]
                status = row[2]
                mime = row[3]
                
                archive_url = f"https://web.archive.org/web/{timestamp}/{url}"
                
                snapshots.append(WaybackSnapshot(
                    url=url,
                    timestamp=timestamp,
                    status_code=status,
                    mime_type=mime,
                    archive_url=archive_url,
                ))
                
                unique_urls.add(url)
        
        # Find interesting URLs
        interesting = self._find_interesting_urls(list(unique_urls))
        
        self.logger.info(f"📚 Found {len(snapshots)} snapshots, {len(unique_urls)} unique URLs")
        
        return {
            "domain": domain,
            "snapshots": snapshots[:50],  # Limit for display
            "unique_urls": list(unique_urls),
            "interesting_urls": interesting,
            "total_snapshots": len(snapshots),
            "total_unique": len(unique_urls),
        }

    def _find_interesting_urls(self, urls: List[str]) -> List[Dict[str, str]]:
        """Identify potentially interesting historical URLs."""
        interesting: List[Dict[str, str]] = []
        
        patterns = {
            "admin": "Admin panel",
            "login": "Login page",
            "api": "API endpoint",
            "backup": "Backup file",
            "config": "Configuration",
            "upload": "Upload functionality",
            "debug": "Debug page",
            "test": "Test environment",
            "staging": "Staging server",
            "dev": "Development",
            ".sql": "SQL file",
            ".zip": "Archive file",
            ".bak": "Backup file",
            ".old": "Old version",
            "wp-admin": "WordPress admin",
            "phpMyAdmin": "Database admin",
            ".git": "Git repository",
            ".env": "Environment file",
            "swagger": "API documentation",
            "graphql": "GraphQL endpoint",
        }
        
        for url in urls[:500]:  # Limit to prevent slowdown
            url_lower = url.lower()
            for pattern, description in patterns.items():
                if pattern in url_lower:
                    interesting.append({
                        "url": url,
                        "pattern": pattern,
                        "description": description,
                    })
                    break
        
        return interesting[:50]  # Limit results


# =============================================================================
# WHOIS LOOKUP
# =============================================================================

@dataclass
class WhoisInfo:
    """WHOIS registration information."""
    domain: str
    registrar: Optional[str]
    creation_date: Optional[str]
    expiration_date: Optional[str]
    updated_date: Optional[str]
    name_servers: List[str]
    status: List[str]
    registrant_country: Optional[str]
    dnssec: Optional[str]
    raw_data: Optional[str]


class WhoisLookup:
    """Perform WHOIS lookups for domain information."""

    # WHOIS servers for different TLDs
    WHOIS_SERVERS = {
        "com": "whois.verisign-grs.com",
        "net": "whois.verisign-grs.com",
        "org": "whois.pir.org",
        "io": "whois.nic.io",
        "co": "whois.nic.co",
        "info": "whois.afilias.net",
        "biz": "whois.biz",
        "me": "whois.nic.me",
        "id": "whois.pandi.or.id",
    }
    
    DEFAULT_WHOIS_SERVER = "whois.iana.org"

    def __init__(self, logger: DebugLogger) -> None:
        self.logger = logger

    def lookup(self, domain: str) -> Dict[str, Any]:
        """Perform WHOIS lookup for a domain."""
        self.logger.info(f"🔎 WHOIS lookup for: {domain}")
        
        domain = domain.strip().lower()
        if domain.startswith("www."):
            domain = domain[4:]
        
        # Extract TLD
        parts = domain.split(".")
        if len(parts) < 2:
            return {"error": "Invalid domain format"}
        
        tld = parts[-1]
        whois_server = self.WHOIS_SERVERS.get(tld, self.DEFAULT_WHOIS_SERVER)
        
        try:
            raw_data = self._query_whois(domain, whois_server)
            if not raw_data:
                return {"error": "No WHOIS data returned"}
            
            # If IANA, need to query the referred server
            if whois_server == self.DEFAULT_WHOIS_SERVER:
                referred = self._extract_referred_server(raw_data)
                if referred:
                    raw_data = self._query_whois(domain, referred)
            
            info = self._parse_whois(domain, raw_data)
            
            self.logger.info(f"✅ WHOIS: Registrar: {info.registrar or 'N/A'}")
            
            return {
                "domain": domain,
                "info": info,
                "raw": raw_data[:2000] if raw_data else None,  # Truncate
            }
            
        except Exception as exc:
            self.logger.warning(f"WHOIS lookup failed: {exc}")
            return {"error": str(exc), "domain": domain}

    def _query_whois(self, domain: str, server: str, port: int = 43) -> Optional[str]:
        """Query a WHOIS server."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((server, port))
            sock.send(f"{domain}\r\n".encode())
            
            response = b""
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
            
            sock.close()
            return response.decode(errors="ignore")
            
        except Exception as exc:
            self.logger.debug(f"WHOIS query to {server} failed: {exc}")
            return None

    def _extract_referred_server(self, data: str) -> Optional[str]:
        """Extract referred WHOIS server from IANA response."""
        for line in data.split("\n"):
            if "whois:" in line.lower() or "refer:" in line.lower():
                parts = line.split(":")
                if len(parts) >= 2:
                    return parts[-1].strip()
        return None

    def _parse_whois(self, domain: str, raw_data: str) -> WhoisInfo:
        """Parse WHOIS raw data into structured info."""
        info = WhoisInfo(
            domain=domain,
            registrar=None,
            creation_date=None,
            expiration_date=None,
            updated_date=None,
            name_servers=[],
            status=[],
            registrant_country=None,
            dnssec=None,
            raw_data=raw_data,
        )
        
        patterns = {
            "registrar": [
                r"Registrar:\s*(.+)",
                r"Registrar Name:\s*(.+)",
                r"Sponsoring Registrar:\s*(.+)",
            ],
            "creation_date": [
                r"Creation Date:\s*(.+)",
                r"Created Date:\s*(.+)",
                r"Created:\s*(.+)",
                r"Registration Date:\s*(.+)",
            ],
            "expiration_date": [
                r"Expir\w+ Date:\s*(.+)",
                r"Expiry Date:\s*(.+)",
                r"Expires:\s*(.+)",
            ],
            "updated_date": [
                r"Updated Date:\s*(.+)",
                r"Last Modified:\s*(.+)",
                r"Last Updated:\s*(.+)",
            ],
            "registrant_country": [
                r"Registrant Country:\s*(.+)",
                r"Country:\s*(.+)",
            ],
            "dnssec": [
                r"DNSSEC:\s*(.+)",
            ],
        }
        
        for field, regexes in patterns.items():
            for regex in regexes:
                match = re.search(regex, raw_data, re.IGNORECASE)
                if match:
                    value = match.group(1).strip()
                    setattr(info, field, value)
                    break
        
        # Extract name servers
        ns_pattern = r"Name Server:\s*(.+)"
        for match in re.finditer(ns_pattern, raw_data, re.IGNORECASE):
            ns = match.group(1).strip().lower()
            if ns and ns not in info.name_servers:
                info.name_servers.append(ns)
        
        # Extract domain status
        status_pattern = r"(?:Domain )?Status:\s*(.+)"
        for match in re.finditer(status_pattern, raw_data, re.IGNORECASE):
            status = match.group(1).strip()
            if status and status not in info.status:
                info.status.append(status)
        
        return info

@dataclass
class ScanRequest:
    target: str
    vendor: str
    product: str
    scan_level: ScanLevel
    user_agent: str
    debug_enabled: bool
    waf_evasion: bool
    crawl: "CrawlSettings"
    document_extensions: List[str]
    social: "SocialConfig"


@dataclass
class CrawlSettings:
    enabled: bool
    max_depth: int
    max_pages: int
    keywords: List[str]
    dedupe: bool = True


@dataclass
class CrawlFinding:
    url: str
    status: Optional[int]
    title: Optional[str]
    forms: int
    scripts: int
    post_forms: int
    password_fields: int
    file_fields: int
    query_params: int
    keywords: List[str]
    flags: List[str]


@dataclass
class DocumentFinding:
    url: str
    extension: str
    source: str
    size: Optional[int] = None
    keywords: List[str] = field(default_factory=list)


@dataclass
class SocialProviderSettings:
    enabled: bool
    api_key: str
    secret: str
    handle: str


@dataclass
class SocialConfig:
    providers: Dict[str, SocialProviderSettings]


@dataclass
class ServiceFinding:
    name: str
    detail: Dict[str, Any]


@dataclass
class AISettings:
    provider: str
    api_key: str
    enabled: bool
    model: Optional[str] = None
    detail: str = "standard"


class LinkParser(HTMLParser):
    """Extracts anchor links, simple metadata, and element counters."""

    def __init__(self) -> None:
        super().__init__()
        self.links: Set[str] = set()
        self.forms = 0
        self.scripts = 0
        self.post_forms = 0
        self.password_inputs = 0
        self.file_inputs = 0
        self._capture_title = False
        self._title_parts: List[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        tag = tag.lower()
        if tag == "a":
            href = None
            for key, value in attrs:
                if key.lower() == "href":
                    href = value
                    break
            if href:
                self.links.add(href.strip())
        elif tag == "form":
            self.forms += 1
            for key, value in attrs:
                if key.lower() == "method" and value and value.lower() == "post":
                    self.post_forms += 1
                    break
        elif tag == "script":
            self.scripts += 1
        elif tag == "title":
            self._capture_title = True
        elif tag == "input":
            input_type = "text"
            for key, value in attrs:
                if key.lower() == "type" and value:
                    input_type = value.lower()
                    break
            if input_type == "password":
                self.password_inputs += 1
            elif input_type in {"file", "image"}:
                self.file_inputs += 1
        elif tag == "textarea":
            # treat textarea as sensitive if name hints at password/upload
            for key, value in attrs:
                if key.lower() == "name" and value and "password" in value.lower():
                    self.password_inputs += 1

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self._capture_title = False

    def handle_data(self, data: str) -> None:
        if self._capture_title:
            cleaned = data.strip()
            if cleaned:
                self._title_parts.append(cleaned)

    @property
    def title(self) -> Optional[str]:
        if not self._title_parts:
            return None
        return " ".join(self._title_parts)[:180]


@dataclass
class ScanResult:
    host: Optional[str]
    level: ScanLevel
    ports: List[Dict[str, Any]]
    http_metadata: Optional[Dict[str, Any]]
    tls_metadata: Optional[Dict[str, Any]]
    insights: List[str]
    duration: float
    crawl_findings: List[CrawlFinding]
    crawl_settings: CrawlSettings
    waf_evasion: bool
    identified_vendor: Optional[str]
    identified_product: Optional[str]
    identified_runtime: Optional[str]
    documents: List[DocumentFinding]
    social: SocialConfig
    services: List[ServiceFinding] = field(default_factory=list)


class VulnerabilityScanner:
    """Performs socket probes and remote metadata collection."""

    def __init__(self, logger: DebugLogger) -> None:
        self.logger = logger

    def run_scan(self, request: ScanRequest) -> ScanResult:
        host = self._extract_host(request.target)
        ports_to_probe = PORT_PROFILES[request.scan_level]
        timeout = PORT_TIMEOUTS[request.scan_level]
        session = self._build_session(request.user_agent, request.waf_evasion)
        waf_message = "enabled" if request.waf_evasion else "disabled"
        self.logger.info(f"WAF evasion heuristics {waf_message}.")

        start = time.time()
        port_findings: List[Dict[str, Any]] = []
        service_findings: List[ServiceFinding] = []
        if host:
            self.logger.info(f"Scanning {host} with {request.scan_level.name} profile.")
            for port, service in ports_to_probe:
                state = self._scan_port(host, port, timeout)
                port_findings.append({"port": port, "service": service, "open": state})
                if state and port == 21:
                    ftp_banner = self._fetch_ftp_banner(host)
                    if ftp_banner:
                        service_findings.append(
                            ServiceFinding(
                                name="ftp",
                                detail=ftp_banner,
                            )
                        )
        else:
            self.logger.info("Skipping socket probes (no host supplied).")

        http_metadata: Optional[Dict[str, Any]] = None
        tls_metadata: Optional[Dict[str, Any]] = None
        if host and request.scan_level in {ScanLevel.MEDIUM, ScanLevel.DEEP, ScanLevel.DEEPER}:
            http_metadata = self._fetch_http_metadata(request.target, session, request)
            if http_metadata:
                self.logger.info("Fetched HTTP metadata.")

        if host and any(p["port"] == 443 and p["open"] for p in port_findings):
            tls_metadata = self._fetch_tls_profile(host)

        crawl_findings: List[CrawlFinding] = []
        document_findings: List[DocumentFinding] = []
        if request.crawl.enabled and host:
            crawl_findings, document_findings = self._crawl_target(request, session, host)
        elif request.crawl.enabled:
            self.logger.warning("Crawler requested but target host could not be resolved.")

        search_documents: List[DocumentFinding] = []
        if host:
            search_documents = self._search_documents_duckduckgo(host, session, request)

        combined_documents: List[DocumentFinding] = []
        seen_doc_urls: Set[str] = set()
        for doc in document_findings + search_documents:
            normalized = doc.url.lower()
            if normalized in seen_doc_urls:
                continue
            seen_doc_urls.add(normalized)
            combined_documents.append(doc)

        insights = self._derive_insights(port_findings, http_metadata)
        vendor_guess, product_guess, runtime_guess = self._infer_identifiers(
            http_metadata,
            tls_metadata,
            crawl_findings,
        )

        duration = time.time() - start
        return ScanResult(
            host=host,
            level=request.scan_level,
            ports=port_findings,
            http_metadata=http_metadata,
            tls_metadata=tls_metadata,
            insights=insights,
            duration=duration,
            crawl_findings=crawl_findings,
            crawl_settings=request.crawl,
            waf_evasion=request.waf_evasion,
            identified_vendor=vendor_guess,
            identified_product=product_guess,
            identified_runtime=runtime_guess,
            documents=combined_documents,
            social=request.social,
            services=service_findings,
        )

    def fetch_cves(self, keyword: str, user_agent: str, max_results: int = 10) -> List[Dict[str, Any]]:
        keyword = keyword.strip()
        if not keyword:
            return []

        endpoint = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": max_results,
        }
        headers = {
            "User-Agent": user_agent[:256],
            "Accept": "application/json",
        }
        self.logger.info(f"Querying NVD for keyword '{keyword}'.")
        response = requests.get(endpoint, params=params, headers=headers, timeout=15, verify=True)
        response.raise_for_status()
        data = response.json()
        results = []

        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            metrics = cve.get("metrics", {})
            score = self._extract_cvss(metrics)
            descriptions = cve.get("descriptions", [])
            summary = descriptions[0]["value"] if descriptions else "n/a"
            published = cve.get("published")
            references = [ref.get("url") for ref in cve.get("references", []) if ref.get("url")]
            results.append(
                {
                    "id": cve.get("id", "unknown"),
                    "score": score,
                    "summary": summary,
                    "published": published,
                    "references": references[:3],
                }
            )
        return results

    def _extract_cvss(self, metrics: Dict[str, Any]) -> Optional[float]:
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                return metrics[key][0].get("cvssData", {}).get("baseScore")
        return None

    def _extract_host(self, target: str) -> Optional[str]:
        if not target:
            return None
        target = target.strip()
        if not target:
            return None
        parsed = urlparse(target if "://" in target else f"//{target}", scheme="http")
        return parsed.hostname

    def _scan_port(self, host: str, port: int, timeout: float) -> bool:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                self.logger.debug(f"Port {port} is open.")
                return True
        except (socket.timeout, ConnectionRefusedError, OSError) as exc:
            self.logger.debug(f"Port {port} closed or filtered ({exc}).")
            return False

    def _fetch_ftp_banner(self, host: str) -> Optional[Dict[str, Any]]:
        try:
            with socket.create_connection((host, 21), timeout=3) as sock:
                banner = sock.recv(512).decode(errors="ignore").strip()
                anonymous_allowed = False
                if banner.startswith("220"):
                    sock.sendall(b"USER anonymous\r\n")
                    response = sock.recv(512).decode(errors="ignore")
                    if response.startswith("331"):
                        anonymous_allowed = True
                return {"banner": banner, "anonymous": anonymous_allowed}
        except OSError as exc:
            self.logger.debug(f"FTP banner fetch failed: {exc}")
            return None

    def _fetch_http_metadata(
        self,
        target: str,
        session: requests.Session,
        request: ScanRequest,
    ) -> Optional[Dict[str, Any]]:
        url = target if target.startswith(("http://", "https://")) else f"http://{target}"
        headers = {"Accept": "text/html,application/json;q=0.9,*/*;q=0.8"}
        timeout = 8 if request.scan_level in {ScanLevel.DEEP, ScanLevel.DEEPER} else 5
        verify = request.scan_level in {ScanLevel.BASIC, ScanLevel.MEDIUM}
        if request.waf_evasion:
            url = self._add_noise_token(url)
            headers["Accept-Language"] = random.choice(WAF_ACCEPT_LANGS)
        self.logger.debug(f"HTTP metadata request to {url} (verify={verify}).")
        try:
            response = session.get(
                url,
                headers=headers,
                timeout=timeout,
                verify=verify,
                allow_redirects=True,
            )
            if request.waf_evasion:
                self._respect_waf_delay()
            server = response.headers.get("Server", "n/a")
            powered_by = response.headers.get("X-Powered-By")
            banner = response.headers.get("Server") or powered_by
            return {
                "url": response.url,
                "status": response.status_code,
                "headers": dict(response.headers),
                "server": server,
                "powered_by": powered_by,
                "banner": banner,
            }
        except requests.RequestException as exc:
            self.logger.warning(f"HTTP metadata lookup failed: {exc}")
            return None

    def _crawl_target(
        self,
        request: ScanRequest,
        session: requests.Session,
        host: str,
    ) -> tuple[List[CrawlFinding], List[DocumentFinding]]:
        settings = request.crawl
        if not settings.enabled:
            return [], []

        if request.target.startswith("https://"):
            scheme_pref = "https"
        elif request.target.startswith("http://"):
            scheme_pref = "http"
        else:
            scheme_pref = "https" if request.scan_level in {ScanLevel.DEEP, ScanLevel.DEEPER} else "http"
        start_url = request.target if request.target.startswith(("http://", "https://")) else f"{scheme_pref}://{request.target}"
        tasks: deque = deque([(start_url, 0)])
        visited_full: Set[str] = set()
        visited_path: Set[str] = set()
        findings: List[CrawlFinding] = []
        documents: List[DocumentFinding] = []
        verify = request.scan_level in {ScanLevel.BASIC, ScanLevel.MEDIUM}
        keywords = request.crawl.keywords or list(DEFAULT_CRAWL_KEYWORDS)
        request.crawl.keywords = keywords

        self.logger.info(
            f"Starting crawler: depth {settings.max_depth}, limit {settings.max_pages} pages."
        )

        while tasks and len(findings) < settings.max_pages:
            url, depth = tasks.popleft()
            if depth > settings.max_depth:
                continue
            normalized_full = self._normalize_url(url, ignore_query=False)
            if normalized_full in visited_full:
                continue
            visited_full.add(normalized_full)
            normalized = self._normalize_url(url, ignore_query=settings.dedupe)
            if settings.dedupe:
                if normalized in visited_path:
                    continue
                visited_path.add(normalized)

            fetch_url = self._add_noise_token(url) if request.waf_evasion else url
            try:
                response = session.get(
                    fetch_url,
                    timeout=8,
                    verify=verify,
                    allow_redirects=True,
                    headers={"Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8"},
                )
            except requests.RequestException as exc:
                self.logger.debug(f"Crawler request failed for {fetch_url}: {exc}")
                if request.waf_evasion:
                    self._respect_waf_delay()
                continue

            if request.waf_evasion:
                self._respect_waf_delay()

            if not self._is_html_response(response):
                continue

            parser = LinkParser()
            try:
                parser.feed(response.text)
            except Exception as exc:  # pragma: no cover
                self.logger.debug(f"Parser error on {response.url}: {exc}")

            matched_keywords: List[str] = []
            should_record = True
            if settings.keywords:
                haystack = f"{response.url.lower()} {parser.title.lower() if parser.title else ''}"
                matched_keywords = [kw for kw in settings.keywords if kw in haystack]
                if not matched_keywords:
                    should_record = False
                else:
                    should_record = True
            else:
                should_record = True

            if should_record:
                query_params = len(parse_qsl(urlparse(response.url).query, keep_blank_values=True))
                flags: List[str] = []
                if parser.password_inputs:
                    flags.append("password_form")
                if parser.file_inputs:
                    flags.append("file_upload")
                if parser.post_forms:
                    flags.append("post_form")
                if matched_keywords:
                    flags.extend(matched_keywords)
                if query_params >= 3:
                    flags.append("multi_param")
                findings.append(
                    CrawlFinding(
                        url=response.url,
                        status=response.status_code,
                        title=parser.title,
                        forms=parser.forms,
                        scripts=parser.scripts,
                        post_forms=parser.post_forms,
                        password_fields=parser.password_inputs,
                        file_fields=parser.file_inputs,
                        query_params=query_params,
                        keywords=matched_keywords,
                        flags=sorted(set(flags)),
                    )
                )

            for link in parser.links:
                next_url = urljoin(response.url, link)
                next_host = self._extract_host(next_url)
                if next_host:
                    if next_host != host:
                        continue
                else:
                    next_host = host
                doc_ext = self._document_extension(next_url, request.document_extensions)
                if doc_ext:
                    if len(documents) < settings.max_pages * 2:
                        doc_meta = self._inspect_document(session, next_url, verify, request, "crawler")
                        if doc_meta:
                            doc_meta.extension = doc_ext
                            documents.append(doc_meta)
                    continue
                if depth + 1 <= settings.max_depth:
                    link_matches = self._match_keywords(next_url, keywords)
                    if link_matches:
                        tasks.appendleft((next_url, depth + 1))
                    else:
                        tasks.append((next_url, depth + 1))

        if not findings:
            self.logger.info("Crawler did not find any HTML pages.")

        return findings, documents

    def _is_html_response(self, response: requests.Response) -> bool:
        content_type = response.headers.get("Content-Type", "").lower()
        return any(hint in content_type for hint in HTML_CONTENT_HINTS)

    def _normalize_url(self, url: str, ignore_query: bool = False) -> str:
        parsed = urlparse(url)
        path = parsed.path or "/"
        query = "" if ignore_query else parsed.query
        return urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), path, parsed.params, query, ""))

    def _add_noise_token(self, url: str) -> str:
        parsed = urlparse(url)
        query_items = parse_qsl(parsed.query, keep_blank_values=True)
        query_items.append((f"_mscan_{random.randint(1000,9999)}", self._random_token()))
        new_query = urlencode(query_items)
        return urlunparse(parsed._replace(query=new_query))

    def _random_token(self, length: int = 6) -> str:
        alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
        return "".join(random.choice(alphabet) for _ in range(length))

    def _random_ip(self) -> str:
        return ".".join(str(random.randint(1, 254)) for _ in range(4))

    def _respect_waf_delay(self) -> None:
        time.sleep(0.15 + random.random() * 0.45)

    def _document_extension(self, url: str, extensions: List[str]) -> Optional[str]:
        path = urlparse(url).path.lower()
        for ext in extensions:
            ext = ext.strip().lower()
            if not ext:
                continue
            normalized = f".{ext}"
            if path.endswith(normalized):
                return ext.upper()
        return None

    def _inspect_document(
        self,
        session: requests.Session,
        url: str,
        verify: bool,
        request: ScanRequest,
        source: str,
    ) -> Optional[DocumentFinding]:
        try:
            response = session.head(url, timeout=6, verify=verify, allow_redirects=True)
            if request.waf_evasion:
                self._respect_waf_delay()
        except requests.RequestException:
            try:
                response = session.get(
                    url,
                    timeout=6,
                    verify=verify,
                    allow_redirects=True,
                    stream=True,
                )
                if request.waf_evasion:
                    self._respect_waf_delay()
            except requests.RequestException:
                return None
        content_type = response.headers.get("Content-Type", "").lower()
        if "text/html" in content_type:
            return None
        size = response.headers.get("Content-Length")
        size_int = int(size) if size and size.isdigit() else None
        keywords_found: List[str] = []
        try:
            with session.get(url, timeout=8, verify=verify, stream=True) as resp:
                if request.waf_evasion:
                    self._respect_waf_delay()
                chunk = resp.raw.read(65536)
                text = chunk.decode(errors="ignore").lower()
                for keyword in DOCUMENT_KEYWORDS:
                    if keyword in text:
                        keywords_found.append(keyword)
        except requests.RequestException:
            pass
        return DocumentFinding(
            url=url,
            extension=self._document_extension(url, request.document_extensions) or "FILE",
            source=source,
            size=size_int,
            keywords=keywords_found,
        )

    def _search_documents_duckduckgo(
        self,
        host: str,
        session: requests.Session,
        request: ScanRequest,
    ) -> List[DocumentFinding]:
        sanitized_host = host.lower()
        doc_terms = " OR ".join(f"filetype:{ext.lstrip('.')}" for ext in request.document_extensions)
        query = f"site:{sanitized_host} ({doc_terms})"
        params = {"q": query, "kl": "us-en", "ia": "web"}
        try:
            response = session.get(
                DUCKDUCKGO_ENDPOINT,
                params=params,
                timeout=10,
                verify=True,
            )
            if request.waf_evasion:
                self._respect_waf_delay()
        except requests.RequestException as exc:
            self.logger.debug(f"DuckDuckGo search failed: {exc}")
            return []

        matches = re.findall(
            r'<a[^>]+class="result__a[^"]*"[^>]+href="([^"]+)"',
            response.text,
            flags=re.IGNORECASE,
        )
        findings: List[DocumentFinding] = []
        for href in matches:
            target_url = self._resolve_duckduckgo_link(href)
            if not target_url:
                continue
            ext = self._document_extension(target_url, request.document_extensions)
            if not ext:
                continue
            parsed = urlparse(target_url)
            netloc = parsed.netloc.lower()
            if not (netloc == sanitized_host or netloc.endswith("." + sanitized_host)):
                continue
            doc_meta = self._inspect_document(session, target_url, True, request, "duckduckgo")
            if not doc_meta:
                doc_meta = DocumentFinding(url=target_url, extension=ext, source="duckduckgo")
            else:
                doc_meta.extension = ext
            findings.append(doc_meta)
            if len(findings) >= DOCUMENT_SEARCH_LIMIT:
                break

        # Link aggregator search (Linktree-style)
        aggregator_queries = [f"site:{domain} {sanitized_host}" for domain in LINK_AGGREGATOR_DOMAINS]
        for agg_query in aggregator_queries:
            agg_params = {"q": agg_query, "kl": "us-en", "ia": "web"}
            try:
                agg_resp = session.get(DUCKDUCKGO_ENDPOINT, params=agg_params, timeout=10, verify=True)
                if request.waf_evasion:
                    self._respect_waf_delay()
            except requests.RequestException:
                continue
            aggregator_matches = re.findall(
                r'<a[^>]+class="result__a[^"]*"[^>]+href="([^"]+)"',
                agg_resp.text,
                flags=re.IGNORECASE,
            )
            for href in aggregator_matches:
                landing_url = self._resolve_duckduckgo_link(href)
                if not landing_url:
                    continue
                doc_meta = self._inspect_document(session, landing_url, True, request, "linkhub")
                if doc_meta:
                    findings.append(doc_meta)
                else:
                    try:
                        landing_resp = session.get(landing_url, timeout=8, verify=True)
                        if request.waf_evasion:
                            self._respect_waf_delay()
                    except requests.RequestException:
                        continue
                    embedded_links = re.findall(r'href=\"(https?://[^\"]+)\"', landing_resp.text)
                    for candidate in embedded_links:
                        doc_ext = self._document_extension(candidate, request.document_extensions)
                        if doc_ext:
                            doc_meta = self._inspect_document(session, candidate, True, request, "linkhub")
                            if doc_meta:
                                findings.append(doc_meta)
                        if len(findings) >= DOCUMENT_SEARCH_LIMIT:
                            break
                if len(findings) >= DOCUMENT_SEARCH_LIMIT:
                    break
            if len(findings) >= DOCUMENT_SEARCH_LIMIT:
                break

        # Cloud storage search (S3, GCS, Azure)
        cloud_queries = [
            f"site:*.s3.amazonaws.com {sanitized_host}",
            f"site:storage.googleapis.com {sanitized_host}",
            f"site:blob.core.windows.net {sanitized_host}",
        ]
        for cloud_query in cloud_queries:
            cloud_params = {"q": cloud_query, "kl": "us-en", "ia": "web"}
            try:
                cloud_resp = session.get(DUCKDUCKGO_ENDPOINT, params=cloud_params, timeout=10, verify=True)
                if request.waf_evasion:
                    self._respect_waf_delay()
            except requests.RequestException:
                continue
            cloud_matches = re.findall(
                r'<a[^>]+class="result__a[^"]*"[^>]+href="([^"]+)"',
                cloud_resp.text,
                flags=re.IGNORECASE,
            )
            for href in cloud_matches:
                target_url = self._resolve_duckduckgo_link(href)
                if not target_url:
                    continue
                ext = self._document_extension(target_url, request.document_extensions)
                if not ext:
                    continue
                doc_meta = self._inspect_document(session, target_url, True, request, "cloud")
                if not doc_meta:
                    doc_meta = DocumentFinding(url=target_url, extension=ext, source="cloud")
                else:
                    doc_meta.extension = ext
                findings.append(doc_meta)
                if len(findings) >= DOCUMENT_SEARCH_LIMIT:
                    break
            if len(findings) >= DOCUMENT_SEARCH_LIMIT:
                break

        if findings:
            self.logger.info(f"DuckDuckGo returned {len(findings)} document leads.")
        else:
            self.logger.info("DuckDuckGo search returned no document leads.")
        return findings

    def _resolve_duckduckgo_link(self, href: str) -> Optional[str]:
        url = href
        if href.startswith("//"):
            url = f"https:{href}"
        elif href.startswith("/"):
            url = f"https://duckduckgo.com{href}"
        parsed = urlparse(url)
        if "duckduckgo.com" not in parsed.netloc:
            return url
        if parsed.path.startswith("/l/"):
            query = parse_qs(parsed.query)
            target_list = query.get("uddg")
            if target_list:
                target_url = unquote(target_list[0])
                if target_url.startswith("http"):
                    return target_url
        return None

    def _build_session(self, user_agent: str, waf_evasion: bool) -> requests.Session:
        session = requests.Session()
        ua = user_agent.strip() or DEFAULT_USER_AGENT
        headers = {
            "User-Agent": ua,
            "Accept": "text/html,application/json;q=0.9,*/*;q=0.8",
            "Connection": "close",
        }
        if waf_evasion:
            headers["User-Agent"] = random.choice(WAF_USER_AGENTS)
            headers["Accept-Language"] = random.choice(WAF_ACCEPT_LANGS)
            headers["X-Forwarded-For"] = self._random_ip()
            headers["X-Requested-With"] = "XMLHttpRequest"
            headers["Pragma"] = "no-cache"
            headers["Cache-Control"] = "no-cache"
        session.headers.update(headers)
        return session

    def _fetch_tls_profile(self, host: str) -> Optional[Dict[str, Any]]:
        context = ssl.create_default_context()
        try:
            with context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=host) as sock:
                sock.settimeout(4)
                sock.connect((host, 443))
                cipher = sock.cipher()
                version = sock.version()
                cert = sock.getpeercert()
        except OSError as exc:
            self.logger.warning(f"TLS profile fetch failed: {exc}")
            return None

        def _flatten(entity: List[tuple]) -> Dict[str, str]:
            flattened: Dict[str, str] = {}

            def _ingest(candidate) -> None:
                if (
                    isinstance(candidate, (tuple, list))
                    and len(candidate) == 2
                    and isinstance(candidate[0], str)
                ):
                    key, value = candidate
                    flattened[key] = str(value)

            for attribute in entity:
                if isinstance(attribute, (tuple, list)):
                    _ingest(attribute)
                    for sub in attribute:
                        _ingest(sub)
            return flattened

        san_entries = []
        for general_name in cert.get("subjectAltName", []):
            if isinstance(general_name, tuple) and len(general_name) == 2:
                san_entries.append(general_name[1])

        expiry = cert.get("notAfter")
        days_to_expiry: Optional[int] = None
        if expiry:
            try:
                expiry_dt = datetime.strptime(expiry, "%b %d %H:%M:%S %Y %Z")
                days_to_expiry = (expiry_dt - datetime.utcnow()).days
            except ValueError:
                days_to_expiry = None

        subject = _flatten(cert.get("subject", []))
        issuer = _flatten(cert.get("issuer", []))
        return {
            "version": version,
            "cipher": cipher[0] if cipher else "n/a",
            "subject": subject,
            "issuer": issuer,
            "notAfter": cert.get("notAfter"),
            "subjectAltName": san_entries,
            "days_to_expiry": days_to_expiry,
        }

    def _derive_insights(
        self,
        ports: List[Dict[str, Any]],
        http_metadata: Optional[Dict[str, Any]],
    ) -> List[str]:
        open_ports = {item["port"] for item in ports if item.get("open")}
        insights: List[str] = []
        if 23 in open_ports:
            insights.append("insight_telnet")
        if 3389 in open_ports:
            insights.append("insight_rdp")
        if 80 in open_ports and 443 not in open_ports:
            insights.append("insight_https")
        if http_metadata:
            if http_metadata.get("banner"):
                insights.append("insight_banner")
            status = http_metadata.get("status") or 0
            if status >= 400:
                insights.append("insight_error_rate")
        return insights

    def _match_keywords(self, text: str, keywords: List[str]) -> List[str]:
        lowered = text.lower()
        return [kw for kw in keywords if kw in lowered]

    def _infer_identifiers(
        self,
        http_metadata: Optional[Dict[str, Any]],
        tls_metadata: Optional[Dict[str, Any]],
        crawl_findings: List[CrawlFinding],
    ) -> tuple[Optional[str], Optional[str], Optional[str]]:
        tokens: List[str] = []
        runtime: Optional[str] = None

        def _append(value: Optional[str]) -> None:
            if value:
                tokens.append(value.lower())

        if http_metadata:
            for key in ("server", "powered_by", "banner"):
                _append(http_metadata.get(key))
            headers = http_metadata.get("headers", {})
            if isinstance(headers, dict):
                for header_key in ("Server", "X-Powered-By", "Via", "CF-RAY", "X-Cache"):
                    _append(headers.get(header_key))

        if tls_metadata:
            for key in ("subject", "issuer"):
                entity = tls_metadata.get(key, {})
                if isinstance(entity, dict):
                    for value in entity.values():
                        _append(str(value))

        for finding in crawl_findings:
            _append(finding.title)

        vendor: Optional[str] = None
        product: Optional[str] = None
        for signature, mapping in SERVER_SIGNATURES:
            signature_low = signature.lower()
            if any(signature_low in token for token in tokens):
                vendor, product = mapping
                break

        if not product and http_metadata and http_metadata.get("server"):
            product = http_metadata["server"].split()[0]

        if not vendor and product:
            vendor = product.split("/")[0]

        # Runtime detection (e.g., PHP)
        php_versions = [
            token
            for token in tokens
            if "php/" in token or token.startswith("php")
        ]
        if php_versions:
            version = php_versions[0].split("/")[-1]
            runtime = f"PHP {version}"
        elif http_metadata and http_metadata.get("powered_by"):
            runtime = http_metadata["powered_by"]

        return vendor, product, runtime


class AIAnalysisClient:
    """Dispatches scan summaries to external LLM providers."""

    def __init__(self, logger: DebugLogger) -> None:
        self.logger = logger
        self._gemini_model_cache: Dict[str, List[str]] = {}

    def summarize(
        self,
        settings: AISettings,
        result: ScanResult,
        cves: List[Dict[str, Any]],
    ) -> str:
        prompt = self._build_prompt(result, cves, settings.detail)
        token_budget = {"short": 350, "standard": 650, "verbose": 950}.get(settings.detail, 650)
        provider = settings.provider
        if provider == "openai":
            return self._call_openai(settings.api_key, prompt, settings.model, token_budget)
        if provider == "claude":
            return self._call_claude(settings.api_key, prompt, settings.model, token_budget)
        if provider == "gemini":
            resolved_model = self._resolve_gemini_model(settings.api_key, settings.model)
            return self._call_gemini(settings.api_key, prompt, resolved_model, token_budget)
        raise ValueError("AI provider is not enabled.")

    def _build_prompt(self, result: ScanResult, cves: List[Dict[str, Any]], detail: str) -> str:
        open_ports = [f"{item['port']}/{item['service']}" for item in result.ports if item.get("open")]
        insights = [item for item in result.insights]
        documents = [f"{doc.extension}: {doc.url}" for doc in result.documents[:6]]
        cve_lines = []
        for cve in cves[:5]:
            cve_lines.append(
                f"{cve.get('id')} | score {cve.get('score') or 'n/a'} | {cve.get('summary', '')[:180]}"
            )
        crawl_lines = []
        for finding in result.crawl_findings[:5]:
            crawl_lines.append(
                f"{finding.status} {finding.url} title={finding.title or 'n/a'} forms={finding.forms} scripts={finding.scripts}"
            )
        http_summary = "n/a"
        if result.http_metadata:
            http_summary = f"status {result.http_metadata.get('status')} server {result.http_metadata.get('server')} banner {result.http_metadata.get('banner')}"
        tls_summary = "n/a"
        if result.tls_metadata:
            tls_summary = f"{result.tls_metadata.get('version')} cipher {result.tls_metadata.get('cipher')}"

        prompt = [
            f"Host: {result.host or 'n/a'}",
            f"Scan level: {result.level.name}",
            f"Open ports: {open_ports or 'none'}",
            f"Insights: {insights or 'none'}",
            f"HTTP service: {http_summary}",
            f"TLS: {tls_summary}",
            f"Crawl (sample): {crawl_lines or 'none'}",
            f"Documents: {documents or 'none'}",
            f"CVE candidates: {cve_lines or 'none'}",
        ]
        extra = {
            "short": "Respond with 3 bullet points and a short mitigation checklist.",
            "standard": "Respond with a tight paragraph plus a three-step remediation plan.",
            "verbose": "Respond with a detailed assessment covering exposure, impact, and prioritized actions.",
        }.get(detail, "")
        instructions = (
            "You are a defensive security analyst. Summarize likely attack surface, "
            "highlight risky services, and suggest actionable mitigations. Avoid speculation "
            "beyond supplied data. "
            + extra
        )
        return instructions + "\n\n" + "\n".join(prompt)

    def _call_openai(self, api_key: str, prompt: str, model: Optional[str], max_tokens: int) -> str:
        url = "https://api.openai.com/v1/chat/completions"
        payload = {
            "model": model or AI_PROVIDER_DEFAULT_MODELS["openai"],
            "messages": [
                {"role": "system", "content": "You are a concise cybersecurity analyst."},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.3,
            "max_tokens": max_tokens,
        }
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        response = requests.post(url, headers=headers, json=payload, timeout=30)
        self._ensure_success(response, "openai")
        data = response.json()
        return data["choices"][0]["message"]["content"].strip()

    def _call_claude(self, api_key: str, prompt: str, model: Optional[str], max_tokens: int) -> str:
        url = "https://api.anthropic.com/v1/messages"
        payload = {
            "model": model or AI_PROVIDER_DEFAULT_MODELS["claude"],
            "max_tokens": max_tokens,
            "temperature": 0.3,
            "system": "You are a concise cybersecurity analyst.",
            "messages": [
                {"role": "user", "content": [{"type": "text", "text": prompt}]},
            ],
        }
        headers = {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }
        response = requests.post(url, headers=headers, json=payload, timeout=30)
        self._ensure_success(response, "claude")
        data = response.json()
        content = data["content"][0].get("text")
        if not content:
            raise ValueError("Claude response was empty.")
        return content.strip()

    def _call_gemini(self, api_key: str, prompt: str, model: str, max_tokens: int) -> str:
        model_name = model or AI_PROVIDER_DEFAULT_MODELS["gemini"]
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent"
        params = {"key": api_key}
        payload = {
            "contents": [
                {"parts": [{"text": prompt}]},
            ],
            "generationConfig": {"temperature": 0.3, "maxOutputTokens": max_tokens},
        }
        response = requests.post(url, params=params, json=payload, timeout=30)
        self._ensure_success(response, "gemini")
        data = response.json()
        candidates = data.get("candidates")
        if not candidates:
            raise ValueError("Gemini response missing candidates.")
        candidate = candidates[0]
        content = candidate.get("content") or {}
        parts = content.get("parts") or candidate.get("output", [])
        text_chunks: List[str] = []
        for part in parts:
            if isinstance(part, dict):
                if part.get("text"):
                    text_chunks.append(part["text"])
                elif "inlineData" in part and part["inlineData"].get("data"):
                    text_chunks.append(part["inlineData"]["data"])
            elif isinstance(part, str):
                text_chunks.append(part)
        if not text_chunks:
            raise ValueError("Gemini response missing content.")
        return "\n".join(text_chunks).strip()

    def _ensure_success(self, response: requests.Response, provider: str) -> None:
        try:
            response.raise_for_status()
        except requests.HTTPError as exc:
            message = ""
            try:
                payload = response.json()
                if isinstance(payload, dict):
                    if "error" in payload:
                        if isinstance(payload["error"], dict):
                            message = payload["error"].get("message") or payload["error"].get("type", "")
                        else:
                            message = str(payload["error"])
                    elif "message" in payload:
                        message = payload.get("message") or ""
            except ValueError:
                message = response.text[:200]
            if not message:
                message = str(exc)
            raise ValueError(f"{provider} API error ({response.status_code}): {message}") from exc

    def _resolve_gemini_model(self, api_key: str, preferred: Optional[str]) -> str:
        models = self._get_gemini_models(api_key)
        if preferred and preferred in models:
            return preferred
        if preferred and preferred not in models:
            self.logger.warning(f"Preferred Gemini model '{preferred}' unavailable; using {models[0]}.")
        return preferred or models[0]

    def _get_gemini_models(self, api_key: str) -> List[str]:
        cache_key = api_key[-6:] if api_key else "anon"
        models = self._gemini_model_cache.get(cache_key)
        if not models:
            try:
                resp = requests.get(
                    "https://generativelanguage.googleapis.com/v1beta/models",
                    params={"key": api_key},
                    timeout=15,
                )
                self._ensure_success(resp, "gemini")
                payload = resp.json()
                models = [
                    item["name"].split("/")[-1]
                    for item in payload.get("models", [])
                    if "generateContent" in item.get("supportedGenerationMethods", [])
                ]
                if not models:
                    models = [AI_PROVIDER_DEFAULT_MODELS["gemini"]]
                self._gemini_model_cache[cache_key] = models
            except Exception as exc:  # pragma: no cover
                self.logger.warning(f"Gemini model discovery failed: {exc}")
                return [AI_PROVIDER_DEFAULT_MODELS["gemini"]]
        return models

# =============================================================================
# GUI APPLICATION (Only define if Tkinter is available)
# =============================================================================

if _GUI_AVAILABLE:
    class ScannerApp(tk.Tk):
        """Main Tkinter application."""

    def __init__(self) -> None:
        super().__init__()
        self.translator = Translator(TRANSLATIONS)
        self.logger = DebugLogger()
        self.scanner = VulnerabilityScanner(self.logger)
        self.ai_client = AIAnalysisClient(self.logger)
        self.title(self.translator("app_title"))
        self.geometry("1024x720")
        self.minsize(900, 640)
        self.queue: queue.Queue = queue.Queue()
        self._status_key = "status_idle"
        self._label_widgets: Dict[str, ttk.Label] = {}
        self._level_display_map: Dict[str, ScanLevel] = {}
        self._build_ui()
        self.logger.subscribe(lambda message: self.queue.put({"type": "log", "payload": message}))
        self.after(150, self._process_queue)
        self.current_thread: Optional[threading.Thread] = None

    def _build_ui(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        self.target_var = tk.StringVar()
        self.vendor_var = tk.StringVar()
        self.product_var = tk.StringVar()
        self.user_agent_var = tk.StringVar(value=DEFAULT_USER_AGENT)
        self.language_var = tk.StringVar(value=self.translator.current)
        self.debug_var = tk.BooleanVar(value=False)
        self.waf_var = tk.BooleanVar(value=True)
        self.crawl_var = tk.BooleanVar(value=False)
        self.crawl_depth_var = tk.IntVar(value=1)
        self.crawl_keywords_var = tk.StringVar()
        self.doc_extensions_var = tk.StringVar(value="pdf,doc,docx,ppt,pptx,txt")
        self.ai_provider_var = tk.StringVar()
        self.ai_key_var = tk.StringVar()
        self.ai_detail_var = tk.StringVar()
        self.level_var = tk.StringVar()
        self._ai_display_map: Dict[str, str] = {}
        self._ai_detail_map: Dict[str, str] = {}
        self._config_data: Dict[str, Any] = {}
        self._config_file = self._default_config_path()
        self._pending_config = self._load_config()
        self._ai_last_summary = ""
        self.social_enable_vars: Dict[str, tk.BooleanVar] = {}
        self.social_api_vars: Dict[str, tk.StringVar] = {}
        self.social_secret_vars: Dict[str, tk.StringVar] = {}
        self.social_handle_vars: Dict[str, tk.StringVar] = {}

        form = ttk.Frame(self, padding=12)
        form.grid(row=0, column=0, sticky="ew")
        form.columnconfigure(1, weight=1)
        form.columnconfigure(3, weight=1)

        self._add_labeled_entry(form, 0, self.target_var, "target_label")
        self._add_labeled_entry(form, 1, self.vendor_var, "vendor_label")
        self._add_labeled_entry(form, 2, self.product_var, "product_label")
        self._add_labeled_entry(form, 3, self.user_agent_var, "user_agent_label")

        self._label_widgets["level_label"] = ttk.Label(form, text=self.translator("level_label"))
        self._label_widgets["level_label"].grid(row=4, column=0, sticky="w", pady=4)
        self.level_select = ttk.Combobox(form, textvariable=self.level_var, state="readonly", width=18)
        self.level_select.grid(row=4, column=1, sticky="ew", pady=4)
        self._configure_level_options()

        self._label_widgets["language_label"] = ttk.Label(form, text=self.translator("language_label"))
        self._label_widgets["language_label"].grid(row=4, column=2, sticky="w", padx=(12, 0))
        self.lang_select = ttk.Combobox(
            form,
            textvariable=self.language_var,
            values=["en", "id"],
            state="readonly",
            width=10,
        )
        self.lang_select.grid(row=4, column=3, sticky="w", pady=4)
        self.lang_select.bind("<<ComboboxSelected>>", lambda _event: self._update_language())

        self.debug_check = ttk.Checkbutton(
            form,
            text=self.translator("debug_label"),
            variable=self.debug_var,
            command=self._toggle_debug,
        )
        self.debug_check.grid(row=5, column=0, sticky="w", pady=4)

        self.status_var = tk.StringVar(value=self.translator("status_idle"))
        self.status_label = ttk.Label(form, textvariable=self.status_var)
        self.status_label.grid(row=5, column=1, sticky="w")

        self.start_button = ttk.Button(form, text=self.translator("start_button"), command=self._start_scan)
        self.start_button.grid(row=5, column=3, sticky="e")

        self.waf_check = ttk.Checkbutton(form, text=self.translator("waf_label"), variable=self.waf_var)
        self.waf_check.grid(row=6, column=0, sticky="w", pady=4)

        self.crawl_check = ttk.Checkbutton(form, text=self.translator("crawl_label"), variable=self.crawl_var)
        self.crawl_check.grid(row=6, column=1, sticky="w", pady=4)

        crawl_depth_label = ttk.Label(form, text=self.translator("crawl_depth_label"))
        crawl_depth_label.grid(row=6, column=2, sticky="e", padx=(12, 0))
        self._label_widgets["crawl_depth_label"] = crawl_depth_label

        SpinboxWidget = getattr(ttk, "Spinbox", tk.Spinbox)
        spinbox_kwargs = {
            "from_": 1,
            "to": 4,
            "textvariable": self.crawl_depth_var,
            "width": 5,
            "state": "readonly",
        }
        if SpinboxWidget is tk.Spinbox:
            spinbox_kwargs.pop("state", None)
        self.crawl_depth_spin = SpinboxWidget(form, **spinbox_kwargs)
        self.crawl_depth_spin.grid(row=6, column=3, sticky="w", pady=4)

        self._label_widgets["crawl_keywords_label"] = ttk.Label(form, text=self.translator("crawl_keywords_label"))
        self._label_widgets["crawl_keywords_label"].grid(row=7, column=0, sticky="w", pady=4)
        self.crawl_keywords_entry = ttk.Entry(form, textvariable=self.crawl_keywords_var)
        self.crawl_keywords_entry.grid(row=7, column=1, sticky="ew", pady=4)

        self._label_widgets["doc_ext_label"] = ttk.Label(form, text=self.translator("doc_ext_label"))
        self._label_widgets["doc_ext_label"].grid(row=7, column=2, sticky="w", padx=(12, 0))
        self.doc_ext_entry = ttk.Entry(form, textvariable=self.doc_extensions_var)
        self.doc_ext_entry.grid(row=7, column=3, sticky="ew", pady=4)

        self._label_widgets["ai_label"] = ttk.Label(form, text=self.translator("ai_label"))
        self._label_widgets["ai_label"].grid(row=8, column=0, sticky="w", pady=4)

        self.ai_provider_select = ttk.Combobox(form, textvariable=self.ai_provider_var, state="readonly", width=20)
        self.ai_provider_select.grid(row=8, column=1, sticky="ew", pady=4)
        self._configure_ai_provider_options()

        self._label_widgets["ai_key_label"] = ttk.Label(form, text=self.translator("ai_key_label"))
        self._label_widgets["ai_key_label"].grid(row=8, column=2, sticky="e", padx=(12, 0))

        self.ai_key_entry = ttk.Entry(form, textvariable=self.ai_key_var, show="*")
        self.ai_key_entry.grid(row=8, column=3, sticky="ew", pady=4)

        self._label_widgets["ai_detail_label"] = ttk.Label(form, text=self.translator("ai_detail_label"))
        self._label_widgets["ai_detail_label"].grid(row=9, column=0, sticky="w", pady=4)
        self.ai_detail_select = ttk.Combobox(
            form,
            textvariable=self.ai_detail_var,
            state="readonly",
            values=[
                self.translator("ai_detail_short"),
                self.translator("ai_detail_standard"),
                self.translator("ai_detail_verbose"),
            ],
        )
        self.ai_detail_select.grid(row=9, column=1, sticky="w", pady=4)
        if not self.ai_detail_var.get():
            self.ai_detail_var.set(self.translator("ai_detail_standard"))
        self._configure_ai_detail_options()

        self.progress = ttk.Progressbar(form, mode="indeterminate")
        self.progress.grid(row=10, column=0, columnspan=4, sticky="ew", pady=(8, 0))

        self.notebook = ttk.Notebook(self)
        self.notebook.grid(row=1, column=0, sticky="nsew", padx=12, pady=12)

        self.log_text = tk.Text(self.notebook, wrap="word")
        self.log_text.insert("1.0", self.translator("placeholder_results"))
        self.log_text.configure(state="disabled")

        self.cve_text = tk.Text(self.notebook, wrap="word")
        self.cve_text.insert("1.0", self.translator("cve_loading"))
        self.cve_text.configure(state="disabled")

        self.ai_text = tk.Text(self.notebook, wrap="word")
        self.ai_text.insert("1.0", self.translator("ai_placeholder"))
        self.ai_text.configure(state="disabled")

        self.notebook.add(self.log_text, text=self.translator("log_tab"))
        self.notebook.add(self.cve_text, text=self.translator("cve_tab"))
        self.notebook.add(self.ai_text, text=self.translator("ai_tab"))
        self._apply_config()

    def _add_labeled_entry(self, parent: ttk.Frame, row: int, variable: tk.StringVar, label_key: str) -> None:
        label = ttk.Label(parent, text=self.translator(label_key))
        label.grid(row=row, column=0, sticky="w", pady=4)
        self._label_widgets[label_key] = label
        entry = ttk.Entry(parent, textvariable=variable)
        entry.grid(row=row, column=1, columnspan=3, sticky="ew", pady=4, padx=(0, 8))

    def _toggle_debug(self) -> None:
        enabled = self.debug_var.get()
        self.logger.set_enabled(enabled)
        tooltip = self.translator("debug_tooltip")
        self.logger.info(f"Debug logging {'enabled' if enabled else 'disabled'} – {tooltip}")

    def _update_language(self) -> None:
        self.translator.set_language(self.language_var.get())
        self._refresh_language_texts()

    def _set_status(self, key: str) -> None:
        self._status_key = key
        self.status_var.set(self.translator(key))

    def _start_scan(self) -> None:
        target = self.target_var.get().strip()
        keyword = self.product_var.get().strip()
        if not target and not keyword:
            messagebox.showwarning(self.translator("scan_failed"), self.translator("input_error"))
            return

        level = self._level_display_map.get(self.level_var.get(), ScanLevel.BASIC)

        crawl_depth = max(1, min(4, self.crawl_depth_var.get()))
        crawl_keywords = [
            token.strip().lower()
            for token in self.crawl_keywords_var.get().split(",")
            if token.strip()
        ]
        doc_extensions = [
            token.strip().lower()
            for token in self.doc_extensions_var.get().split(",")
            if token.strip()
        ] or list(DEFAULT_DOCUMENT_EXTENSIONS)
        crawl_settings = CrawlSettings(
            enabled=self.crawl_var.get(),
            max_depth=crawl_depth,
            max_pages=max(12, crawl_depth * 10),
            keywords=crawl_keywords or list(DEFAULT_CRAWL_KEYWORDS),
        )

        request = ScanRequest(
            target=target,
            vendor=self.vendor_var.get().strip(),
            product=keyword,
            scan_level=level,
            user_agent=self.user_agent_var.get().strip() or DEFAULT_USER_AGENT,
            debug_enabled=self.debug_var.get(),
            waf_evasion=self.waf_var.get(),
            crawl=crawl_settings,
            document_extensions=doc_extensions,
            social=self._collect_social_settings(),
        )
        self.logger.set_enabled(request.debug_enabled)
        waf_status = "waf_enabled_status" if request.waf_evasion else "waf_disabled_status"
        self.logger.info(self.translator(waf_status))
        self._set_status("status_running")
        self.start_button.configure(state="disabled")
        self.progress.start(10)
        self._clear_text_widgets()

        self.current_thread = threading.Thread(target=self._run_scan, args=(request,), daemon=True)
        self.current_thread.start()
        self._save_config()

    def _configure_level_options(self, keep_current: bool = False) -> None:
        previous_level = self._level_display_map.get(self.level_var.get()) if keep_current else None
        self._level_display_map = {self.translator(level.label_key): level for level in ScanLevel}
        values = list(self._level_display_map.keys())
        self.level_select.configure(values=values)
        if keep_current and previous_level:
            for label, level in self._level_display_map.items():
                if level == previous_level:
                    self.level_var.set(label)
                    break
        elif not self.level_var.get():
            self.level_var.set(values[0])

    def _configure_ai_provider_options(self, keep_current: bool = False) -> None:
        provider_map: Dict[str, str] = {}
        values: List[str] = []
        for provider in ["none", "openai", "claude", "gemini"]:
            label = self.translator(f"ai_provider_{provider}")
            provider_map[label] = provider
            values.append(label)
        previous = self._ai_display_map.get(self.ai_provider_var.get()) if keep_current else None
        self._ai_display_map = provider_map
        self.ai_provider_select.configure(values=values)
        if keep_current and previous:
            for display, code in provider_map.items():
                if code == previous:
                    self.ai_provider_var.set(display)
                    break
        elif not self.ai_provider_var.get():
            self.ai_provider_var.set(values[0])

    def _configure_ai_detail_options(self, keep_current: bool = False) -> None:
        detail_pairs = [
            ("short", self.translator("ai_detail_short")),
            ("standard", self.translator("ai_detail_standard")),
            ("verbose", self.translator("ai_detail_verbose")),
        ]
        previous_code = self._ai_detail_map.get(self.ai_detail_var.get()) if keep_current else None
        self._ai_detail_map = {label: code for code, label in detail_pairs}
        self.ai_detail_select.configure(values=[label for _code, label in detail_pairs])
        if keep_current and previous_code:
            for label, code in self._ai_detail_map.items():
                if code == previous_code:
                    self.ai_detail_var.set(label)
                    break
        elif not self.ai_detail_var.get():
            self.ai_detail_var.set(detail_pairs[1][1])

    def _collect_ai_settings(self) -> tuple[AISettings, Optional[str]]:
        provider_display = self.ai_provider_var.get()
        provider_code = self._ai_display_map.get(provider_display, "none")
        api_key = self.ai_key_var.get().strip()
        model = AI_PROVIDER_DEFAULT_MODELS.get(provider_code)
        detail_label = self.ai_detail_var.get()
        detail_code = self._ai_detail_map.get(detail_label, "standard")
        enabled = provider_code != "none" and bool(api_key)
        if provider_code == "none":
            return AISettings(provider_code, api_key, False, model, detail_code), "disabled"
        if not api_key:
            return AISettings(provider_code, api_key, False, model, detail_code), "missing_key"
        return AISettings(provider_code, api_key, enabled, model, detail_code), None

    def _collect_social_settings(self) -> SocialConfig:
        providers: Dict[str, SocialProviderSettings] = {}
        for provider in SOCIAL_PLATFORMS:
            enabled_var = self.social_enable_vars.get(provider)
            api_var = self.social_api_vars.get(provider)
            secret_var = self.social_secret_vars.get(provider)
            handle_var = self.social_handle_vars.get(provider)
            providers[provider] = SocialProviderSettings(
                enabled=enabled_var.get() if enabled_var else False,
                api_key=api_var.get().strip() if api_var else "",
                secret=secret_var.get().strip() if secret_var else "",
                handle=handle_var.get().strip() if handle_var else "",
            )
        return SocialConfig(providers=providers)

    def _refresh_language_texts(self) -> None:
        self.title(self.translator("app_title"))
        for key, label in self._label_widgets.items():
            label.configure(text=self.translator(key))
        self.debug_check.configure(text=self.translator("debug_label"))
        self.waf_check.configure(text=self.translator("waf_label"))
        self.crawl_check.configure(text=self.translator("crawl_label"))
        self.start_button.configure(text=self.translator("start_button"))
        self.status_var.set(self.translator(self._status_key))
        self._configure_level_options(keep_current=True)
        self._configure_ai_provider_options(keep_current=True)
        self._configure_ai_detail_options(keep_current=True)
        self.notebook.tab(0, text=self.translator("log_tab"))
        self.notebook.tab(1, text=self.translator("cve_tab"))
        self.notebook.tab(2, text=self.translator("ai_tab"))

    def _clear_text_widgets(self) -> None:
        for widget in (self.log_text, self.cve_text, self.ai_text):
            widget.configure(state="normal")
            widget.delete("1.0", tk.END)
            if widget is self.log_text:
                widget.insert("1.0", self.translator("placeholder_results"))
            elif widget is self.cve_text:
                widget.insert("1.0", self.translator("cve_loading"))
            else:
                widget.insert("1.0", self.translator("ai_placeholder"))
            widget.configure(state="disabled")
        self._ai_last_summary = ""

    def _default_config_path(self) -> Path:
        base = Path.home() / ".makassarscan"
        base.mkdir(parents=True, exist_ok=True)
        return base / "config.json"

    def _load_config(self) -> Dict[str, Any]:
        try:
            with self._config_file.open("r", encoding="utf-8") as handle:
                return json.load(handle)
        except FileNotFoundError:
            return {}
        except json.JSONDecodeError:
            self.logger.warning("Config file is corrupted; ignoring.")
            return {}

    def _apply_config(self) -> None:
        data = self._pending_config
        if not data:
            return
        if data.get("doc_extensions"):
            self.doc_extensions_var.set(data["doc_extensions"])
        if data.get("crawl_keywords"):
            self.crawl_keywords_var.set(data["crawl_keywords"])
        if data.get("ai_key"):
            self.ai_key_var.set(data["ai_key"])
        provider_code = data.get("ai_provider")
        if provider_code:
            for label, code in self._ai_display_map.items():
                if code == provider_code:
                    self.ai_provider_var.set(label)
                    break
        detail_code = data.get("ai_detail")
        if detail_code:
            for label, code in self._ai_detail_map.items():
                if code == detail_code:
                    self.ai_detail_var.set(label)
                    break

    def _save_config(self) -> None:
        data = {
            "doc_extensions": self.doc_extensions_var.get(),
            "crawl_keywords": self.crawl_keywords_var.get(),
            "ai_provider": self._ai_display_map.get(self.ai_provider_var.get(), "none"),
            "ai_key": self.ai_key_var.get().strip(),
            "ai_detail": self._ai_detail_map.get(self.ai_detail_var.get(), "standard"),
        }
        with self._config_file.open("w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2)

    def _run_scan(self, request: ScanRequest) -> None:
        try:
            result = self.scanner.run_scan(request)
            self.queue.put({"type": "result", "payload": result})
            vendor_term = request.vendor or result.identified_vendor or ""
            product_term = request.product or result.identified_product or ""
            keyword = " ".join(part for part in (vendor_term, product_term) if part.strip())
            if not keyword:
                keyword = result.host or request.target
            cves = self.scanner.fetch_cves(keyword or "", request.user_agent)
            self.queue.put({"type": "cves", "payload": cves})
            ai_settings, ai_state = self._collect_ai_settings()
            if ai_state == "disabled":
                self.queue.put({"type": "ai", "payload": {"state": "disabled"}})
            elif ai_state == "missing_key":
                self.queue.put({"type": "ai", "payload": {"state": "missing_key"}})
            elif ai_settings.enabled:
                self.queue.put({"type": "ai", "payload": {"state": "waiting"}})
                try:
                    summary = self.ai_client.summarize(ai_settings, result, cves)
                    self.queue.put({"type": "ai", "payload": {"state": "result", "text": summary}})
                except Exception as exc:  # pragma: no cover - remote API variability
                    self.logger.error(f"AI analysis failed: {exc}")
                    self.queue.put({"type": "ai", "payload": {"state": "error", "error": str(exc)}})
        except requests.RequestException as exc:
            self.queue.put({"type": "error", "payload": f"Network error: {exc}"})
        except Exception as exc:  # pragma: no cover - guard for unforeseen issues
            self.queue.put({"type": "error", "payload": str(exc)})

    def _process_queue(self) -> None:
        while True:
            try:
                item = self.queue.get_nowait()
            except queue.Empty:
                break

            if item["type"] == "log":
                self._append_text(self.log_text, item["payload"])
            elif item["type"] == "result":
                self._render_result(item["payload"])
            elif item["type"] == "cves":
                self._render_cves(item["payload"])
            elif item["type"] == "ai":
                self._handle_ai_message(item["payload"])
            elif item["type"] == "error":
                self._append_text(self.log_text, item["payload"])
                messagebox.showerror(self.translator("scan_failed"), item["payload"])
                self.progress.stop()
                self.start_button.configure(state="normal")
                self._set_status("status_idle")
            self.queue.task_done()
        self.after(150, self._process_queue)

    def _append_text(self, widget: tk.Text, message: str) -> None:
        widget.configure(state="normal")
        widget.insert(tk.END, message + "\n")
        widget.see(tk.END)
        widget.configure(state="disabled")

    def _set_ai_text(self, text: str) -> None:
        self.ai_text.configure(state="normal")
        self.ai_text.delete("1.0", tk.END)
        self.ai_text.insert("1.0", text.strip())
        self.ai_text.configure(state="disabled")

    def _handle_ai_message(self, payload: Dict[str, Any]) -> None:
        state = payload.get("state")
        if state == "waiting":
            text = self.translator("ai_status_wait")
        elif state == "disabled":
            text = self.translator("ai_status_disabled")
        elif state == "missing_key":
            text = self.translator("ai_status_missing_key")
        elif state == "error":
            error_text = self.translator("ai_error").format(error=payload.get("error", "unknown"))
            if self._ai_last_summary:
                text = f"{self._ai_last_summary}\n\n{error_text}"
            else:
                text = error_text
        elif state == "result":
            text = payload.get("text") or self.translator("ai_error").format(error="empty response")
            self._ai_last_summary = text
        else:
            text = self.translator("ai_placeholder")
        self._set_ai_text(text)

    def _render_result(self, result: ScanResult) -> None:
        lines = []
        if result.host:
            level_label = self.translator(result.level.label_key)
            intro = self.translator("scan_intro").format(
                level=level_label,
                seconds=result.duration,
                host=result.host,
            )
            lines.append(intro)
        else:
            lines.append(self.translator("placeholder_results"))

        waf_line = "• " + (
            self.translator("waf_enabled_status") if result.waf_evasion else self.translator("waf_disabled_status")
        )
        lines.append(waf_line)

        if result.identified_vendor and not self.vendor_var.get().strip():
            self.vendor_var.set(result.identified_vendor)
        if result.identified_product and not self.product_var.get().strip():
            self.product_var.set(result.identified_product)

        lines.append(self.translator("detected_section") + ":")
        if result.identified_vendor:
            lines.append(" • " + self.translator("detected_vendor").format(vendor=result.identified_vendor))
        if result.identified_product:
            lines.append(" • " + self.translator("detected_product").format(product=result.identified_product))
        if result.identified_runtime:
            lines.append(" • " + self.translator("detected_runtime").format(runtime=result.identified_runtime))
        if not result.identified_vendor and not result.identified_product:
            lines.append(" • " + self.translator("detected_missing"))

        for port in result.ports:
            key = "port_open" if port["open"] else "port_closed"
            lines.append(
                self.translator(key).format(port=port["port"], service=port["service"])
            )

        if result.http_metadata:
            meta = result.http_metadata
            server = meta.get("server") or "n/a"
            lines.append(
                self.translator("http_summary").format(
                    status=meta.get("status"),
                    url=meta.get("url"),
                    server=server,
                )
            )
            if meta.get("powered_by"):
                label = self.translator("powered_by_label")
                lines.append(f"{label}: {meta['powered_by']}")

        if result.tls_metadata:
            tls = result.tls_metadata
            lines.append(
                self.translator("tls_summary").format(
                    version=tls.get("version", "n/a"),
                    cipher=tls.get("cipher", "n/a"),
                )
            )
            subj_label = self.translator("tls_subject_label")
            issuer_label = self.translator("tls_issuer_label")
            expiry_label = self.translator("tls_expiry_label")
            lines.append(f"{subj_label}: {json.dumps(tls.get('subject', {}))}")
            lines.append(f"{issuer_label}: {json.dumps(tls.get('issuer', {}))}")
            lines.append(f"{expiry_label}: {tls.get('notAfter')}")

        if result.insights:
            lines.append(self.translator("insights_title") + ":")
            for insight_key in result.insights:
                lines.append(f" • {self.translator(insight_key)}")
        else:
            lines.append(self.translator("insights_none"))

        if result.services:
            lines.append("Service highlights:")
            for service in result.services:
                detail_parts = [f"{key}: {value}" for key, value in service.detail.items()]
                lines.append(f" • {service.name} -> " + "; ".join(detail_parts))

        lines.append(self.translator("crawl_title") + ":")
        if result.crawl_findings:
            summary = self.translator("crawl_summary").format(
                pages=len(result.crawl_findings),
                depth=result.crawl_settings.max_depth,
            )
            lines.append(f" • {summary}")
            for finding in result.crawl_findings:
                entry = self.translator("crawl_entry").format(
                    url=finding.url,
                    status=finding.status or "n/a",
                    title=finding.title or "n/a",
                    forms=finding.forms,
                    scripts=finding.scripts,
                )
                extra_parts: List[str] = []
                if finding.post_forms:
                    extra_parts.append(f"POST forms: {finding.post_forms}")
                if finding.password_fields:
                    extra_parts.append(f"password fields: {finding.password_fields}")
                if finding.file_fields:
                    extra_parts.append(f"file inputs: {finding.file_fields}")
                if finding.query_params:
                    extra_parts.append(f"query params: {finding.query_params}")
                if finding.flags:
                    extra_parts.append("flags: " + ", ".join(finding.flags))
                if extra_parts:
                    entry += " | " + " | ".join(extra_parts)
                lines.append(f"   - {entry}")
        else:
            lines.append(f" • {self.translator('crawl_disabled')}")

        lines.append(self.translator("docs_title") + ":")
        if result.documents:
            for doc in result.documents:
                source_key = f"doc_source_{doc.source}"
                source_label = self.translator(source_key)
                if source_label == source_key:
                    source_label = doc.source
                entry = self.translator("docs_entry").format(
                    ext=doc.extension,
                    url=doc.url,
                    source=source_label,
                )
                extra_bits = []
                if doc.size:
                    extra_bits.append(f"{doc.size} bytes")
                if doc.keywords:
                    extra_bits.append("tags: " + ", ".join(doc.keywords))
                if extra_bits:
                    entry += " | " + " | ".join(extra_bits)
                lines.append(" • " + entry)
        else:
            lines.append(" • " + self.translator("docs_none"))

        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", tk.END)
        self.log_text.insert("1.0", "\n".join(lines))
        self.log_text.configure(state="disabled")

        self.progress.stop()
        self.start_button.configure(state="normal")
        self._set_status("status_done")

    def _render_cves(self, cves: List[Dict[str, Any]]) -> None:
        self.cve_text.configure(state="normal")
        self.cve_text.delete("1.0", tk.END)
        if not cves:
            self.cve_text.insert("1.0", self.translator("no_cves"))
        else:
            title = self.translator("cve_title")
            self.cve_text.insert(tk.END, f"{title}\n\n")
            for cve in cves:
                score = cve.get("score")
                line = f"{cve.get('id')} | CVSS: {score or 'n/a'} | {cve.get('published')}"
                self.cve_text.insert(tk.END, line + "\n")
                self.cve_text.insert(tk.END, f"{cve.get('summary')}\n")
                for ref in cve.get("references", []):
                    self.cve_text.insert(tk.END, f"  - {ref}\n")
                self.cve_text.insert(tk.END, "\n")
        self.cve_text.configure(state="disabled")


def main() -> None:
    """Launch the GUI application."""
    if not _GUI_AVAILABLE:
        print("Error: Tkinter is not available. Use --cli mode instead.")
        print("Usage: python app.py --cli <target>")
        sys.exit(1)
    app = ScannerApp()
    app.mainloop()


# =============================================================================
# SUBDOMAIN ENUMERATION
# =============================================================================

class SubdomainEnumerator:
    """Discovers subdomains via Certificate Transparency logs."""

    def __init__(self, logger: DebugLogger) -> None:
        self.logger = logger
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": DEFAULT_USER_AGENT})

    def enumerate(self, domain: str, resolve_dns: bool = True) -> List[Dict[str, Any]]:
        """Enumerate subdomains for a given domain using crt.sh."""
        domain = domain.strip().lower()
        if domain.startswith("www."):
            domain = domain[4:]
        
        self.logger.info(f"Enumerating subdomains for: {domain}")
        subdomains: Set[str] = set()
        
        # crt.sh Certificate Transparency lookup
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = self._session.get(url, timeout=30)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lower()
                        if sub and sub.endswith(domain) and "*" not in sub:
                            subdomains.add(sub)
                self.logger.info(f"Found {len(subdomains)} unique subdomains from crt.sh")
        except Exception as exc:
            self.logger.warning(f"crt.sh lookup failed: {exc}")
        
        # Resolve DNS if requested
        results: List[Dict[str, Any]] = []
        for subdomain in sorted(subdomains):
            entry = {"subdomain": subdomain, "resolved": False, "ips": []}
            if resolve_dns:
                try:
                    if _DNS_AVAILABLE:
                        answers = dns.resolver.resolve(subdomain, "A")
                        entry["ips"] = [str(rdata) for rdata in answers]
                        entry["resolved"] = True
                    else:
                        ip = socket.gethostbyname(subdomain)
                        entry["ips"] = [ip]
                        entry["resolved"] = True
                except Exception:
                    pass
            results.append(entry)
        
        resolved_count = sum(1 for r in results if r["resolved"])
        self.logger.info(f"Resolved {resolved_count}/{len(results)} subdomains to IP addresses")
        return results


# =============================================================================
# CVE CACHE (SQLite)
# =============================================================================

class CVECache:
    """Local SQLite cache for CVE data to enable offline scanning."""

    def __init__(self, cache_dir: Optional[Path] = None) -> None:
        self.cache_dir = cache_dir or get_cache_dir()
        self.db_path = self.cache_dir / "cve_cache.db"
        self._init_db()

    def _init_db(self) -> None:
        """Initialize the SQLite database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cves (
                    keyword TEXT NOT NULL,
                    cve_id TEXT NOT NULL,
                    score REAL,
                    summary TEXT,
                    published TEXT,
                    refs TEXT,
                    cached_at TEXT NOT NULL,
                    PRIMARY KEY (keyword, cve_id)
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_keyword ON cves(keyword)
            """)
            conn.commit()

    def get(self, keyword: str, max_age_hours: int = 24) -> Optional[List[Dict[str, Any]]]:
        """Get cached CVEs for a keyword if not expired."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT cve_id, score, summary, published, refs, cached_at "
                "FROM cves WHERE keyword = ?",
                (keyword.lower(),)
            )
            rows = cursor.fetchall()
            
            if not rows:
                return None
            
            # Check if cache is expired
            cached_at = datetime.fromisoformat(rows[0][5])
            if datetime.now() - cached_at > timedelta(hours=max_age_hours):
                return None
            
            results = []
            for row in rows:
                results.append({
                    "id": row[0],
                    "score": row[1],
                    "summary": row[2],
                    "published": row[3],
                    "references": json.loads(row[4]) if row[4] else [],
                })
            return results

    def set(self, keyword: str, cves: List[Dict[str, Any]]) -> None:
        """Cache CVE results for a keyword."""
        with sqlite3.connect(self.db_path) as conn:
            # Clear existing entries
            conn.execute("DELETE FROM cves WHERE keyword = ?", (keyword.lower(),))
            
            # Insert new entries
            cached_at = datetime.now().isoformat()
            for cve in cves:
                conn.execute(
                    "INSERT INTO cves (keyword, cve_id, score, summary, published, refs, cached_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        keyword.lower(),
                        cve.get("id", ""),
                        cve.get("score"),
                        cve.get("summary", ""),
                        cve.get("published", ""),
                        json.dumps(cve.get("references", [])),
                        cached_at,
                    )
                )
            conn.commit()

    def clear(self) -> None:
        """Clear all cached data."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM cves")
            conn.commit()


# =============================================================================
# TECHNOLOGY FINGERPRINTING
# =============================================================================

class TechFingerprinter:
    """Enhanced technology stack detection."""

    def __init__(self, logger: DebugLogger) -> None:
        self.logger = logger

    def fingerprint(
        self,
        html_content: str,
        headers: Dict[str, str],
        cookies: Dict[str, str],
    ) -> List[Dict[str, Any]]:
        """Detect technologies from response data."""
        detected: List[Dict[str, Any]] = []
        html_lower = html_content.lower()
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        
        for tech_name, patterns in TECH_FINGERPRINTS.items():
            confidence = 0
            matches = []
            
            # Check headers
            for header_pattern in patterns.get("headers", []):
                for header_key, header_val in headers_lower.items():
                    combined = f"{header_key}: {header_val}"
                    if header_pattern.lower() in combined:
                        confidence += 30
                        matches.append(f"header: {header_pattern}")
            
            # Check HTML patterns
            for pattern in patterns.get("html_patterns", []):
                if re.search(pattern, html_lower, re.IGNORECASE):
                    confidence += 20
                    matches.append(f"html: {pattern}")
            
            # Check meta generators
            for generator in patterns.get("meta_generators", []):
                if f'content="{generator.lower()}' in html_lower or \
                   f"content='{generator.lower()}" in html_lower:
                    confidence += 40
                    matches.append(f"generator: {generator}")
            
            # Check cookies
            for cookie_name in patterns.get("cookies", []):
                if cookie_name.lower() in [c.lower() for c in cookies.keys()]:
                    confidence += 25
                    matches.append(f"cookie: {cookie_name}")
            
            if confidence > 0:
                detected.append({
                    "technology": tech_name,
                    "confidence": min(confidence, 100),
                    "matches": matches,
                })
        
        # Sort by confidence
        detected.sort(key=lambda x: x["confidence"], reverse=True)
        return detected


# =============================================================================
# EXPORT FUNCTIONALITY
# =============================================================================

class ReportExporter:
    """Export scan results to various formats."""

    def __init__(self, logger: DebugLogger) -> None:
        self.logger = logger

    def export_json(self, result: ScanResult, cves: List[Dict[str, Any]], filepath: Path) -> None:
        """Export results to JSON format."""
        data = self._build_report_data(result, cves)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        self.logger.info(f"Exported JSON report to: {filepath}")

    def export_html(self, result: ScanResult, cves: List[Dict[str, Any]], filepath: Path) -> None:
        """Export results to HTML format."""
        data = self._build_report_data(result, cves)
        html = self._generate_html_report(data)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)
        self.logger.info(f"Exported HTML report to: {filepath}")

    def export_markdown(self, result: ScanResult, cves: List[Dict[str, Any]], filepath: Path) -> None:
        """Export results to Markdown format."""
        data = self._build_report_data(result, cves)
        md = self._generate_markdown_report(data)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(md)
        self.logger.info(f"Exported Markdown report to: {filepath}")

    def export_csv(self, result: ScanResult, cves: List[Dict[str, Any]], filepath: Path) -> None:
        """Export results to CSV format."""
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            
            # Header
            writer.writerow(["Category", "Type", "Value", "Details"])
            
            # Host info
            writer.writerow(["Host", "Target", result.host or "N/A", ""])
            writer.writerow(["Scan", "Level", result.level.name, f"Duration: {result.duration:.1f}s"])
            
            # Ports
            for port in result.ports:
                status = "OPEN" if port.get("open") else "CLOSED"
                writer.writerow(["Port", str(port["port"]), port["service"], status])
            
            # CVEs
            for cve in cves:
                writer.writerow([
                    "CVE",
                    cve.get("id", ""),
                    f"CVSS: {cve.get('score', 'N/A')}",
                    cve.get("summary", "")[:200]
                ])
            
            # Documents
            for doc in result.documents:
                writer.writerow(["Document", doc.extension, doc.url, doc.source])
        
        self.logger.info(f"Exported CSV report to: {filepath}")

    def _build_report_data(self, result: ScanResult, cves: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Build structured report data."""
        return {
            "meta": {
                "tool": "MakassarScan",
                "version": __version__,
                "generated_at": datetime.now().isoformat(),
                "host": result.host,
                "scan_level": result.level.name,
                "duration_seconds": result.duration,
            },
            "ports": result.ports,
            "http_metadata": result.http_metadata,
            "tls_metadata": result.tls_metadata,
            "insights": result.insights,
            "identified": {
                "vendor": result.identified_vendor,
                "product": result.identified_product,
                "runtime": result.identified_runtime,
            },
            "crawl_findings": [
                {
                    "url": f.url,
                    "status": f.status,
                    "title": f.title,
                    "forms": f.forms,
                    "scripts": f.scripts,
                    "flags": f.flags,
                }
                for f in result.crawl_findings
            ],
            "documents": [
                {
                    "url": d.url,
                    "extension": d.extension,
                    "source": d.source,
                    "size": d.size,
                    "keywords": d.keywords,
                }
                for d in result.documents
            ],
            "cves": cves,
            "services": [
                {"name": s.name, "detail": s.detail}
                for s in result.services
            ],
        }

    def _generate_html_report(self, data: Dict[str, Any]) -> str:
        """Generate HTML report."""
        meta = data["meta"]
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MakassarScan Report - {meta['host']}</title>
    <style>
        :root {{
            --bg: #1e1e2e;
            --fg: #cdd6f4;
            --accent: #89b4fa;
            --success: #a6e3a1;
            --warning: #f9e2af;
            --error: #f38ba8;
            --surface: #313244;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: var(--bg);
            color: var(--fg);
            line-height: 1.6;
            padding: 2rem;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1, h2, h3 {{ color: var(--accent); margin-bottom: 1rem; }}
        h1 {{ font-size: 2rem; border-bottom: 2px solid var(--accent); padding-bottom: 0.5rem; }}
        h2 {{ font-size: 1.5rem; margin-top: 2rem; }}
        .card {{
            background: var(--surface);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }}
        .meta {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; }}
        .meta-item {{ padding: 0.5rem; background: var(--bg); border-radius: 4px; }}
        .meta-label {{ font-size: 0.875rem; color: var(--accent); }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; }}
        th, td {{ padding: 0.75rem; text-align: left; border-bottom: 1px solid var(--bg); }}
        th {{ background: var(--bg); color: var(--accent); }}
        .status-open {{ color: var(--success); font-weight: bold; }}
        .status-closed {{ color: var(--error); }}
        .cvss-high {{ color: var(--error); }}
        .cvss-medium {{ color: var(--warning); }}
        .cvss-low {{ color: var(--success); }}
        .tag {{ display: inline-block; padding: 0.25rem 0.5rem; background: var(--accent); color: var(--bg); border-radius: 4px; font-size: 0.75rem; margin: 0.125rem; }}
        a {{ color: var(--accent); }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 MakassarScan Security Report</h1>
        
        <div class="card">
            <h2>📋 Scan Summary</h2>
            <div class="meta">
                <div class="meta-item">
                    <div class="meta-label">Target</div>
                    <div>{meta['host'] or 'N/A'}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Scan Level</div>
                    <div>{meta['scan_level']}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Duration</div>
                    <div>{meta['duration_seconds']:.1f}s</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Generated</div>
                    <div>{meta['generated_at'][:19]}</div>
                </div>
            </div>
        </div>
        
        <div class="card">
            <h2>🔓 Port Scan Results</h2>
            <table>
                <tr><th>Port</th><th>Service</th><th>Status</th></tr>
"""
        for port in data["ports"]:
            status_class = "status-open" if port.get("open") else "status-closed"
            status_text = "OPEN" if port.get("open") else "CLOSED"
            html += f"""                <tr>
                    <td>{port['port']}</td>
                    <td>{port['service']}</td>
                    <td class="{status_class}">{status_text}</td>
                </tr>
"""
        html += """            </table>
        </div>
"""
        
        if data["cves"]:
            html += """        <div class="card">
            <h2>🛡️ CVE Matches</h2>
            <table>
                <tr><th>CVE ID</th><th>CVSS</th><th>Published</th><th>Summary</th></tr>
"""
            for cve in data["cves"]:
                score = cve.get("score", 0) or 0
                cvss_class = "cvss-high" if score >= 7 else "cvss-medium" if score >= 4 else "cvss-low"
                html += f"""                <tr>
                    <td><a href="https://nvd.nist.gov/vuln/detail/{cve['id']}" target="_blank">{cve['id']}</a></td>
                    <td class="{cvss_class}">{score or 'N/A'}</td>
                    <td>{cve.get('published', 'N/A')[:10]}</td>
                    <td>{cve.get('summary', '')[:150]}...</td>
                </tr>
"""
            html += """            </table>
        </div>
"""
        
        html += f"""        <footer style="text-align: center; margin-top: 3rem; color: var(--accent);">
            <p>Generated by MakassarScan v{__version__} | <a href="https://github.com/Masriyan/Makassarscan">GitHub</a></p>
        </footer>
    </div>
</body>
</html>"""
        return html

    def _generate_markdown_report(self, data: Dict[str, Any]) -> str:
        """Generate Markdown report."""
        meta = data["meta"]
        md = f"""# 🔍 MakassarScan Security Report

**Target:** {meta['host'] or 'N/A'}  
**Scan Level:** {meta['scan_level']}  
**Duration:** {meta['duration_seconds']:.1f}s  
**Generated:** {meta['generated_at'][:19]}

---

## 🔓 Port Scan Results

| Port | Service | Status |
|------|---------|--------|
"""
        for port in data["ports"]:
            status = "✅ OPEN" if port.get("open") else "❌ CLOSED"
            md += f"| {port['port']} | {port['service']} | {status} |\n"
        
        if data["cves"]:
            md += "\n---\n\n## 🛡️ CVE Matches\n\n"
            for cve in data["cves"]:
                score = cve.get("score", "N/A")
                md += f"### {cve['id']} (CVSS: {score})\n\n"
                md += f"**Published:** {cve.get('published', 'N/A')[:10]}\n\n"
                md += f"{cve.get('summary', 'No description available.')}\n\n"
        
        if data["documents"]:
            md += "\n---\n\n## 📄 Discovered Documents\n\n"
            for doc in data["documents"]:
                md += f"- **{doc['extension']}**: [{doc['url']}]({doc['url']}) _(Source: {doc['source']})_\n"
        
        md += f"\n---\n\n_Generated by [MakassarScan](https://github.com/Masriyan/Makassarscan) v{__version__}_\n"
        return md


# =============================================================================
# CLI MODE
# =============================================================================

class CLIScanner:
    """Command-line interface for headless scanning."""

    def __init__(self) -> None:
        self.logger = DebugLogger()
        self.scanner = VulnerabilityScanner(self.logger)
        self.exporter = ReportExporter(self.logger)
        self.subdomain_enum = SubdomainEnumerator(self.logger)
        self.cve_cache = CVECache()
        # New reconnaissance tools
        self.port_scanner = ConcurrentPortScanner(self.logger)
        self.security_headers = SecurityHeadersAnalyzer(self.logger)
        self.dns_enum = DNSEnumerator(self.logger)
        self.wayback = WaybackMachine(self.logger)
        self.whois = WhoisLookup(self.logger)

    def run(self, args: argparse.Namespace) -> int:
        """Execute CLI scan."""
        if args.verbose:
            self.logger.set_enabled(True)
            # Also log to console
            def console_log(msg: str) -> None:
                print(msg)
            self.logger.subscribe(console_log)
        
        print(f"\n{'='*60}")
        print(f"  🔥 MakassarScan v{__version__} - CLI Mode")
        print(f"  🎯 Target: {args.target}")
        print(f"{'='*60}\n")
        
        # Store all reconnaissance data
        recon_data: Dict[str, Any] = {}
        
        # 1. WHOIS Lookup
        if args.whois:
            print("[*] 🔎 Performing WHOIS lookup...")
            whois_result = self.whois.lookup(args.target)
            recon_data["whois"] = whois_result
            if "info" in whois_result and whois_result["info"]:
                info = whois_result["info"]
                print(f"[+] Registrar: {info.registrar or 'N/A'}")
                print(f"    Created: {info.creation_date or 'N/A'}")
                print(f"    Expires: {info.expiration_date or 'N/A'}")
                if info.name_servers:
                    print(f"    NS: {', '.join(info.name_servers[:3])}")
        
        # 2. DNS Enumeration
        if args.dns:
            print("[*] 🌐 Enumerating DNS records...")
            dns_result = self.dns_enum.enumerate(args.target)
            recon_data["dns"] = dns_result
            print(f"[+] Found {dns_result['total_records']} DNS records")
            for rtype, records in dns_result.get("records", {}).items():
                if records:
                    values = [r.value[:50] for r in records[:2]]
                    print(f"    {rtype}: {', '.join(values)}")
            analysis = dns_result.get("analysis", {})
            if analysis.get("mail_providers"):
                print(f"    📧 Mail: {', '.join(set(analysis['mail_providers']))}")
            if analysis.get("cloud_providers"):
                print(f"    ☁️  Cloud: {', '.join(set(analysis['cloud_providers']))}")
        
        # 3. Subdomain enumeration
        subdomains: List[Dict[str, Any]] = []
        if args.subdomains:
            print("[*] 🔍 Enumerating subdomains...")
            subdomains = self.subdomain_enum.enumerate(args.target, resolve_dns=not args.no_resolve)
            recon_data["subdomains"] = subdomains
            print(f"[+] Found {len(subdomains)} subdomains")
            if subdomains and args.verbose:
                for sub in subdomains[:10]:
                    status = "✓" if sub["resolved"] else "✗"
                    ips = ", ".join(sub["ips"]) if sub["ips"] else "unresolved"
                    print(f"    {status} {sub['subdomain']} -> {ips}")
                if len(subdomains) > 10:
                    print(f"    ... and {len(subdomains) - 10} more")
        
        # 4. Wayback Machine
        if args.wayback:
            print("[*] 📜 Fetching Wayback Machine data...")
            wayback_result = self.wayback.get_snapshots(args.target, limit=100)
            recon_data["wayback"] = wayback_result
            print(f"[+] Found {wayback_result.get('total_unique', 0)} archived URLs")
            interesting = wayback_result.get("interesting_urls", [])
            if interesting:
                print(f"[!] Interesting URLs ({len(interesting)}):")
                for item in interesting[:5]:
                    print(f"    ⚡ {item['description']}: {item['url'][:60]}")
        
        # 5. Security Headers Check
        if args.headers:
            print("[*] 🔒 Analyzing HTTP security headers...")
            headers_result = self.security_headers.analyze(args.target)
            recon_data["security_headers"] = headers_result
            grade = headers_result.get("grade", "?")
            score = headers_result.get("score", 0)
            present = headers_result.get("present_count", 0)
            total = headers_result.get("total_count", 0)
            
            # Color the grade
            grade_colors = {"A+": "🟢", "A": "🟢", "B": "🟡", "C": "🟠", "D": "🟠", "F": "🔴"}
            grade_icon = grade_colors.get(grade, "⚪")
            
            print(f"[+] Security Grade: {grade_icon} {grade} ({score}%)")
            print(f"    Headers present: {present}/{total}")
            
            # Show missing high-severity headers
            for h in headers_result.get("headers", []):
                if not h.present and h.severity == "high":
                    print(f"    ❌ Missing: {h.header} ({h.description})")
            
            # Show dangerous headers
            for danger in headers_result.get("dangerous_headers", []):
                print(f"    ⚠️  {danger}")
        
        # Build scan request
        profile = SCAN_PROFILES.get(args.profile, SCAN_PROFILES["standard"])
        level = ScanLevel[args.level.upper()] if args.level else profile["level"]
        
        crawl_settings = CrawlSettings(
            enabled=args.crawl if args.crawl is not None else profile["crawl"],
            max_depth=args.crawl_depth,
            max_pages=args.crawl_depth * 10,
            keywords=args.crawl_keywords.split(",") if args.crawl_keywords else list(DEFAULT_CRAWL_KEYWORDS),
        )
        
        social_config = SocialConfig(providers={
            platform: SocialProviderSettings(enabled=False, api_key="", secret="", handle="")
            for platform in SOCIAL_PLATFORMS
        })
        
        request = ScanRequest(
            target=args.target,
            vendor=args.vendor or "",
            product=args.product or "",
            scan_level=level,
            user_agent=args.user_agent or DEFAULT_USER_AGENT,
            debug_enabled=args.verbose,
            waf_evasion=args.waf if args.waf is not None else profile["waf_evasion"],
            crawl=crawl_settings,
            document_extensions=args.extensions.split(",") if args.extensions else list(DEFAULT_DOCUMENT_EXTENSIONS),
            social=social_config,
        )
        
        # Run scan
        print(f"\n[*] 🚀 Starting {level.name} scan...")
        result = self.scanner.run_scan(request)
        
        # Fetch CVEs
        print("[*] 🛡️ Fetching CVE data...")
        keyword = args.product or result.identified_product or result.host or args.target
        
        # Try cache first
        cves = self.cve_cache.get(keyword) if not args.no_cache else None
        if cves is None:
            cves = self.scanner.fetch_cves(keyword, request.user_agent)
            if cves and not args.no_cache:
                self.cve_cache.set(keyword, cves)
        
        # Display results
        print(f"\n{'='*60}")
        print("  📊 SCAN RESULTS")
        print(f"{'='*60}\n")
        
        open_ports = [p for p in result.ports if p.get("open")]
        print(f"[+] 🔓 Open Ports: {len(open_ports)}/{len(result.ports)}")
        for port in open_ports:
            banner = port.get("banner", "")
            banner_str = f" | {banner[:40]}..." if banner else ""
            print(f"    • {port['port']}/tcp ({port['service']}){banner_str}")
        
        if result.identified_vendor or result.identified_product:
            print(f"\n[+] 🧬 Identified: {result.identified_vendor or 'Unknown'} / {result.identified_product or 'Unknown'}")
        
        if cves:
            print(f"\n[+] 🛡️ Top CVEs ({len(cves)}):")
            for cve in cves[:5]:
                score = cve.get("score", 0) or 0
                severity_icon = "🔴" if score >= 7 else "🟠" if score >= 4 else "🟡"
                print(f"    {severity_icon} {cve['id']} (CVSS: {score})")
        
        if result.documents:
            print(f"\n[+] 📄 Documents Found: {len(result.documents)}")
            for doc in result.documents[:5]:
                print(f"    • {doc.extension}: {doc.url}")
        
        if subdomains:
            print(f"\n[+] 🔍 Subdomains: {len(subdomains)} discovered")
        
        print(f"\n[✓] Scan completed in {result.duration:.1f}s\n")
        
        # Export if requested
        if args.output:
            output_path = Path(args.output)
            ext = output_path.suffix.lower()
            
            if ext == ".json":
                self.exporter.export_json(result, cves, output_path)
            elif ext == ".html":
                self.exporter.export_html(result, cves, output_path)
            elif ext == ".md":
                self.exporter.export_markdown(result, cves, output_path)
            elif ext == ".csv":
                self.exporter.export_csv(result, cves, output_path)
            else:
                # Default to JSON
                self.exporter.export_json(result, cves, output_path.with_suffix(".json"))
            
            print(f"[✓] Report saved to: {args.output}")
        
        return 0


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="makassarscan",
        description=f"MakassarScan v{__version__} - Advanced Vulnerability Assessment Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  makassarscan example.com
  makassarscan --target example.com --level deep --output report.html
  makassarscan example.com --profile full --subdomains
  makassarscan --cli example.com --crawl --waf
  
Profiles:
  quick    - Fast scan, top 8 ports, no crawling
  standard - Standard scan, 15 ports, basic crawling (default)
  full     - Full scan, 22 ports, deep crawling, WAF evasion
  stealth  - Stealth scan, all ports, slow timing, full evasion

GitHub: https://github.com/Masriyan/Makassarscan
        """
    )
    
    parser.add_argument("target", nargs="?", help="Target host or URL to scan")
    parser.add_argument("--cli", action="store_true", help="Run in CLI mode (no GUI)")
    parser.add_argument("-t", "--target", dest="target_arg", help="Target host or URL (alternative)")
    parser.add_argument("-l", "--level", choices=["basic", "medium", "deep", "deeper"],
                        help="Scan level (overrides profile)")
    parser.add_argument("-p", "--profile", choices=["quick", "standard", "full", "stealth"],
                        default="standard", help="Scan profile (default: standard)")
    parser.add_argument("-o", "--output", help="Output file path (supports .json, .html, .md, .csv)")
    parser.add_argument("--vendor", help="Vendor name for CVE lookup")
    parser.add_argument("--product", help="Product name for CVE lookup")
    parser.add_argument("--user-agent", help="Custom User-Agent string")
    parser.add_argument("--crawl", action="store_true", help="Enable web crawling")
    parser.add_argument("--no-crawl", dest="crawl", action="store_false", help="Disable web crawling")
    parser.add_argument("--crawl-depth", type=int, default=2, help="Crawl depth (default: 2)")
    parser.add_argument("--crawl-keywords", help="Comma-separated crawl keywords")
    parser.add_argument("--waf", action="store_true", help="Enable WAF evasion")
    parser.add_argument("--no-waf", dest="waf", action="store_false", help="Disable WAF evasion")
    parser.add_argument("--extensions", help="Comma-separated document extensions")
    parser.add_argument("--subdomains", action="store_true", help="Enumerate subdomains via crt.sh")
    parser.add_argument("--no-resolve", action="store_true", help="Skip DNS resolution for subdomains")
    parser.add_argument("--no-cache", action="store_true", help="Disable CVE cache")
    
    # New reconnaissance features
    parser.add_argument("--whois", action="store_true", help="Perform WHOIS lookup")
    parser.add_argument("--dns", action="store_true", help="Enumerate DNS records (A, AAAA, MX, TXT, NS, etc.)")
    parser.add_argument("--wayback", action="store_true", help="Fetch historical URLs from Wayback Machine")
    parser.add_argument("--headers", action="store_true", help="Analyze HTTP security headers")
    parser.add_argument("--recon", action="store_true", help="Enable all recon (--whois --dns --subdomains --wayback --headers)")
    
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--version", action="version", version=f"MakassarScan v{__version__}")
    
    return parser.parse_args()


def cli_main() -> int:
    """CLI entry point."""
    args = parse_args()
    
    # Handle target from either positional or --target argument
    if args.target_arg and not args.target:
        args.target = args.target_arg
    
    if not args.target:
        print(f"MakassarScan v{__version__}")
        print("Usage: makassarscan [--cli] <target> [options]")
        print("       makassarscan --help for more information")
        return 1
    
    # Handle --recon shortcut (enable all recon features)
    if args.recon:
        args.whois = True
        args.dns = True
        args.subdomains = True
        args.wayback = True
        args.headers = True
    
    cli = CLIScanner()
    return cli.run(args)


if __name__ == "__main__":
    # Check if running in CLI mode
    if "--cli" in sys.argv or not _GUI_AVAILABLE:
        sys.exit(cli_main())
    else:
        # Check for any CLI arguments
        if len(sys.argv) > 1 and sys.argv[1] not in ("--help", "-h"):
            # Has arguments, run in CLI mode
            sys.exit(cli_main())
        else:
            # No arguments or help, run GUI
            main()
