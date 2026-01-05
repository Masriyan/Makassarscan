<div align="center">

```
███╗   ███╗ █████╗ ██╗  ██╗ █████╗ ███████╗███████╗ █████╗ ██████╗ 
████╗ ████║██╔══██╗██║ ██╔╝██╔══██╗██╔════╝██╔════╝██╔══██╗██╔══██╗
██╔████╔██║███████║█████╔╝ ███████║███████╗███████╗███████║██████╔╝
██║╚██╔╝██║██╔══██║██╔═██╗ ██╔══██║╚════██║╚════██║██╔══██║██╔══██╗
██║ ╚═╝ ██║██║  ██║██║  ██╗██║  ██║███████║███████║██║  ██║██║  ██║
╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝
                    ███████╗ ██████╗ █████╗ ███╗   ██╗              
                    ██╔════╝██╔════╝██╔══██╗████╗  ██║              
                    ███████╗██║     ███████║██╔██╗ ██║              
                    ╚════██║██║     ██╔══██║██║╚██╗██║              
                    ███████║╚██████╗██║  ██║██║ ╚████║              
                    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝  v2.0.0
```

# 🔥 MakassarScan

### *The Ultimate Vulnerability Assessment & Reconnaissance Toolkit*

[![Python](https://img.shields.io/badge/Python-3.9+-FFD43B?style=for-the-badge&logo=python&logoColor=blue)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Win%20%7C%20Linux%20%7C%20Mac-blue?style=for-the-badge&logo=windows&logoColor=white)]()
[![Stars](https://img.shields.io/github/stars/Masriyan/Makassarscan?style=for-the-badge&color=yellow)](https://github.com/Masriyan/Makassarscan/stargazers)

<img src="https://readme-typing-svg.herokuapp.com?font=Fira+Code&weight=600&size=22&pause=1000&color=00D9FF&center=true&vCenter=true&random=false&width=600&lines=🎯+Multi-threaded+Port+Scanning;🔍+CVE+Vulnerability+Lookup;🕷️+Intelligent+Web+Crawling;🧬+Technology+Fingerprinting;🤖+AI-Powered+Analysis;📊+Beautiful+HTML+Reports" alt="Typing SVG" />

---

[**⚡ Quick Start**](#-quick-start) • [**🎯 Features**](#-features) • [**📸 Screenshots**](#-screenshots) • [**🛠️ Installation**](#️-installation) • [**📖 Usage**](#-usage) • [**🤝 Contributing**](#-contributing)

</div>

---

## 🎬 What is MakassarScan?

> **MakassarScan** is a blazing-fast, all-in-one security reconnaissance toolkit built for penetration testers, bug bounty hunters, and security researchers. Born in Makassar 🇮🇩, engineered for the world. 🌍

Whether you're hunting for vulnerabilities, mapping attack surfaces, or conducting security assessments - MakassarScan has got you covered with:

- 🔓 **Lightning-fast port scanning** with service fingerprinting
- 🛡️ **Real-time CVE database** queries with intelligent caching
- 🕷️ **Smart web crawling** that finds hidden endpoints
- 🧬 **Tech stack detection** (WordPress, React, Django, and 15+ more)
- 🤖 **AI-powered analysis** via ChatGPT, Claude, or Gemini
- 📊 **Stunning HTML reports** with dark theme aesthetics

---

## ⚡ Quick Start

```bash
# Clone the repo
git clone https://github.com/Masriyan/Makassarscan.git && cd Makassarscan

# Install dependencies
pip install -r requirements.txt

# Run your first scan! 🚀
python app.py example.com --profile full -o report.html
```

**That's it!** Open `report.html` in your browser and enjoy the beautiful dark-themed report. 🌙

---

## 🎯 Features

<table>
<tr>
<td width="50%">

### 🔓 Port Scanning
```
✓ Multi-threaded TCP scanning
✓ 27+ common service ports
✓ Banner grabbing
✓ FTP anonymous detection
✓ Service fingerprinting
```

### 🛡️ CVE Intelligence
```
✓ Real-time NVD API queries
✓ CVSS score analysis
✓ SQLite offline cache
✓ 24-hour cache expiry
✓ Reference links included
```

### 🕷️ Web Crawler
```
✓ Configurable crawl depth
✓ Form detection (login/upload)
✓ Password field discovery
✓ Script analysis
✓ Smart keyword matching
```

</td>
<td width="50%">

### 🔍 Subdomain Enumeration
```
✓ Certificate Transparency (crt.sh)
✓ Automatic DNS resolution
✓ Wildcard filtering
✓ Parallel processing
✓ Export-ready results
```

### 🧬 Tech Fingerprinting
```
✓ CMS: WordPress, Drupal, Joomla
✓ Frameworks: Laravel, Django, Express
✓ Frontend: React, Vue, Angular
✓ E-commerce: Shopify, Wix
✓ Confidence scoring
```

### 🤖 AI Analysis
```
✓ ChatGPT (OpenAI)
✓ Claude (Anthropic)
✓ Gemini (Google)
✓ Automatic model selection
✓ Customizable detail levels
```

</td>
</tr>
</table>

---

## 📸 Screenshots

<details>
<summary><b>🖥️ GUI Mode</b> (Click to expand)</summary>

The sleek Tkinter-based GUI with bilingual support (English/Bahasa Indonesia):

```
┌─────────────────────────────────────────────────────────────────┐
│  MakassarScan - Vulnerability Toolkit                  [─][□][×]│
├─────────────────────────────────────────────────────────────────┤
│  Target: [example.com                                    ]      │
│  Vendor: [                                               ]      │
│  Product:[                                               ]      │
│                                                                 │
│  Scan Level: [Medium ▼]     Language: [English ▼]               │
│  [✓] Debug   [✓] WAF Evasion   [✓] Crawl                       │
│                                                                 │
│  ═══════════════ [  🚀 START SCAN  ] ═══════════════            │
│                                                                 │
│  ┌─Activity────┬─CVE Matches────┬─AI Analysis────┐              │
│  │ [INFO] Scanning ports...                      │              │
│  │ [INFO] Port 80/tcp OPEN (http)               │               │
│  │ [INFO] Port 443/tcp OPEN (https)             │               │
│  │ [INFO] Fetching CVE data...                  │               │
│  └───────────────────────────────────────────────┘              │
└─────────────────────────────────────────────────────────────────┘
```

</details>

<details>
<summary><b>⌨️ CLI Mode</b> (Click to expand)</summary>

```bash
============================================================
  MakassarScan v2.0.0 - CLI Mode
  Target: github.com
============================================================

[*] Enumerating subdomains...
[+] Found 47 subdomains
    ✓ api.github.com -> 140.82.112.6
    ✓ gist.github.com -> 140.82.112.4
    ✓ pages.github.com -> 185.199.108.153
    ... and 44 more

[*] Starting FULL scan...

[+] Open Ports: 3/22
    • 22/tcp (ssh)      ✅
    • 80/tcp (http)     ✅
    • 443/tcp (https)   ✅

[+] Identified: GitHub / nginx

[+] Technologies Detected:
    • Ruby on Rails (confidence: 85%)
    • React (confidence: 70%)
    • nginx (confidence: 100%)

[+] Top CVEs (5):
    • CVE-2024-1234 (CVSS: 9.8) 🔴 CRITICAL
    • CVE-2024-5678 (CVSS: 7.5) 🟠 HIGH
    • CVE-2024-9012 (CVSS: 5.3) 🟡 MEDIUM

[+] Documents Found: 3
    • PDF: /docs/security-policy.pdf
    • TXT: /robots.txt

[✓] Scan completed in 12.4s
[✓] Report saved to: report.html
```

</details>

<details>
<summary><b>📊 HTML Report</b> (Click to expand)</summary>

Beautiful dark-themed HTML reports with:
- 🎨 Modern CSS with glassmorphism effects
- 📱 Fully responsive design
- 🔗 Clickable CVE links to NVD
- 📈 Color-coded CVSS scores
- 🌙 Eye-friendly dark mode

</details>

---

## 🛠️ Installation

### Option 1: pip (Recommended)
```bash
pip install makassarscan
```

### Option 2: From Source
```bash
git clone https://github.com/Masriyan/Makassarscan.git
cd Makassarscan
pip install -r requirements.txt
python app.py --help
```

### Option 3: With All Features
```bash
pip install makassarscan[full]  # Includes dnspython + Pillow
```

---

## 📖 Usage

### 🎮 GUI Mode
```bash
python app.py
```

### ⌨️ CLI Mode

| Command | Description |
|---------|-------------|
| `python app.py example.com` | Quick scan |
| `python app.py example.com --profile full` | Full scan with crawling |
| `python app.py example.com --subdomains` | Include subdomain enumeration |
| `python app.py example.com -o report.html` | Export to HTML |
| `python app.py example.com --waf --crawl` | WAF evasion + crawling |

### 🎯 Scan Profiles

| Profile | Ports | Crawl | WAF | Speed | Description |
|---------|:-----:|:-----:|:---:|:-----:|-------------|
| `quick` | 8 | ❌ | ❌ | ⚡⚡⚡ | Lightning fast recon |
| `standard` | 15 | ✅ | ❌ | ⚡⚡ | Balanced approach |
| `full` | 22 | ✅ | ✅ | ⚡ | Comprehensive scan |
| `stealth` | 27+ | ✅ | ✅ | 🐢 | Low and slow |

### 📤 Export Formats

```bash
python app.py target.com -o report.json   # Machine-readable
python app.py target.com -o report.html   # Beautiful dark report
python app.py target.com -o report.md     # GitHub-friendly
python app.py target.com -o report.csv    # Spreadsheet-ready
```

---

## 🔧 Advanced Features

### 🤖 AI-Powered Analysis

Connect your favorite AI for intelligent vulnerability triage:

```bash
# Via GUI: Select provider and enter API key

# The AI will analyze:
# - Attack surface exposure
# - Risk prioritization  
# - Remediation recommendations
```

Supported providers:
- **OpenAI** (gpt-4o-mini)
- **Anthropic** (claude-3-sonnet)
- **Google** (gemini-2.5-flash)

### 🔍 Subdomain Discovery

```bash
python app.py example.com --subdomains

# Output:
# [+] Found 47 subdomains from Certificate Transparency
#     ✓ api.example.com -> 1.2.3.4
#     ✓ staging.example.com -> 5.6.7.8
#     ✗ dev.example.com -> unresolved
```

### 🛡️ WAF Evasion Techniques

When `--waf` is enabled:
- 🔄 Rotating User-Agent strings
- ⏱️ Random request delays (150-600ms)
- 🎲 Cache-busting query parameters
- 🌐 Spoofed X-Forwarded-For headers

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    MakassarScan v2.0                    │
├─────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │
│  │   GUI Mode  │  │   CLI Mode  │  │  API Mode   │     │
│  │  (Tkinter)  │  │  (argparse) │  │   (Future)  │     │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘     │
│         │                │                │             │
│         └────────────────┼────────────────┘             │
│                          ▼                              │
│  ┌──────────────────────────────────────────────────┐  │
│  │              VulnerabilityScanner                │  │
│  │  ┌──────────┬──────────┬──────────┬──────────┐  │  │
│  │  │PortScan │ Crawler  │ CVE API  │TechDetect│  │  │
│  │  └──────────┴──────────┴──────────┴──────────┘  │  │
│  └──────────────────────────────────────────────────┘  │
│                          │                              │
│         ┌────────────────┼────────────────┐            │
│         ▼                ▼                ▼            │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐       │
│  │  Subdomain │  │  AI Client │  │  Exporter  │       │
│  │ Enumerator │  │ (GPT/etc) │  │ (JSON/HTML)│       │
│  └────────────┘  └────────────┘  └────────────┘       │
└─────────────────────────────────────────────────────────┘
```

---

## 🤝 Contributing

We love contributions! 💙

```bash
# 1. Fork the repo
# 2. Create a branch
git checkout -b feature/amazing-feature

# 3. Make changes & commit
git commit -m "Add amazing feature"

# 4. Push & create PR
git push origin feature/amazing-feature
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

---

## ⚠️ Disclaimer

```diff
! FOR AUTHORIZED SECURITY TESTING ONLY

This tool is designed for authorized security assessments and educational 
purposes. Users are responsible for ensuring they have proper authorization 
before scanning any systems. Unauthorized scanning may violate laws in your 
jurisdiction.

- Never scan systems you don't own or have explicit permission to test
- Always follow responsible disclosure practices
- Respect rate limits and avoid denial-of-service conditions
```

---

## 📜 License

This project is licensed under the **MIT License** - see [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgments

<table>
<tr>
<td align="center"><a href="https://nvd.nist.gov/"><b>NVD/NIST</b></a><br/>CVE Database</td>
<td align="center"><a href="https://crt.sh/"><b>crt.sh</b></a><br/>CT Logs</td>
<td align="center"><a href="https://duckduckgo.com/"><b>DuckDuckGo</b></a><br/>Doc Search</td>
<td align="center"><a href="https://openai.com/"><b>OpenAI</b></a><br/>AI Analysis</td>
</tr>
</table>

---

<div align="center">

### 🌟 Star this repo if you find it useful!

**Made with ❤️ and ☕ in Makassar, Indonesia 🇮🇩**

[![GitHub](https://img.shields.io/badge/GitHub-@Masriyan-181717?style=for-the-badge&logo=github)](https://github.com/Masriyan)

<sub>© 2024-2026 Masriyan. All rights reserved.</sub>

</div>
