#!/usr/bin/env python3
"""
recon_pipeline.py - Automated reconnaissance & vulnerability scanning pipeline.

Chains Nmap -> (Nikto + Gobuster on discovered web ports) -> parsed findings ->
JSON + HTML (+ optional PDF) report.

FOR AUTHORIZED TESTING ONLY. Scan only systems you own or have written
permission to test. The tool refuses to run unless the target is listed in a
scope file and you pass --authorized.

Requirements:
    pip install jinja2            (required)
    pip install weasyprint        (optional, for --pdf)
    nmap, nikto, gobuster installed and on PATH

Example:
    echo "192.168.56.0/24" > scope.txt
    python3 recon_pipeline.py -t 192.168.56.101 --scope scope.txt --authorized \
        --wordlist /usr/share/wordlists/dirb/common.txt --vulners
"""

import argparse
import ipaddress
import json
import logging
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, asdict, field
from datetime import datetime
from pathlib import Path

from jinja2 import Environment

log = logging.getLogger("recon")

SEVERITIES = ["critical", "high", "medium", "low", "info"]

# Ports that are commonly risky when exposed: port -> (label, severity)
RISKY_PORTS = {
    21: ("FTP exposed (cleartext credentials)", "medium"),
    23: ("Telnet exposed (cleartext protocol)", "high"),
    69: ("TFTP exposed (no authentication)", "medium"),
    135: ("MS-RPC exposed", "medium"),
    139: ("NetBIOS exposed", "medium"),
    445: ("SMB exposed", "medium"),
    512: ("rexec exposed", "high"),
    513: ("rlogin exposed", "high"),
    514: ("rsh exposed", "high"),
    1433: ("MSSQL exposed", "medium"),
    3306: ("MySQL exposed", "medium"),
    3389: ("RDP exposed", "medium"),
    5432: ("PostgreSQL exposed", "medium"),
    5900: ("VNC exposed", "medium"),
    6379: ("Redis exposed", "medium"),
    27017: ("MongoDB exposed", "medium"),
}


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------
@dataclass
class Finding:
    host: str
    port: int | None
    service: str
    title: str
    severity: str
    evidence: str
    source: str
    cvss: float | None = None


@dataclass
class HostResult:
    address: str
    hostname: str = ""
    open_ports: list = field(default_factory=list)  # dicts


def cvss_to_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


# --------------------------------------------------------------------------
# Scope validation
# --------------------------------------------------------------------------
def load_scope(path: Path) -> list[str]:
    entries = []
    for line in path.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            entries.append(line)
    return entries


def in_scope(target: str, scope: list[str]) -> bool:
    """Target (IP, CIDR, or hostname) must fall inside a scope entry."""
    nets, names = [], set()
    for entry in scope:
        try:
            nets.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            names.add(entry.lower())

    # Hostname exact match
    if target.lower() in names:
        return True

    # Resolve hostnames to IPs
    try:
        target_net = ipaddress.ip_network(target, strict=False)
        candidates = [target_net]
    except ValueError:
        try:
            candidates = [ipaddress.ip_network(socket.gethostbyname(target))]
        except socket.gaierror:
            return False

    return all(any(c.subnet_of(n) for n in nets if c.version == n.version) for c in candidates)


# --------------------------------------------------------------------------
# Command runner
# --------------------------------------------------------------------------
def run(cmd: list[str], timeout: int) -> tuple[int, str, str]:
    """Run a command with a list of args (never shell=True)."""
    log.debug("exec: %s", " ".join(cmd))
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        log.error("Tool not found: %s", cmd[0])
        return 127, "", f"{cmd[0]} not found"
    except subprocess.TimeoutExpired:
        log.warning("Timeout after %ss: %s", timeout, cmd[0])
        return 124, "", "timeout"


# --------------------------------------------------------------------------
# Nmap
# --------------------------------------------------------------------------
def run_nmap(target: str, top_ports: int, vulners: bool, timeout: int, extra: list[str]):
    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
        xml_path = tmp.name
    cmd = ["nmap", "-sV", "-T4", "--top-ports", str(top_ports), "-oX", xml_path]
    if vulners:
        cmd += ["--script", "vulners"]
    cmd += extra + [target]
    rc, _, err = run(cmd, timeout)
    if rc not in (0,):
        log.error("Nmap failed (rc=%s): %s", rc, err.strip()[:200])
        return [], []
    try:
        return parse_nmap(xml_path)
    except ET.ParseError as e:
        log.error("Could not parse Nmap XML: %s", e)
        return [], []
    finally:
        Path(xml_path).unlink(missing_ok=True)


def parse_nmap(xml_path: str):
    hosts: list[HostResult] = []
    findings: list[Finding] = []
    root = ET.parse(xml_path).getroot()

    for h in root.findall("host"):
        status = h.find("status")
        if status is not None and status.get("state") != "up":
            continue
        addr_el = h.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = h.find("address")
        addr = addr_el.get("addr") if addr_el is not None else "unknown"
        hn_el = h.find("hostnames/hostname")
        host = HostResult(address=addr, hostname=hn_el.get("name") if hn_el is not None else "")

        for p in h.findall("ports/port"):
            state = p.find("state")
            if state is None or state.get("state") != "open":
                continue
            port = int(p.get("portid"))
            proto = p.get("protocol")
            svc = p.find("service")
            name = svc.get("name", "unknown") if svc is not None else "unknown"
            product = svc.get("product", "") if svc is not None else ""
            version = svc.get("version", "") if svc is not None else ""
            tunnel = svc.get("tunnel", "") if svc is not None else ""
            banner = " ".join(x for x in (product, version) if x).strip()

            host.open_ports.append({
                "port": port, "proto": proto, "service": name,
                "banner": banner, "tunnel": tunnel,
            })

            if port in RISKY_PORTS:
                label, sev = RISKY_PORTS[port]
                findings.append(Finding(addr, port, name, label, sev,
                                        banner or "Service detected", "nmap"))
            else:
                findings.append(Finding(addr, port, name, f"Open port {port}/{proto}",
                                        "info", banner or "Service detected", "nmap"))

            # vulners NSE output: lines like "CVE-2019-0211  7.2  https://vulners.com/..."
            for script in p.findall("script"):
                if script.get("id") != "vulners":
                    continue
                for m in re.finditer(r"(CVE-\d{4}-\d{4,7})\s+(\d+(?:\.\d+)?)",
                                     script.get("output", "")):
                    cve, score = m.group(1), float(m.group(2))
                    findings.append(Finding(addr, port, name, cve,
                                            cvss_to_severity(score),
                                            f"{banner} - CVSS {score}", "nmap-vulners", score))
        hosts.append(host)
    return hosts, findings


# --------------------------------------------------------------------------
# Web tools
# --------------------------------------------------------------------------
def web_targets(hosts: list[HostResult]) -> list[tuple[str, int, str]]:
    """Return (host, port, base_url) for every open port that looks like HTTP."""
    out = []
    for h in hosts:
        for p in h.open_ports:
            is_http = "http" in p["service"] or p["port"] in (80, 443, 8000, 8080, 8443)
            if not is_http:
                continue
            tls = p["tunnel"] == "ssl" or p["port"] in (443, 8443) or p["service"] == "https"
            scheme = "https" if tls else "http"
            out.append((h.address, p["port"], f"{scheme}://{h.address}:{p['port']}"))
    return out


def run_nikto(host: str, port: int, url: str, timeout: int,
              extra: list[str] | None = None) -> list[Finding]:
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        out_path = tmp.name
    Path(out_path).unlink(missing_ok=True)  # nikto refuses to overwrite some files
    cmd = ["nikto", "-h", url, "-Format", "json", "-output", out_path, "-nointeractive"]
    cmd += extra or []
    rc, _, err = run(cmd, timeout)
    findings: list[Finding] = []
    p = Path(out_path)
    if not p.exists():
        log.warning("Nikto produced no output for %s (%s)", url, err.strip()[:120])
        return findings
    try:
        data = json.loads(p.read_text() or "[]")
    except json.JSONDecodeError:
        log.warning("Nikto JSON unparsable for %s", url)
        return findings
    finally:
        p.unlink(missing_ok=True)

    # Nikto output is a dict or a list of dicts depending on version
    entries = data if isinstance(data, list) else [data]
    for entry in entries:
        for v in entry.get("vulnerabilities", []):
            msg = v.get("msg", "").strip()
            if not msg:
                continue
            low = msg.lower()
            if any(k in low for k in ("remote code", "rce", "shell", "command exec")):
                sev = "high"
            elif any(k in low for k in ("outdated", "vulnerable", "xss", "injection",
                                        "traversal", "default file", "credentials")):
                sev = "medium"
            elif any(k in low for k in ("header", "cookie", "x-frame", "allowed methods")):
                sev = "low"
            else:
                sev = "info"
            findings.append(Finding(host, port, "http", msg[:140], sev,
                                    f"{v.get('method', 'GET')} {v.get('url', '/')}", "nikto"))
    return findings


GOBUSTER_RE = re.compile(r"^(/\S*)\s+\(Status:\s*(\d{3})\)")
INTERESTING = ("admin", "backup", ".git", ".env", "config", "phpmyadmin",
               "upload", "login", "db", "dump", ".svn", "console")


def run_gobuster(host: str, port: int, url: str, wordlist: str, timeout: int,
                 extra: list[str] | None = None, use_defaults: bool = True) -> list[Finding]:
    cmd = ["gobuster", "dir", "-u", url, "-w", wordlist, "-q", "--no-color"]
    if use_defaults:
        # gobuster >= 3.2 errors if -s is set while the default -b "404" is also active,
        # so the blacklist is cleared with -b "".
        cmd += ["-k", "-s", "200,204,301,302,307,401,403", "-b", ""]
    cmd += extra or []
    rc, out, err = run(cmd, timeout)
    findings: list[Finding] = []
    for line in out.splitlines():
        m = GOBUSTER_RE.match(line.strip())
        if not m:
            continue
        path, status = m.group(1), m.group(2)
        hot = any(k in path.lower() for k in INTERESTING)
        sev = "medium" if hot and status.startswith("2") else ("low" if hot else "info")
        findings.append(Finding(host, port, "http", f"Discovered path {path}", sev,
                                f"HTTP {status} at {url}{path}", "gobuster"))
    if rc not in (0, 124) and not findings:
        log.warning("Gobuster issue for %s: %s", url, err.strip()[:120])
    return findings


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------
HTML_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Security Assessment Report - {{ target }}</title>
<style>
 body{font-family:Arial,Helvetica,sans-serif;margin:40px;color:#222}
 h1{border-bottom:3px solid #1a3a5c;padding-bottom:8px;color:#1a3a5c}
 h2{color:#1a3a5c;margin-top:32px}
 table{border-collapse:collapse;width:100%;font-size:13px;margin-top:8px}
 th,td{border:1px solid #ccc;padding:6px 8px;text-align:left;vertical-align:top}
 th{background:#1a3a5c;color:#fff}
 .sev{color:#fff;padding:2px 8px;border-radius:3px;font-weight:bold;font-size:12px}
 .critical{background:#7b0000}.high{background:#d32f2f}.medium{background:#f57c00}
 .low{background:#fbc02d;color:#222}.info{background:#607d8b}
 .cards{display:flex;gap:12px;margin:16px 0}
 .card{flex:1;padding:12px;border-radius:6px;color:#fff;text-align:center}
 .card b{display:block;font-size:26px}
 .meta{color:#555;font-size:13px}
 .new{background:#e8f5e9;padding:8px;border-left:4px solid #2e7d32;margin:8px 0}
</style></head><body>
<h1>Security Assessment Report</h1>
<p class="meta">Target: <b>{{ target }}</b> &nbsp;|&nbsp; Generated: {{ generated }}
 &nbsp;|&nbsp; Tools: {{ tools|join(", ") }}</p>

<h2>Executive Summary</h2>
<p>The assessment identified <b>{{ findings|length }}</b> items across
<b>{{ hosts|length }}</b> live host(s). {{ summary_sentence }}</p>
<div class="cards">
{% for s in severities %}<div class="card {{ s }}"><b>{{ counts[s] }}</b>{{ s|capitalize }}</div>{% endfor %}
</div>

{% if new_ports %}
<div class="new"><b>New open ports since baseline:</b>
{% for h, p in new_ports %}{{ h }}:{{ p }}{% if not loop.last %}, {% endif %}{% endfor %}</div>
{% endif %}

<h2>Hosts &amp; Open Ports</h2>
{% for h in hosts %}
<h3>{{ h.address }}{% if h.hostname %} ({{ h.hostname }}){% endif %}</h3>
<table><tr><th>Port</th><th>Protocol</th><th>Service</th><th>Version / Banner</th></tr>
{% for p in h.open_ports %}
<tr><td>{{ p.port }}</td><td>{{ p.proto }}</td><td>{{ p.service }}</td><td>{{ p.banner }}</td></tr>
{% endfor %}</table>
{% endfor %}

<h2>Findings (sorted by severity)</h2>
<table><tr><th>Severity</th><th>Host</th><th>Port</th><th>Finding</th><th>Evidence</th><th>CVSS</th><th>Source</th></tr>
{% for f in findings %}
<tr><td><span class="sev {{ f.severity }}">{{ f.severity|upper }}</span></td>
<td>{{ f.host }}</td><td>{{ f.port or "-" }}</td><td>{{ f.title }}</td>
<td>{{ f.evidence }}</td><td>{{ f.cvss or "-" }}</td><td>{{ f.source }}</td></tr>
{% endfor %}</table>

<p class="meta" style="margin-top:40px">Automated results may include false positives and must be
validated manually. Generated by recon_pipeline.py for authorized testing only.</p>
</body></html>"""


def build_report(target, hosts, findings, tools, new_ports, out_dir: Path, pdf: bool):
    order = {s: i for i, s in enumerate(SEVERITIES)}
    findings = sorted(findings, key=lambda f: (order[f.severity], f.host, f.port or 0))
    counts = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITIES}

    if counts["critical"] or counts["high"]:
        summary = "Critical/high-severity issues were found and should be remediated first."
    elif counts["medium"]:
        summary = "No critical issues were found, but medium-risk exposures need review."
    else:
        summary = "No significant issues were identified by automated checks."

    html = Environment(autoescape=True).from_string(HTML_TEMPLATE).render(
        target=target, generated=datetime.now().strftime("%Y-%m-%d %H:%M"),
        tools=tools, hosts=hosts, findings=findings, severities=SEVERITIES,
        counts=counts, summary_sentence=summary, new_ports=new_ports)

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", target)
    base = out_dir / f"report_{safe}_{stamp}"
    base.with_suffix(".html").write_text(html, encoding="utf-8")
    base.with_suffix(".json").write_text(json.dumps({
        "target": target, "generated": stamp,
        "hosts": [asdict(h) for h in hosts],
        "findings": [asdict(f) for f in findings],
    }, indent=2), encoding="utf-8")
    written = [base.with_suffix(".html"), base.with_suffix(".json")]

    if pdf:
        try:
            from weasyprint import HTML
            HTML(string=html).write_pdf(str(base.with_suffix(".pdf")))
            written.append(base.with_suffix(".pdf"))
        except ImportError:
            log.error("weasyprint not installed; skipping PDF (pip install weasyprint)")
    return written


def diff_baseline(baseline: Path, hosts: list[HostResult]):
    old = json.loads(baseline.read_text())
    old_ports = {(h["address"], p["port"]) for h in old.get("hosts", []) for p in h["open_ports"]}
    now = {(h.address, p["port"]) for h in hosts for p in h.open_ports}
    return sorted(now - old_ports)


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Automated recon & vulnerability scan pipeline")
    ap.add_argument("-t", "--target", required=True, help="IP, CIDR, or hostname")
    ap.add_argument("--scope", required=True, type=Path, help="File listing authorized targets")
    ap.add_argument("--authorized", action="store_true",
                    help="Confirm you have written permission to test the target")
    ap.add_argument("--wordlist", default="/usr/share/wordlists/dirb/common.txt")
    ap.add_argument("--top-ports", type=int, default=1000)
    ap.add_argument("--vulners", action="store_true", help="Run Nmap vulners script for CVEs")
    ap.add_argument("--skip-nikto", action="store_true")
    ap.add_argument("--skip-gobuster", action="store_true")
    ap.add_argument("--threads", type=int, default=4)
    ap.add_argument("--timeout", type=int, default=900, help="Per-tool timeout in seconds")
    ap.add_argument("--baseline", type=Path, help="Previous JSON report to diff against")
    ap.add_argument("--pdf", action="store_true", help="Also produce a PDF (needs weasyprint)")
    ap.add_argument("-o", "--output", type=Path, default=Path("reports"))
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")

    # --- Safety gates ---
    if not args.authorized:
        sys.exit("Refusing to run: pass --authorized to confirm you have permission to test.")
    if not args.scope.exists():
        sys.exit(f"Scope file not found: {args.scope}")
    if not in_scope(args.target, load_scope(args.scope)):
        sys.exit(f"Target {args.target} is NOT in scope file {args.scope}. Aborting.")

    if not shutil.which("nmap"):
        sys.exit("nmap is required but not found on PATH.")
    args.output.mkdir(parents=True, exist_ok=True)
    tools = ["nmap"]

    # --- Stage 1: Nmap ---
    log.info("Stage 1/3: Nmap service scan on %s", args.target)
    hosts, findings = run_nmap(args.target, args.top_ports, args.vulners, args.timeout, [])
    if not hosts:
        sys.exit("No live hosts or open ports found (or Nmap failed).")
    log.info("Found %d host(s)", len(hosts))

    # --- Stage 2: web tools, run concurrently on discovered HTTP services ---
    webs = web_targets(hosts)
    log.info("Stage 2/3: %d web service(s) discovered", len(webs))
    jobs = []
    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        for host, port, url in webs:
            if not args.skip_nikto and shutil.which("nikto"):
                jobs.append(pool.submit(run_nikto, host, port, url, args.timeout))
                if "nikto" not in tools:
                    tools.append("nikto")
            if not args.skip_gobuster and shutil.which("gobuster"):
                if Path(args.wordlist).exists():
                    jobs.append(pool.submit(run_gobuster, host, port, url,
                                            args.wordlist, args.timeout))
                    if "gobuster" not in tools:
                        tools.append("gobuster")
                else:
                    log.warning("Wordlist not found: %s (skipping gobuster)", args.wordlist)
        for j in jobs:
            try:
                findings.extend(j.result())
            except Exception as e:  # keep pipeline alive if one job dies
                log.error("Job failed: %s", e)

    # --- Stage 3: report ---
    log.info("Stage 3/3: generating report")
    new_ports = diff_baseline(args.baseline, hosts) if args.baseline else []
    files = build_report(args.target, hosts, findings, tools, new_ports, args.output, args.pdf)
    for f in files:
        log.info("Wrote %s", f)


if __name__ == "__main__":
    main()
