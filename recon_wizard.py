#!/usr/bin/env python3
"""
recon_wizard.py - 4-step interactive recon wizard (type numbers to choose).

    STEP 1  Setup    : target & scope, settings (all tool flags), check tools
    STEP 2  Scan     : Nmap, Nikto, Gobuster, run all
    STEP 3  Results  : view findings, AI advice (local Llama), generate report
    STEP 4  Report   : choose format(s): HTML, PDF, Word, Markdown, CSV, JSON, TXT

Needs recon_pipeline.py in the same folder.
Optional: pip install weasyprint (or reportlab) for PDF, python-docx for Word.

FOR AUTHORIZED TESTING ONLY.
"""

import csv
import importlib.util
import itertools
import json
import logging
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
from xml.sax.saxutils import escape as xml_escape

import recon_pipeline as rp

try:
    import llm_advisor            # optional: local Llama via Ollama
except ImportError:
    llm_advisor = None

logging.basicConfig(level=logging.INFO, format="  [%(levelname)s] %(message)s")


# ---------------------------------------------------------------------
# Terminal colours - automatic. Off when output is piped, NO_COLOR is set or TERM=dumb.
# Set FORCE_COLOR=1 to turn them on anyway.
# ---------------------------------------------------------------------
import builtins

try:
    import readline              # arrow keys + history in prompts (not available on Windows)
except ImportError:
    readline = None


def _use_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return sys.stdout.isatty() and os.environ.get("TERM") != "dumb"


USE_COLOR = _use_color()
if USE_COLOR and os.name == "nt":
    os.system("")                # lets Windows 10+ terminals understand colour codes

CODES = {"bold": "1", "dim": "2", "red": "91", "green": "92", "yellow": "93", "blue": "94",
         "magenta": "95", "cyan": "96", "white": "97", "grey": "90", "orange": "38;5;208",
         "bg_red": "41"}


def paint(text, *styles) -> str:
    if not USE_COLOR or not styles:
        return str(text)
    return "\033[" + ";".join(CODES[s] for s in styles) + "m" + str(text) + "\033[0m"


def paint_prompt(text: str) -> str:
    """Bold yellow prompt. Escape codes are wrapped for readline so line editing stays correct."""
    if not USE_COLOR:
        return text
    a, b = ("\001", "\002") if readline else ("", "")
    return f"{a}\033[1;93m{b}{text}{a}\033[0m{b}"


SEV_STYLE = {"critical": ("bold", "white", "bg_red"), "high": ("bold", "red"),
             "medium": ("orange",), "low": ("yellow",), "info": ("cyan",)}


def sev_tag(sev: str) -> str:
    return paint(f"[{sev.upper():<8}]", *SEV_STYLE.get(sev, ("grey",)))


# One colour per kind of menu option, so each choice is easy to tell apart.
MENU_STYLES = {
    "target": ("bold", "cyan"), "settings": ("bold", "blue"), "check": ("bold", "green"),
    "nmap": ("bold", "blue"), "nikto": ("bold", "orange"), "gobuster": ("bold", "cyan"),
    "all": ("bold", "yellow"), "next": ("bold", "green"), "back": ("grey",),
    "exit": ("bold", "red"), "view": ("bold", "cyan"), "report": ("bold", "green"),
    "ai": ("bold", "magenta"), "plain": (),
}


def menu_item(key: str, label: str, kind: str = "plain", indent: str = "  ") -> str:
    st = MENU_STYLES[kind]
    return f"{indent}{paint(key + ')', *(st or ('bold', 'cyan')))} {paint(label, *[x for x in st if x != 'bold'])}"


def show_menu(items, indent: str = "  "):
    for key, label, kind in items:
        print(menu_item(key, label, kind, indent))


# Plain status lines are coloured by how they start: green = done, yellow = heads-up, red = problem.
_GOOD = re.compile(r"^\s*(Saved|Target set|Applied|Reset\.|Advice discarded|Run-all finished|Open TCP ports)")
_BAD = re.compile(r"^\s*(Invalid|Could not|Cannot|Nmap exited|Refusing|Aborted|Please enter|Deep scan failed|"
                  r"Wordlist not found|No wordlist found|No valid|Model '|llm_advisor\.py was not found|"
                  r"Ollama|Lost connection|The model did not|.* is not installed)")
_WARN = re.compile(r"^\s*(Warning|Note:|Tip:|Cancelled|Set a target first|No findings yet|No live hosts|"
                   r"No open TCP|No web services|Nothing|No AI advice|Phase 3/3 skipped|These flags need root|"
                   r".* missing - skipped|gobuster or wordlist missing|nikto missing|Scope file .* not found)")
_print = builtins.print


def print(*args, **kw):                      # noqa: A001 - intentional: colours plain status lines
    if (USE_COLOR and len(args) == 1 and isinstance(args[0], str) and kw.get("file") is None
            and "\033" not in args[0]):
        t = args[0]
        if _BAD.match(t):
            args = (paint(t, "red"),)
        elif _WARN.match(t):
            args = (paint(t, "yellow"),)
        elif _GOOD.match(t):
            args = (paint(t, "green"),)
    _print(*args, **kw)

SEV_COLORS = {"critical": "7B0000", "high": "D32F2F", "medium": "F57C00",
              "low": "FBC02D", "info": "607D8B"}


# =====================================================================
# Option definitions (every flag the wizard exposes)
# =====================================================================
@dataclass
class Opt:
    key: str
    label: str
    kind: str                 # bool | int | text | choice
    flag: str | None = None   # CLI flag (None for choices / specially handled options)
    default: object = None
    choices: list | None = None   # [(value, description)]
    special: bool = False     # built by hand in the command builders
    secret: bool = False


NMAP_OPTS = [
    Opt("scan_type", "Scan technique", "choice", default="", choices=[
        ("", "default (SYN if root, else connect)"), ("-sS", "TCP SYN (root)"),
        ("-sT", "TCP connect"), ("-sU", "UDP (root, slow)"), ("-sN", "TCP NULL (root)"),
        ("-sF", "TCP FIN (root)"), ("-sX", "Xmas (root)"), ("-sA", "ACK / firewall map (root)")]),
    Opt("service", "Service/version detection (-sV)", "bool", "-sV", True),
    Opt("intensity", "Version intensity 0-9", "int", "--version-intensity"),
    Opt("os", "OS detection (-O, root)", "bool", "-O"),
    Opt("scripts_default", "Default scripts (-sC)", "bool", "-sC"),
    Opt("aggressive", "Aggressive: OS+version+scripts+traceroute (-A)", "bool", "-A"),
    Opt("timing", "Timing template", "choice", default="-T4", choices=[
        ("-T0", "paranoid"), ("-T1", "sneaky"), ("-T2", "polite"),
        ("-T3", "normal"), ("-T4", "aggressive"), ("-T5", "insane")]),
    Opt("ports", "Ports (-p): 1-1000 | 22,80,443 | - for all", "text", special=True),
    Opt("top_ports", "Top ports (ignored if -p or -F set)", "int", default="1000", special=True),
    Opt("fast", "Fast mode, 100 ports (-F; ignored if -p set)", "bool", "-F", special=True),
    Opt("skip_ping", "Skip host discovery (-Pn)", "bool", "-Pn"),
    Opt("no_dns", "No DNS resolution (-n)", "bool", "-n"),
    Opt("open_only", "Show only open ports (--open)", "bool", "--open"),
    Opt("script", "NSE scripts (e.g. http-enum,vuln)", "text", special=True),
    Opt("vulners", "Add 'vulners' CVE script", "bool", special=True),
    Opt("min_rate", "Min packet rate (--min-rate)", "int", "--min-rate"),
    Opt("max_retries", "Max retries (--max-retries)", "int", "--max-retries"),
    Opt("host_timeout", "Host timeout (--host-timeout, e.g. 30m)", "text", "--host-timeout"),
    Opt("exclude", "Exclude hosts (--exclude)", "text", "--exclude"),
    Opt("ipv6", "IPv6 scanning (-6)", "bool", "-6"),
    Opt("verbose", "Verbose (-v)", "bool", "-v"),
    Opt("extra", "Extra raw flags", "text", special=True),
]

NIKTO_OPTS = [
    Opt("tuning", "Tuning (-Tuning, e.g. 123bde)", "text", "-Tuning"),
    Opt("maxtime", "Max scan time (-maxtime, e.g. 600s)", "text", "-maxtime"),
    Opt("timeout", "Request timeout (-timeout)", "int", "-timeout"),
    Opt("pause", "Pause between requests (-Pause)", "int", "-Pause"),
    Opt("ssl", "Force SSL (-ssl)", "bool", "-ssl"),
    Opt("nossl", "Disable SSL (-nossl)", "bool", "-nossl"),
    Opt("no404", "Skip 404 guessing (-no404)", "bool", "-no404"),
    Opt("useragent", "User agent (-useragent)", "text", "-useragent"),
    Opt("evasion", "IDS evasion (-evasion, e.g. 1,2)", "text", "-evasion"),
    Opt("vhost", "Virtual host (-vhost)", "text", "-vhost"),
    Opt("plugins", "Plugins (-Plugins)", "text", "-Plugins"),
    Opt("mutate", "Mutation (-mutate)", "text", "-mutate"),
    Opt("display", "Display options (-Display)", "text", "-Display"),
    Opt("extra", "Extra raw flags", "text", special=True),
]

GOBUSTER_OPTS = [
    Opt("threads", "Threads (-t)", "int", "-t", "10"),
    Opt("extensions", "File extensions (-x, e.g. php,txt,bak)", "text", "-x"),
    Opt("status", "Show status codes (-s)", "text", default="200,204,301,302,307,401,403", special=True),
    Opt("blacklist", "Hide status codes (-b, used if -s empty)", "text", special=True),
    Opt("skip_tls", "Skip TLS verification (-k)", "bool", "-k", True),
    Opt("follow", "Follow redirects (-r)", "bool", "-r"),
    Opt("add_slash", "Append / to requests (-f)", "bool", "-f"),
    Opt("backup", "Discover backup files (-d)", "bool", "-d"),
    Opt("wildcard", "Continue on wildcard responses (--wildcard)", "bool", "--wildcard"),
    Opt("useragent", "User agent (-a)", "text", "-a"),
    Opt("headers", "Custom header (-H, 'Name: value')", "text", "-H"),
    Opt("cookies", "Cookies (-c)", "text", "-c"),
    Opt("username", "Basic-auth username (-U)", "text", "-U"),
    Opt("password", "Basic-auth password (-P)", "text", "-P", secret=True),
    Opt("timeout", "HTTP timeout (--timeout, e.g. 10s)", "text", "--timeout"),
    Opt("delay", "Delay between requests (--delay, e.g. 100ms)", "text", "--delay"),
    Opt("retry", "Retry on failure (--retry)", "bool", "--retry"),
    Opt("retry_attempts", "Retry attempts (--retry-attempts)", "int", "--retry-attempts"),
    Opt("proxy", "Proxy (--proxy)", "text", "--proxy"),
    Opt("exclude_len", "Exclude response length (--exclude-length)", "text", "--exclude-length"),
    Opt("extra", "Extra raw flags", "text", special=True),
]

OPTS = {"nmap": NMAP_OPTS, "nikto": NIKTO_OPTS, "gobuster": GOBUSTER_OPTS}

NMAP_PRESETS = {
    "Quick (-F)": {"fast": True},
    "Standard service scan": {},
    "Full TCP (-p-)": {"ports": "-"},
    "Aggressive (-A)": {"aggressive": True},
    "Stealth (SYN, polite, no ping/DNS)": {"scan_type": "-sS", "timing": "-T2",
                                           "skip_ping": True, "no_dns": True},
    "Vulnerability (vuln + vulners)": {"script": "vuln", "vulners": True},
    "UDP top 100": {"scan_type": "-sU", "top_ports": "100"},
}


def default_for(o: Opt):
    if o.default is not None:
        return o.default
    return False if o.kind == "bool" else ""


# =====================================================================
# State
# =====================================================================
def default_wordlist() -> str:
    """First wordlist that exists: Kali/dirb paths, then the mini list made by install.sh."""
    candidates = ["/usr/share/wordlists/dirb/common.txt",
                  "/usr/share/dirb/wordlists/common.txt",
                  str(Path(__file__).resolve().parent / "wordlists" / "mini.txt")]
    return next((p for p in candidates if Path(p).exists()), candidates[0])


state = {
    "target": None,
    "hosts": [],
    "findings": [],
    "runs": [],
    "tools_used": [],
    "reported": False,
    "ai": None,                 # AI advice for the current scan (set by the AI menu)
    "ai_model": None,
    "general": {
        "scope_file": "scope.txt",
        "wordlist": default_wordlist(),
        "timeout": 900,
        "threads": 4,
        "output": "reports",
    },
    "opts": {t: {o.key: default_for(o) for o in lst} for t, lst in OPTS.items()},
}


# =====================================================================
# Loading indicator + process tracking
# =====================================================================
class _Capture(logging.Handler):
    def __init__(self, sink):
        super().__init__()
        self.sink = sink

    def emit(self, record):
        self.sink.append((record.levelname, record.getMessage()))


def fmt_time(sec: float) -> str:
    sec = int(sec)
    return f"{sec // 60:02d}:{sec % 60:02d}"


class Spinner:
    """Animated 'loading' line with elapsed time and optional detail (e.g. 42%)."""

    def __init__(self, label: str):
        self.label = label
        self.detail = ""
        self.failed = False
        self._stop = threading.Event()
        self._thread = None
        self._logs = []
        enc = (sys.stdout.encoding or "").lower()
        self._frames = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏" if "utf" in enc else "|/-\\"
        self._ok = "✔" if "utf" in enc else "OK"
        self._tty = sys.stdout.isatty()

    def __enter__(self):
        self.t0 = time.time()
        lg = logging.getLogger("recon")
        self._handler = _Capture(self._logs)
        self._prop = lg.propagate
        lg.addHandler(self._handler)
        lg.propagate = False          # hold log lines until the spinner is cleared
        if self._tty:
            self._thread = threading.Thread(target=self._spin, daemon=True)
            self._thread.start()
        else:
            print(f"  {self.label} ... (running)")
        return self

    def _spin(self):
        for frame in itertools.cycle(self._frames):
            if self._stop.wait(0.1):
                break
            extra = f" ({self.detail})" if self.detail else ""
            clock = paint(f"[{fmt_time(time.time() - self.t0)}]", "grey")
            sys.stdout.write(f"\r\033[K  {paint(frame, 'bold', 'cyan')} {self.label}{paint(extra, 'yellow')}  {clock}")
            sys.stdout.flush()

    def __exit__(self, et, ev, tb):
        self._stop.set()
        if self._thread:
            self._thread.join()
            sys.stdout.write("\r\033[K")
        lg = logging.getLogger("recon")
        lg.removeHandler(self._handler)
        lg.propagate = self._prop
        took = fmt_time(time.time() - self.t0)
        if et is None and self.failed:
            print(f"  {paint('x', 'bold', 'red')} {self.label} {paint('failed after ' + took, 'red')}")
        elif et is None:
            print(f"  {paint(self._ok, 'bold', 'green')} {self.label} {paint('finished in ' + took, 'grey')}")
        else:
            print(f"  {paint('x', 'bold', 'yellow')} {self.label} {paint('stopped after ' + took, 'yellow')}")
        for level, msg in self._logs:
            print(paint(f"  [{level}] {msg}", "red" if level in ("ERROR", "CRITICAL") else "yellow"))
        return False


PROCS: set = set()
PROCS_LOCK = threading.Lock()
RUN_LOG: list = []          # one entry per Nikto/Gobuster command: rc, seconds, error text


def add_run(tool: str, target: str, rc: int, secs: float, results: str, note: str = "", command: str = ""):
    """Remember what a tool did so the report can show scan coverage (including failures)."""
    if rc == 0:
        status = "ok"
    elif rc in (124, -9):
        status = "timed out"
    else:
        status = f"failed (exit {rc})"
    state["runs"].append({"tool": tool, "target": target, "status": status, "time": fmt_time(secs),
                          "results": results, "note": note, "command": command})


def kill_all():
    with PROCS_LOCK:
        for p in list(PROCS):
            try:
                p.kill()
            except OSError:
                pass


def tracked_run(cmd, timeout):
    """Drop-in for rp.run that registers processes so Ctrl+C can stop them."""
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except FileNotFoundError:
        logging.getLogger("recon").error("Tool not found: %s", cmd[0])
        return 127, "", f"{cmd[0]} not found"
    with PROCS_LOCK:
        PROCS.add(p)
    t0 = time.time()
    rc, out, err = None, "", ""
    try:
        out, err = p.communicate(timeout=timeout)
        rc = p.returncode
        return rc, out, err
    except subprocess.TimeoutExpired:
        p.kill()
        p.communicate()
        logging.getLogger("recon").warning("Timeout after %ss: %s", timeout, cmd[0])
        rc, err = 124, "timeout"
        return rc, "", err
    finally:
        with PROCS_LOCK:
            PROCS.discard(p)
        tail = next((l.strip() for l in reversed((err or out or "").splitlines()) if l.strip()), "")
        RUN_LOG.append({"cmd": list(cmd), "rc": rc if rc is not None else -1,
                        "secs": time.time() - t0, "err": tail if rc else ""})


rp.run = tracked_run   # make the pipeline's Nikto/Gobuster runners cancellable


# =====================================================================
# Input helpers
# =====================================================================
def ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    try:
        val = input(f"{paint_prompt(prompt)}{suffix}: ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\nBye.")
        sys.exit(0)
    return val or default


def yes(prompt: str) -> bool:
    return ask(f"{prompt} (y/n)", "n").lower().startswith("y")


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def have(module: str) -> bool:
    return importlib.util.find_spec(module) is not None


def banner(step: int, title: str):
    tgt = paint(state["target"], "bold", "green") if state["target"] else paint("not set", "red")
    n = len(state["findings"])
    count = paint(n, "bold", "yellow") if n else paint(0, "grey")
    bar = paint("=" * 54, "cyan")
    print("\n" + bar)
    print("  " + paint(f"STEP {step} of 4", "bold", "cyan") + paint(" - ", "grey") + paint(title, "bold", "white"))
    print(f"  Target: {tgt}   |   Findings: {count}")
    print(bar)


# =====================================================================
# Command builders
# =====================================================================
def parse_extra(text: str, tool: str) -> list[str]:
    tokens = shlex.split(text)
    if tool == "nmap" and any(t.startswith("-o") for t in tokens):
        raise ValueError("Output flags (-oX/-oN/-oA...) are managed by the wizard.")
    return tokens


def generic_flags(tool: str) -> list[str]:
    vals, out = state["opts"][tool], []
    for o in OPTS[tool]:
        if o.special:
            continue
        v = vals[o.key]
        if o.kind == "bool":
            if v:
                out.append(o.flag)
        elif o.kind == "choice":
            if v:
                out.append(v)
        elif v != "":
            out += [o.flag, str(v)]
    return out


def nmap_cmd(target: str, xml_path: str) -> list[str]:
    o = state["opts"]["nmap"]
    cmd = ["nmap"] + generic_flags("nmap")
    if o["ports"]:
        cmd += ["-p", o["ports"]]
    elif o["fast"]:
        cmd += ["-F"]
    elif o["top_ports"]:
        cmd += ["--top-ports", str(o["top_ports"])]
    scripts = ",".join(x for x in (o["script"], "vulners" if o["vulners"] else "") if x)
    if scripts:
        cmd += ["--script", scripts]
    cmd += ["--stats-every", "3s", "-oX", xml_path]
    cmd += parse_extra(o["extra"], "nmap")
    return cmd + [target]


def nikto_flags() -> list[str]:
    return generic_flags("nikto") + parse_extra(state["opts"]["nikto"]["extra"], "nikto")


def gobuster_flags() -> list[str]:
    o = state["opts"]["gobuster"]
    flags = generic_flags("gobuster")
    if o["status"]:
        flags += ["-s", o["status"], "-b", ""]
    elif o["blacklist"]:
        flags += ["-b", o["blacklist"]]
    return flags + parse_extra(o["extra"], "gobuster")


def masked(cmd: list[str]) -> str:
    out, hide = [], False
    for tok in cmd:
        out.append("****" if hide else shlex.quote(tok))
        hide = tok == "-P"
    return " ".join(out)


# =====================================================================
# Settings editor
# =====================================================================
def show_val(o: Opt, v) -> str:
    if o.kind == "bool":
        return "ON" if v else "off"
    if o.kind == "choice":
        return next((f"{c} {d}".strip() for c, d in o.choices if c == v), v)
    if v == "":
        return "-"
    return "****" if o.secret else str(v)


def paint_val(o: Opt, v) -> str:
    txt = show_val(o, v)
    if o.kind == "bool":
        return paint(txt, "bold", "green") if v else paint(txt, "grey")
    return paint(txt, "grey") if txt == "-" else paint(txt, "cyan")


def edit_opts(tool: str, title: str):
    opts, vals = OPTS[tool], state["opts"][tool]
    while True:
        print("\n  " + paint(f"--- {title} ---", "bold", "blue"))
        for i, o in enumerate(opts, 1):
            num = paint(f"{i:>2})", "bold", "cyan")
            print(f"  {num} {o.label:<52} {paint_val(o, vals[o.key])}")
        if tool == "nmap":
            print(paint("   p) Presets", "bold", "magenta"))
        print(paint("   r) Reset to defaults", "yellow"))
        print(paint("   0) Back", "grey"))
        c = ask("  Choose a number").lower()
        if c == "0":
            return
        if c == "r":
            vals.update({o.key: default_for(o) for o in opts})
            print("  Reset.")
        elif c == "p" and tool == "nmap":
            names = list(NMAP_PRESETS)
            for i, n in enumerate(names, 1):
                print(f"    {paint(str(i) + ')', 'bold', 'magenta')} {n}")
            pick = ask("  Preset number (0 = cancel)", "0")
            if pick.isdigit() and 1 <= int(pick) <= len(names):
                vals.update({o.key: default_for(o) for o in opts})
                vals.update(NMAP_PRESETS[names[int(pick) - 1]])
                print(f"  Applied: {names[int(pick) - 1]}")
        elif c.isdigit() and 1 <= int(c) <= len(opts):
            edit_one(tool, opts[int(c) - 1], vals)
        else:
            print("  Invalid choice.")


def edit_one(tool: str, o: Opt, vals: dict):
    if o.kind == "bool":
        vals[o.key] = not vals[o.key]
        return
    if o.kind == "choice":
        for i, (c, d) in enumerate(o.choices, 1):
            print(f"    {paint(str(i) + ')', 'bold', 'cyan')} {paint((c + ' ').lstrip(), 'cyan')}{d}")
        pick = ask("  Pick a number", "")
        if pick.isdigit() and 1 <= int(pick) <= len(o.choices):
            vals[o.key] = o.choices[int(pick) - 1][0]
        return
    cur = "" if o.secret else str(vals[o.key])
    new = ask(f"  {o.label} (Enter = keep, '-' = clear)", cur)
    if new == "-":
        vals[o.key] = ""
    elif o.kind == "int" and not new.isdigit():
        print("  Please enter a whole number.")
    elif o.key == "extra":
        try:
            parse_extra(new, tool)
            vals[o.key] = new
        except ValueError as e:
            print(f"  {e}")
    else:
        vals[o.key] = new


def general_settings():
    g = state["general"]
    items = [("scope_file", "Scope file", str), ("wordlist", "Gobuster wordlist", str),
             ("timeout", "Per-tool timeout (seconds)", int),
             ("threads", "Parallel web jobs", int), ("output", "Output folder", str)]
    while True:
        print("\n  " + paint("--- General settings ---", "bold", "blue"))
        for i, (k, label, _) in enumerate(items, 1):
            print(f"  {paint(str(i) + ')', 'bold', 'cyan')} {label:<28} {paint(g[k], 'cyan')}")
        print(paint("  0) Back", "grey"))
        c = ask("  Choose a number")
        if c == "0":
            return
        if c.isdigit() and 1 <= int(c) <= len(items):
            k, label, typ = items[int(c) - 1]
            new = ask(f"  {label}", str(g[k]))
            try:
                g[k] = max(1, int(new)) if typ is int else new
            except ValueError:
                print("  Please enter a number.")


def preview_commands():
    t = state["target"] or "<target>"
    g = state["general"]
    print("\n  " + paint("Commands that will run with the current settings:", "bold") + "\n")
    try:
        print(paint("  Nmap    :", "bold", "blue"), paint(masked(nmap_cmd(t, "<out.xml>")), "grey"))
        print(paint("  Nikto   :", "bold", "orange"), paint(masked(["nikto", "-h", "<url>", "-Format", "json", "-output",
                                     "<tmp.json>", "-nointeractive"] + nikto_flags()), "grey"))
        print(paint("  Gobuster:", "bold", "cyan"), paint(masked(["gobuster", "dir", "-u", "<url>", "-w", g["wordlist"],
                                     "-q", "--no-color"] + gobuster_flags()), "grey"))
    except ValueError as e:
        print(f"  {e}")


def settings_menu():
    while True:
        print("\n  " + paint("--- Settings ---", "bold", "blue"))
        show_menu([("1", "General (scope file, wordlist, timeout, threads, output)", "settings"),
                   ("2", "Nmap flags", "nmap"), ("3", "Nikto flags", "nikto"),
                   ("4", "Gobuster flags", "gobuster"), ("5", "Preview the exact commands", "view"),
                   ("0", "Back", "back")])
        c = ask("  Choose a number")
        if c == "1":
            general_settings()
        elif c == "2":
            edit_opts("nmap", "Nmap flags")
        elif c == "3":
            edit_opts("nikto", "Nikto flags")
        elif c == "4":
            edit_opts("gobuster", "Gobuster flags")
        elif c == "5":
            preview_commands()
        elif c == "0":
            return
        else:
            print("  Invalid choice.")


# =====================================================================
# Step 1 actions
# =====================================================================
def set_target():
    target = ask("Target (IP, CIDR, or hostname)")
    if not target:
        return
    g = state["general"]
    scope_path = Path(ask("Scope file", g["scope_file"]))
    g["scope_file"] = str(scope_path)
    if not scope_path.exists():
        print(f"  Scope file '{scope_path}' not found.")
        if yes(f"  Create it containing only {target} (you confirm you own it / are authorized)?"):
            scope_path.write_text(f"{target}\n")
        else:
            return
    if not rp.in_scope(target, rp.load_scope(scope_path)):
        print(f"  {target} is NOT in {scope_path}. Add it there first.")
        return
    if not yes("  Do you have written permission to test this target?"):
        print("  Aborted. Only test systems you are authorized to test.")
        return
    RUN_LOG.clear()
    state.update(target=target, hosts=[], findings=[], runs=[], tools_used=[], reported=False,
                 ai=None, ai_model=None)
    print(f"  Target set: {target}")


def okmiss(ok: bool, extra: str = "") -> str:
    return (paint("OK     ", "bold", "green") if ok else paint("MISSING", "bold", "red")) + (f" {extra}" if extra else "")


def check_tools():
    print("\n  " + paint("Scanners:", "bold", "cyan"))
    for t in ("nmap", "nikto", "gobuster"):
        p = shutil.which(t)
        print(f"    {t:<10} {okmiss(bool(p), p or '')}")
    root_txt = paint("yes", "bold", "green") if is_root() else paint("no (SYN/UDP scans and -O need sudo)", "yellow")
    print(f"    root/admin {root_txt}")
    wl = Path(state["general"]["wordlist"])
    print(f"    wordlist   {okmiss(wl.exists(), str(wl))}")
    print("\n  " + paint("Report formats:", "bold", "cyan"))
    pdf = "weasyprint" if have("weasyprint") else ("reportlab" if have("reportlab") else None)
    rows = [("HTML / Markdown / CSV / JSON / TXT", True, ""),
            ("PDF", pdf is not None, f"via {pdf}" if pdf else "pip install weasyprint  (or reportlab)"),
            ("Word (.docx)", have("docx"), "" if have("docx") else "pip install python-docx")]
    for name, ok, note in rows:
        print(f"    {name:<36} {okmiss(ok)}  {paint(note, 'yellow')}")


# =====================================================================
# Step 2 actions
# =====================================================================
def need_target() -> bool:
    if not state["target"]:
        print("  Set a target first (Step 1, option 1).")
        return False
    return True


def need_tool(name: str) -> bool:
    if shutil.which(name):
        return True
    print(f"  {name} is not installed or not on PATH.")
    return False


def mark_tool(name: str):
    if name not in state["tools_used"]:
        state["tools_used"].append(name)


def replace_findings(prefix: str, new: list, host=None, port=None):
    def stale(f):
        return f.source.startswith(prefix) and (host is None or (f.host == host and f.port == port))
    state["findings"] = [f for f in state["findings"] if not stale(f)] + new


def cancellable(fn):
    def wrapper(*a, **k):
        try:
            return fn(*a, **k)
        except KeyboardInterrupt:
            kill_all()
            print("\n  Cancelled.")
    return wrapper


PCT = re.compile(r"About\s+([\d.]+)%\s+done")


def nmap_exec(cmd: list[str], timeout: int, spin: Spinner):
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         text=True, bufsize=1)
    with PROCS_LOCK:
        PROCS.add(p)
    timer = threading.Timer(timeout, p.kill)
    timer.start()
    lines = []
    try:
        for line in p.stdout:
            lines.append(line.rstrip())
            m = PCT.search(line)
            if m:
                spin.detail = f"{float(m.group(1)):.0f}% done"
    finally:
        timer.cancel()
        p.wait()
        with PROCS_LOCK:
            PROCS.discard(p)
    return p.returncode, lines


# ---------------------------------------------------------------------
# Nmap AUTO mode: 3 phases, picks every useful compatible flag by itself
# ---------------------------------------------------------------------
def nmap_script_dirs() -> list[str]:
    dirs = ["/usr/share/nmap/scripts", "/usr/local/share/nmap/scripts",
            "/opt/homebrew/share/nmap/scripts"]
    exe = shutil.which("nmap")
    if exe:
        dirs.append(str(Path(exe).resolve().parent.parent / "share" / "nmap" / "scripts"))
    return [d for d in dirs if Path(d).is_dir()]


def script_available(name: str) -> bool:
    return any((Path(d) / f"{name}.nse").exists() for d in nmap_script_dirs())


def shorten(text: str, n: int = 240) -> str:
    text = " ".join(str(text).split())
    if len(text) <= n:
        return text
    return text[:n].rsplit(" ", 1)[0] + " ..."


CRITICAL_IDS = re.compile(r"heartbleed|ms17-010|ms08-067|ms12-020|shellshock|cve2017-5638|"
                          r"cve2014-3704|distcc|vsftpd-backdoor|unrealircd|ccs-injection")


def classify_vuln(sid: str, text: str):
    """Return (severity, title, evidence) for an NSE script that reports VULNERABLE."""
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    idx = next((i for i, l in enumerate(lines) if "VULNERABLE:" in l and "STATE" not in l.upper()), -1)
    headline = lines[idx + 1] if 0 <= idx + 1 < len(lines) else ""
    m = re.search(r"State:\s*(LIKELY VULNERABLE|VULNERABLE)", text)
    state_txt = m.group(1) if m else "VULNERABLE"
    cves = sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", text)))
    likely = state_txt.startswith("LIKELY")
    low = (sid + " " + headline).lower()

    if re.search(r"slowloris|dos\b|denial", low):
        sev = "low" if likely else "medium"            # availability only, no data exposure
    elif "dh-params" in low or "diffie" in low:
        sev = "medium"                                   # weak key exchange, needs a network position
    elif CRITICAL_IDS.search(sid.lower()) and not likely:
        sev = "critical"
    else:
        sev = "medium" if likely else "high"
    title = headline or f"{sid}: vulnerable"
    if cves:
        title += f" ({', '.join(cves[:3])})"
    evidence = f"{sid} reports {state_txt}" + (" (not confirmed - verify manually)" if likely else "")
    return sev, title, evidence


def parse_nmap_scripts(xml_path: str) -> list:
    """Turn NSE script output and OS fingerprints into findings."""
    out = []
    root = ET.parse(xml_path).getroot()
    for h in root.findall("host"):
        a = h.find("address[@addrtype='ipv4']")
        if a is None:
            a = h.find("address")
        addr = a.get("addr") if a is not None else "unknown"
        m = h.find("os/osmatch")
        if m is not None:
            out.append(rp.Finding(addr, None, "os", f"OS guess: {m.get('name')} ({m.get('accuracy')}%)",
                                  "info", "Nmap OS fingerprint (a guess - verify manually)", "nmap-os"))
        for p in h.findall("ports/port"):
            port = int(p.get("portid"))
            svc = p.find("service")
            name = svc.get("name", "unknown") if svc is not None else "unknown"
            for sc in p.findall("script"):
                sid, text = sc.get("id", ""), sc.get("output", "")
                if sid == "vulners":
                    continue                      # CVEs already handled by the pipeline parser
                if "VULNERABLE" in text and "NOT VULNERABLE" not in text:
                    sev, title, ev = classify_vuln(sid, text)
                    out.append(rp.Finding(addr, port, name, title, sev, ev, "nmap-vuln"))
                elif sid == "ssl-enum-ciphers":
                    weak = sorted(set(re.findall(r"SSLv3|TLSv1\.0|TLSv1\.1", text)))
                    grade = re.search(r"least strength:\s*([A-F])", text)
                    if weak or (grade and grade.group(1) in "DEF"):
                        warn = re.search(r"warnings:\s*\n?\s*(.+)", text)
                        ev = (f"Offers {', '.join(weak)}" if weak else "Weak cipher offered")
                        if grade:
                            ev += f"; weakest cipher grade {grade.group(1)}"
                        if warn:
                            ev += f"; {warn.group(1).strip()}"
                        out.append(rp.Finding(addr, port, name,
                                              "Weak TLS configuration" + (f" ({', '.join(weak)})" if weak else ""),
                                              "medium", ev, "nmap-tls"))
                elif sid == "http-enum":
                    paths = list(dict.fromkeys(l.strip().lstrip("|_ ").strip() for l in text.splitlines()
                                               if l.strip().startswith("/") or "/" in l))
                    admin = "admin" in text.lower()
                    out.append(rp.Finding(addr, port, name, "Interesting web paths found",
                                          "low" if admin else "info", shorten("; ".join(paths) or text), "nmap-http"))
                elif sid == "http-title":
                    out.append(rp.Finding(addr, port, name, f"Page title: {shorten(text, 80)}", "info",
                                          "http-title", "nmap-http"))
                elif sid == "http-server-header":
                    uniq = list(dict.fromkeys(l.strip() for l in text.splitlines() if l.strip()))
                    out.append(rp.Finding(addr, port, name, f"Server header: {shorten('; '.join(uniq), 80)}",
                                          "info", "http-server-header", "nmap-http"))
    return out


def run_phase(label: str, cmd: list[str], timeout: int):
    fd, path = tempfile.mkstemp(suffix=".xml")
    os.close(fd)
    cmd = [path if t == "{XML}" else t for t in cmd]
    print(paint("   $ " + masked(cmd), "grey"))
    t0 = time.time()
    with Spinner(label) as sp:
        rc, lines = nmap_exec(cmd, timeout, sp)
        if rc != 0:
            sp.failed = True
    shown = [t if t != path else "<out.xml>" for t in cmd]
    add_run("nmap", state["target"], rc, time.time() - t0, "", label,
            masked(shown))
    if rc != 0:
        state["runs"][-1]["note"] = label + ": " + (lines[-1] if lines else "")
        print(f"  Nmap exited with code {rc}. Last output:")
        for ln in lines[-5:]:
            print("    " + ln)
        Path(path).unlink(missing_ok=True)
        return None
    return path


def port_line(p: dict) -> str:
    pp = paint(f"{p['port']:>5}/{p['proto']:<4}", "bold", "green")
    sv = paint(f"{p['service']:<14}", "cyan")
    return f"    {pp} {sv} {p['banner']}"


def show_hosts(hosts, findings):
    for h in hosts:
        print("\n  " + paint(f"{h.address} {h.hostname}", "bold", "green"))
        for f in findings:
            if f.host == h.address and f.source == "nmap-os":
                print(paint(f"    {f.title}", "yellow"))
        for p in sorted(h.open_ports, key=lambda x: (x["proto"], x["port"])):
            print(port_line(p))
    vulns = [f for f in findings if f.severity in ("critical", "high")]
    print("\n  " + paint(f"{len(findings)} finding(s) stored, ", "bold", "green")
          + (paint(f"{len(vulns)} high/critical.", "bold", "red") if vulns else paint("0 high/critical.", "green")))


def auto_nmap():
    target, root = state["target"], is_root()
    timeout = state["general"]["timeout"]
    scripts = ["default", "vuln"]
    notes = []
    for name in ("vulners", "http-enum", "ssl-enum-ciphers"):
        if script_available(name):
            scripts.append(name)
        else:
            notes.append(name)
    print("\n  " + paint("AUTO mode - Nmap picks the flags for you:", "bold", "blue"))
    print("    Phase 1: all 65,535 TCP ports (fast)      Phase 2: versions + OS + scripts + vulns on open ports")
    print(f"    Phase 3: top UDP ports {'(root: yes)' if root else '(skipped - needs root)'}")
    if not root:
        print("    Tip: run with sudo for OS detection, traceroute, SYN and UDP scans.")
    if notes:
        print(f"    Not installed (skipped): {', '.join(notes)}  - run install.sh to add them")

    # ---- Phase 1: port discovery
    cmd1 = ["nmap"] + (["-sS"] if root else []) + ["-Pn", "-n", "-p-", "-T4", "--min-rate", "1000",
                                                    "--open", "--stats-every", "3s", "-oX", "{XML}", target]
    p1 = run_phase("Phase 1/3 - finding open ports (all 65,535)", cmd1, timeout)
    if not p1:
        return
    try:
        hosts1, findings1 = rp.parse_nmap(p1)
    except ET.ParseError:
        print("  Could not read Phase 1 results.")
        return
    finally:
        Path(p1).unlink(missing_ok=True)
    ports = sorted({p["port"] for h in hosts1 for p in h.open_ports if p["proto"] == "tcp"})
    if not ports:
        print("  No open TCP ports found - nothing more to scan.")
        return
    print(f"  Open TCP ports: {','.join(map(str, ports))}")
    state["runs"][-1]["results"] = f"{len(ports)} open TCP port(s)"

    # ---- Phase 2: deep scan on the open ports only
    cmd2 = ["nmap", "-Pn", "-n", "-sV", "--version-intensity", "7", "-T4", "-p", ",".join(map(str, ports)),
            "--script", ",".join(scripts), "--script-timeout", "120s", "--stats-every", "3s",
            "-oX", "{XML}", target]
    if root:
        cmd2[1:1] = ["-sS", "-O", "--osscan-guess", "--traceroute"]
    p2 = run_phase("Phase 2/3 - deep scan (versions, OS, scripts, vulnerabilities)", cmd2, max(timeout, 1800))
    hosts, findings = hosts1, findings1
    if p2:
        try:
            hosts, findings = rp.parse_nmap(p2)
            findings += parse_nmap_scripts(p2)
            state["runs"][-1]["results"] = f"{len(findings)} observation(s)"
        except ET.ParseError:
            print("  Could not read Phase 2 results - using Phase 1 results only.")
        finally:
            Path(p2).unlink(missing_ok=True)
    else:
        print("  Deep scan failed - keeping the Phase 1 port list.")

    # ---- Phase 3: UDP (root only, never fatal)
    if root:
        cmd3 = ["nmap", "-Pn", "-n", "-sU", "--top-ports", "20", "--max-retries", "1", "-T4",
                "--open", "--stats-every", "3s", "-oX", "{XML}", target]
        p3 = run_phase("Phase 3/3 - UDP top 20 ports", cmd3, timeout)
        if p3:
            try:
                hosts3, findings3 = rp.parse_nmap(p3)
                by_addr = {h.address: h for h in hosts}
                for h3 in hosts3:
                    if h3.address in by_addr:
                        by_addr[h3.address].open_ports += h3.open_ports
                findings += findings3
                state["runs"][-1]["results"] = f"{sum(len(h.open_ports) for h in hosts3)} open UDP port(s)"
            except ET.ParseError:
                pass
            finally:
                Path(p3).unlink(missing_ok=True)
    else:
        print("  Phase 3/3 skipped (UDP scanning needs root).")

    state["hosts"] = hosts
    replace_findings("nmap", findings)
    mark_tool("nmap")
    show_hosts(hosts, findings)


ROOT_ONLY = {"-O", "-A", "-sS", "-sU", "-sN", "-sF", "-sX", "-sA"}
DEDUPE = {"-sV", "-sC", "-Pn", "-n", "-v", "--open", "-F"}


def preflight(cmd: list[str]):
    """Fix flag combinations that would make Nmap quit. Returns the cmd, or None to cancel."""
    target = state["target"]
    if "-6" in cmd:
        import socket
        try:
            socket.getaddrinfo(target, None, socket.AF_INET6)
        except socket.gaierror:
            print("  Note: -6 (IPv6) is on but the target has no IPv6 address - removing -6 for this scan.")
            cmd = [t for t in cmd if t != "-6"]
    if not is_root():
        bad = [t for t in cmd if t in ROOT_ONLY]
        if bad:
            print(f"  These flags need root and would make Nmap quit: {' '.join(bad)}")
            if not yes("  Run without them for this scan? (or answer n and restart with sudo)"):
                print("  Cancelled. Restart with: sudo python3 recon_wizard.py")
                return None
            fixed = []
            for t in cmd:
                if t == "-A":
                    fixed += ["-sV", "-sC"]       # keep the non-root parts of -A
                elif t not in ROOT_ONLY:
                    fixed.append(t)
            cmd = fixed
    seen, out = set(), []                       # drop harmless duplicate flags like -sV -sV
    for t in cmd:
        if t in DEDUPE and t in seen:
            continue
        seen.add(t)
        out.append(t)
    return out


@cancellable
def do_nmap(auto=None):
    if not need_target() or not need_tool("nmap"):
        return
    if auto is None:
        print("  " + paint("Nmap mode:", "bold"))
        show_menu([("1", "AUTO   - runs all the useful flags by itself (recommended)", "all"),
                   ("2", "MANUAL - uses the flags from Step 1 > Settings", "settings")], indent="    ")
        auto = ask("  Choose", "1") != "2"
    if auto:
        return auto_nmap()
    fd, xml_path = tempfile.mkstemp(suffix=".xml")
    os.close(fd)
    try:
        cmd = nmap_cmd(state["target"], xml_path)
    except ValueError as e:
        print(f"  {e}")
        Path(xml_path).unlink(missing_ok=True)
        return
    cmd = preflight(cmd)
    if cmd is None:
        Path(xml_path).unlink(missing_ok=True)
        return
    print(paint("  Command: " + masked(cmd), "grey"))
    try:
        t0 = time.time()
        with Spinner("Nmap scan") as spin:
            rc, lines = nmap_exec(cmd, state["general"]["timeout"], spin)
            if rc != 0:
                spin.failed = True          # spinner prints "failed" instead of a tick
        add_run("nmap", state["target"], rc, time.time() - t0, "", "manual flags",
                masked([t if t != xml_path else "<out.xml>" for t in cmd]))
        if rc != 0:
            print(f"  Nmap exited with code {rc}. Last output:")
            for ln in lines[-6:]:
                print("    " + ln)
            return
        hosts, findings = rp.parse_nmap(xml_path)
    except (ET.ParseError, FileNotFoundError):
        print("  Could not read Nmap results (scan interrupted or timed out?).")
        return
    finally:
        Path(xml_path).unlink(missing_ok=True)
    if not hosts:
        print("  No live hosts or open ports found.")
        return
    state["hosts"] = hosts
    replace_findings("nmap", findings)
    mark_tool("nmap")
    state["runs"][-1]["results"] = f"{sum(len(h.open_ports) for h in hosts)} open port(s)"
    for h in hosts:
        print("\n  " + paint(f"{h.address} {h.hostname}", "bold", "green"))
        for p in h.open_ports:
            print(port_line(p))
    print(paint(f"\n  {len(findings)} Nmap finding(s) stored.", "bold", "green"))


def host_in_scope(host: str) -> bool:
    path = Path(state["general"]["scope_file"])
    return path.exists() and rp.in_scope(host, rp.load_scope(path))


def pick_web_targets():
    found = rp.web_targets(state["hosts"])
    if found:
        print("  Web services found by Nmap:")
        for i, (_, _, url) in enumerate(found, 1):
            print(f"    {paint(str(i) + ')', 'bold', 'cyan')} {url}")
        print("    " + paint("a) all", "bold", "yellow") + "      " + paint("u) type a URL manually", "bold", "blue"))
        c = ask("  Choose", "a").lower()
        if c == "a":
            return found
        if c.isdigit() and 1 <= int(c) <= len(found):
            return [found[int(c) - 1]]
    url = ask("  Full URL (e.g. http://192.168.56.101:8080)")
    u = urlparse(url)
    if not u.scheme or not u.hostname:
        print("  Invalid URL.")
        return []
    if not host_in_scope(u.hostname):
        print(f"  {u.hostname} is not in the scope file. Aborting.")
        return []
    return [(u.hostname, u.port or (443 if u.scheme == "https" else 80), url.rstrip("/"))]


# ---------------------------------------------------------------------
# Nikto / Gobuster AUTO mode
# ---------------------------------------------------------------------
WORDLIST_CANDIDATES = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/dirb/wordlists/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
    str(Path(__file__).resolve().parent / "wordlists" / "mini.txt"),
]


def auto_wordlist():
    """The wordlist from Settings if it exists, otherwise the first one found on this system."""
    chosen = state["general"]["wordlist"]
    if Path(chosen).exists():
        return chosen
    return next((w for w in WORDLIST_CANDIDATES if Path(w).exists()), None)


def ask_auto(tool: str) -> bool:
    print("  " + paint(f"{tool} mode:", "bold"))
    show_menu([("1", "AUTO   - picks all the useful flags by itself (recommended)", "all"),
               ("2", "MANUAL - uses the flags from Step 1 > Settings", "settings")], indent="    ")
    return ask("  Choose", "1") != "2"


def nikto_auto_flags() -> list[str]:
    # Everything except test group 6 (denial of service) so the target is not knocked over.
    # -maxtime ends Nikto cleanly before our hard timeout, so its results are still saved.
    maxtime = max(120, state["general"]["timeout"] - 60)
    return ["-Tuning", "012345789abcde", "-C", "all", "-timeout", "10", "-maxtime", f"{maxtime}s"]


def auto_extensions(host: str, port: int) -> str:
    """Pick file extensions to try, based on what Nmap found on that port."""
    info = ""
    for h in state["hosts"]:
        if h.address == host:
            for pt in h.open_ports:
                if pt["port"] == port:
                    info = f"{pt['service']} {pt['banner']}".lower()
    exts = ["txt", "html", "bak", "old", "zip", "conf"]
    java = any(k in info for k in ("tomcat", "jetty", "jsp", "java", "coyote", "weblogic", "glassfish"))
    ms = any(k in info for k in ("iis", "asp", "microsoft", "windows"))
    php = any(k in info for k in ("php", "httpd", "nginx", "lighttpd", "litespeed"))
    if java:
        exts += ["jsp", "do", "action"]
    if ms:
        exts += ["asp", "aspx", "config"]
    if php:
        exts += ["php"]
    if not (java or ms or php):
        exts += ["php", "asp", "aspx", "jsp"]
    return ",".join(dict.fromkeys(exts))


_GB_HELP = None


def gobuster_supports(flag: str) -> bool:
    """Ask the installed Gobuster whether it knows a flag (older versions lack some)."""
    global _GB_HELP
    if _GB_HELP is None:
        try:
            r = subprocess.run(["gobuster", "dir", "--help"], capture_output=True, text=True, timeout=10)
            _GB_HELP = r.stdout + r.stderr
        except (OSError, subprocess.SubprocessError):
            _GB_HELP = ""
    return not _GB_HELP or flag in _GB_HELP      # can't tell -> assume a modern version


def gobuster_auto_flags(host: str, port: int) -> list[str]:
    flags = ["-t", "20", "-k", "-x", auto_extensions(host, port)]
    if gobuster_supports("--discover-backup"):
        flags += ["-d"]                          # also look for backup copies of found files
    if gobuster_supports("--timeout"):
        flags += ["--timeout", "10s"]
    if gobuster_supports("--retry-attempts"):
        flags += ["--retry", "--retry-attempts", "2"]
    return flags + ["-s", "200,204,301,302,307,401,403", "-b", ""]


def run_web_jobs(tools: list[str], targets: list, auto: bool = False):
    g = state["general"]
    wordlist = g["wordlist"]
    try:
        if auto:
            nf = nikto_auto_flags()
            wordlist = auto_wordlist()
            if "gobuster" in tools and not wordlist:
                print("  No wordlist found - skipping Gobuster (run install.sh).")
                tools = [t for t in tools if t != "gobuster"]
                if not tools:
                    return
            gf_for = gobuster_auto_flags
        else:
            nf, gf = nikto_flags(), gobuster_flags()
            gf_for = lambda host, port: gf
    except ValueError as e:
        print(f"  {e}")
        return
    mode = "AUTO" if auto else "manual"
    if "nikto" in tools:
        print(f"  Nikto flags ({mode}):", masked(nf) or "(defaults)")
    if "gobuster" in tools:
        print(f"  Gobuster wordlist ({mode}): {wordlist}")
        for host, port, url in targets:
            print(f"  Gobuster flags {url}:", masked(gf_for(host, port)))

    jobs = []
    with ThreadPoolExecutor(max_workers=g["threads"]) as pool:
        for host, port, url in targets:
            if "nikto" in tools:
                jobs.append(("nikto", host, port, url,
                             pool.submit(rp.run_nikto, host, port, url, g["timeout"], nf)))
            if "gobuster" in tools:
                jobs.append(("gobuster", host, port, url,
                             pool.submit(rp.run_gobuster, host, port, url, wordlist,
                                         g["timeout"], gf_for(host, port), False)))
        futs = [j[4] for j in jobs]
        label = " + ".join(t.capitalize() for t in tools)
        with Spinner(f"{label} on {len(targets)} target(s)") as sp:
            try:
                while True:
                    done = sum(f.done() for f in futs)
                    sp.detail = f"{done}/{len(futs)} jobs done"
                    if done == len(futs):
                        break
                    time.sleep(0.2)
            except KeyboardInterrupt:
                kill_all()
                for f in futs:
                    f.cancel()
                raise
    for name, host, port, url, fut in jobs:
        try:
            res = fut.result()
        except Exception as e:
            print(f"  {name} failed on {url}: {e}")
            continue
        replace_findings(name, res, host, port)
        mark_tool(name)
        log = next((e for e in reversed(RUN_LOG) if e["cmd"][0] == name and url in e["cmd"]), None)
        add_run(name, url, log["rc"] if log else 0, log["secs"] if log else 0.0,
                f"{len(res)} finding(s)", log["err"] if log else "",
                masked((log["cmd"] if log else [name])[:]))
        flag = "" if (log is None or log["rc"] == 0) else f"   <- {state['runs'][-1]['status']}: {log['err'][:70]}"
        if not res and not flag:
            flag = "   <- no results (see Scan Coverage in the report)"
        print(f"    {name:<9} {url}: {len(res)} finding(s){flag}")


@cancellable
def do_web_tool(name: str):
    if not need_target() or not need_tool(name):
        return
    auto = ask_auto(name.capitalize())
    if name == "gobuster" and not auto and not Path(state["general"]["wordlist"]).exists():
        print(f"  Wordlist not found: {state['general']['wordlist']} (change it in Step 1 > Settings).")
        return
    targets = pick_web_targets()
    if targets:
        run_web_jobs([name], targets, auto=auto)


@cancellable
def do_all():
    if not need_target():
        return
    do_nmap(auto=True)
    if not state["hosts"]:
        return
    webs = rp.web_targets(state["hosts"])
    if not webs:
        print("  No web services found; skipping Nikto and Gobuster.")
        return
    tools = []
    if shutil.which("nikto"):
        tools.append("nikto")
    else:
        print("  nikto missing - skipped.")
    if shutil.which("gobuster") and auto_wordlist():
        tools.append("gobuster")
    else:
        print("  gobuster or wordlist missing - skipped.")
    if tools:
        run_web_jobs(tools, webs, auto=True)
    print("  Run-all finished. Continue to Step 3 to view or export results.")


# =====================================================================
# Step 3: findings
# =====================================================================
def view_findings():
    if not state["findings"]:
        print("  No findings yet. Run a scan in Step 2.")
        return
    order = {s: i for i, s in enumerate(rp.SEVERITIES)}
    counts = {s: sum(1 for f in state["findings"] if f.severity == s) for s in rp.SEVERITIES}
    print("\n  " + "  ".join(paint(f"{s}={n}", *(SEV_STYLE[s] if n else ("grey",))) for s, n in counts.items()))
    minimum = ask("  Minimum severity to show (critical/high/medium/low/info)", "info").lower()
    if minimum not in order:
        minimum = "info"
    items = sorted((f for f in state["findings"] if order[f.severity] <= order[minimum]),
                   key=lambda f: (order[f.severity], f.host, f.port or 0))
    for f in items[:300]:
        print(f"  {sev_tag(f.severity)} {f.host}:{str(f.port or '-'):<5} {f.title[:90]}  {paint('(' + f.source + ')', 'grey')}")
    if len(items) > 300:
        print(f"  ... {len(items) - 300} more (export a report to see everything)")


# =====================================================================
# AI advisor (local Llama through Ollama) - Step 3 > AI advice
# =====================================================================
import hashlib


def fingerprint(groups: list) -> str:
    """Identifies the exact findings the AI advice was written for."""
    raw = json.dumps([(g["severity"], g["title"], g["affected"]) for g in groups], sort_keys=True)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def current_ai(groups: list):
    """AI advice for the report - only if it still matches the findings (re-scans invalidate it)."""
    ai = state.get("ai")
    if ai and ai.get("fingerprint") == fingerprint(groups):
        return ai
    return None


def ai_ready() -> bool:
    if llm_advisor is None:
        print("  llm_advisor.py was not found next to recon_wizard.py.")
        return False
    if not state["findings"]:
        print("  No findings yet. Run a scan in Step 2 first.")
        return False
    return True


def get_advisor():
    """Create the advisor and check Ollama + model. Returns None (with a message) if unavailable."""
    adv = llm_advisor.Advisor()
    try:
        state["ai_model"] = adv.check()
    except llm_advisor.AdvisorError as e:
        print(f"  {e}")
        return None
    return adv


def ai_call(label: str, fn):
    """Run one model task with the spinner; returns the result or None."""
    try:
        with Spinner(f"Llama ({state['ai_model']}): {label}") as sp:
            sp.detail = "loading model - the first answer can take a minute"

            def tick(n):
                sp.detail = f"{n} tokens written"
            return fn(tick)
    except llm_advisor.AdvisorError as e:
        print(f"  {e}")
        return None


def ai_store() -> dict:
    ai = state.get("ai")
    groups = group_findings(state["findings"])
    fp = fingerprint(groups)
    if not ai or ai.get("fingerprint") != fp:
        ai = {"fingerprint": fp, "model": state["ai_model"], "summary": "", "findings": {}, "plan": []}
        state["ai"] = ai
    ai["model"] = state["ai_model"]
    return ai


def print_wrapped(text: str, indent="    ", label: str = "", style: tuple = ()):
    """Word-wrap text; an optional label on the first line is painted in `style`."""
    import textwrap
    lines = textwrap.wrap((f"{label} " if label else "") + text, 92) or [""]
    for n, line in enumerate(lines):
        if n == 0 and label:
            line = paint(label, *style) + line[len(label):]
        print(indent + line)


FP_STYLE = {"low": ("bold", "green"), "medium": ("bold", "yellow"), "high": ("bold", "red"), "unknown": ("grey",)}


def ai_analyze(adv, ai: dict):
    """Summary + per-finding advice + action plan in one go."""
    ctx = build_ctx()
    summ = ai_call("writing summary", lambda cb: adv.summary(ctx, on_token=cb))
    if summ:
        ai["summary"] = summ
    ex = ai_call("explaining findings", lambda cb: adv.explain(ctx, on_token=cb))
    if ex:
        ai["findings"] = ex
    plan = ai_call("building action plan", lambda cb: adv.plan(ctx, on_token=cb))
    if plan:
        ai["plan"] = plan


def ai_show(ai: dict):
    groups = group_findings(state["findings"])
    if ai.get("summary"):
        print("\n  " + paint("AI SUMMARY", "bold", "magenta"))
        print_wrapped(ai["summary"])
    if ai.get("plan"):
        print("\n  " + paint("AI ACTION PLAN", "bold", "magenta"))
        for i, st in enumerate(ai["plan"], 1):
            print(f"    {paint(str(i) + '.', 'bold', 'yellow')} {paint(st['step'], 'bold')}")
            if st["why"]:
                print_wrapped(st["why"], "       ")
    if ai.get("findings"):
        print("\n  " + paint("AI ADVICE PER FINDING", "bold", "magenta"))
        for i, g in enumerate(groups[:40], 1):
            a = ai["findings"].get(i)
            if not a:
                continue
            print(f"\n   {sev_tag(g['severity'])} {paint(g['title'][:80], 'bold')}")
            print_wrapped(a["explain"], label="Meaning:", style=("bold", "cyan"))
            print_wrapped(a["verify"], label="Verify: ", style=("bold", "blue"))
            print_wrapped(a["fix"], label="Fix:    ", style=("bold", "green"))
            fp = a["false_positive"]
            print("    " + paint("False-positive chance:", "bold", "yellow") + " "
                  + paint(fp.upper(), *FP_STYLE.get(fp, ("grey",))) + paint(f" - {a['reason']}", "grey"))
    print(paint("\n  AI text is a second opinion from a small local model. Verify before acting on it.", "grey"))


def ai_chat(adv):
    ctx = build_ctx()
    history = []
    print("  Ask anything about this scan (empty line to stop). Examples: 'what should I fix first?',")
    print("  'is the Slowloris finding real?', 'explain the TLS issue simply'.")
    while True:
        q = ask("\n  You")
        if not q:
            return
        ans = ai_call("thinking", lambda cb: adv.ask(ctx, history, q, on_token=cb))
        if ans:
            history.append((q, ans))
            print_wrapped(ans, "  ", label="Llama:", style=("bold", "magenta"))


@cancellable
def ai_menu():
    if not ai_ready():
        return
    adv = get_advisor()
    if adv is None:
        return
    while True:
        ai = state.get("ai") if current_ai(group_findings(state["findings"])) else None
        status = (paint("advice ready - included in reports", "green") if ai
                  else paint("no advice yet", "yellow"))
        print("\n  " + paint("--- AI advice ", "bold", "magenta") + paint(f"(model: {state['ai_model']}, ", "magenta")
              + status + paint(") ---", "magenta"))
        show_menu([("1", "Full analysis: summary + advice per finding + action plan", "ai"),
                   ("2", "Executive summary only", "plain"), ("3", "Advice per finding only", "plain"),
                   ("4", "Action plan only", "plain"), ("5", "Ask Llama a question", "target"),
                   ("6", "Show saved advice", "view"), ("7", "Save Llama report as PDF", "report"),
                   ("8", "Discard advice", "exit"), ("0", "Back", "back")])
        c = ask("  Select")
        if c == "1":
            store = ai_store(); ai_analyze(adv, store); ai_show(store)
            if (store["summary"] or store["findings"] or store["plan"]) and yes("\n  Save the Llama report as a PDF now?"):
                save_llama_pdf()
        elif c == "2":
            store = ai_store(); r = ai_call("writing summary", lambda cb: adv.summary(build_ctx(), on_token=cb))
            if r:
                store["summary"] = r; print_wrapped(r)
        elif c == "3":
            store = ai_store(); r = ai_call("explaining findings", lambda cb: adv.explain(build_ctx(), on_token=cb))
            if r:
                store["findings"] = r; ai_show({"findings": r})
        elif c == "4":
            store = ai_store(); r = ai_call("building action plan", lambda cb: adv.plan(build_ctx(), on_token=cb))
            if r:
                store["plan"] = r; ai_show({"plan": r})
        elif c == "5":
            ai_chat(adv)
        elif c == "6":
            if ai:
                ai_show(ai)
            else:
                print("  Nothing saved yet - choose 1 first.")
        elif c == "7":
            save_llama_pdf()
        elif c == "8":
            state["ai"] = None; print("  Advice discarded.")
        elif c == "0":
            return
        else:
            print("  Invalid choice.")


# =====================================================================
# Step 4: report export
# =====================================================================
# ---------------------------------------------------------------------
# Report model: grouped findings, recommendations, scan coverage
# ---------------------------------------------------------------------
REMEDIATION = [
    (r"os guess|page title|server header", ""),
    (r"slowloris|dos attack", "Set connection and header timeouts and per-client connection limits, or put the server behind a reverse proxy/WAF."),
    (r"diffie-hellman|dh-params|logjam", "Use Diffie-Hellman groups of 2048 bits or more, or prefer ECDHE key exchange."),
    (r"weak tls|tlsv1\.0|sslv3", "Disable SSLv3, TLS 1.0 and TLS 1.1. Allow only TLS 1.2 or newer with strong ciphers."),
    (r"security headers?", "Add the missing headers: HSTS, X-Content-Type-Options, Content-Security-Policy, Referrer-Policy, Permissions-Policy."),
    (r"interesting web paths", "Restrict admin and login pages by IP or extra authentication, and remove pages that are not needed."),
    (r"discovered path", "Remove or protect files and directories that should not be public."),
    (r"outdated|end.of.life", "Upgrade to a supported, patched version of the software."),
    (r"^cve-\d{4}-", "Patch or upgrade the affected software, then confirm the CVE applies to the exact version in use."),
    (r"certificate", "Use a certificate whose names match the host name users connect to."),
    (r"exposed", "Close the port or restrict it to trusted IPs. Prefer encrypted alternatives."),
    (r"junk http methods|unknown http methods", "Make sure the server rejects unknown HTTP methods, and verify scanner findings manually."),
    (r"vulnerable|\(cve-", "Apply the vendor patch or mitigation for the listed issue, then re-test."),
]


def remediation_for(title: str) -> str:
    low = title.lower()
    for pat, text in REMEDIATION:
        if re.search(pat, low):
            return text
    return ""


def group_findings(findings: list) -> list[dict]:
    """Merge repeats (same issue on several ports, many missing-header lines) into one row."""
    order = {s: i for i, s in enumerate(rp.SEVERITIES)}
    groups: dict = {}
    for f in findings:
        if f.source == "nmap-os" or (f.severity == "info" and f.title.startswith("Open port")):
            continue                                   # already shown in the hosts section
        title, detail = f.title, f.evidence
        low = title.lower()
        if low.startswith("suggested security header missing"):
            title, detail = "Missing HTTP security headers", title.split(":", 1)[-1].strip(" .")
        elif "junk http methods" in low:
            title, detail = "Server accepts unknown HTTP methods (may cause false positives)", ""
        g = groups.setdefault((f.severity, title, f.source), {
            "severity": f.severity, "title": title, "source": f.source,
            "details": [], "affected": {}, "cvss": None})
        if detail and detail not in g["details"]:
            g["details"].append(detail)
        g["affected"].setdefault(f.host, set()).add(f.port)
        if f.cvss:
            g["cvss"] = max(g["cvss"] or 0.0, f.cvss)
    out = []
    for g in groups.values():
        parts = []
        for host, ports in g["affected"].items():
            plist = sorted(p for p in ports if p is not None)
            parts.append(f"{host}: {', '.join(map(str, plist))}" if plist else f"{host} (host-wide)")
        out.append({"severity": g["severity"], "title": g["title"], "source": g["source"],
                    "cvss": g["cvss"], "affected": "; ".join(parts),
                    "evidence": shorten("; ".join(g["details"]), 260) or "-",
                    "fix": remediation_for(g["title"]) or "-"})
    out.sort(key=lambda g: (order[g["severity"]], g["title"]))
    return out


def ai_note(c: dict, index_0based: int):
    """AI advice dict for grouped finding #index (0-based) or None."""
    ai = c.get("ai")
    return ai["findings"].get(index_0based + 1) if ai else None


def ai_line(a: dict) -> str:
    return (f"Meaning: {a['explain']}  Verify: {a['verify']}  Fix: {a['fix']}  "
            f"False-positive chance: {a['false_positive']} ({a['reason']})")


# ---------------------------------------------------------------------
# Standalone Llama report (PDF containing only the AI analysis)
# ---------------------------------------------------------------------
HTML_AI = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Llama AI Analysis - {{ target }}</title>
<style>
 @page{size:A4 landscape;margin:12mm}
 *{box-sizing:border-box}
 body{font-family:Arial,Helvetica,sans-serif;color:#222;font-size:12px;line-height:1.4;margin:0}
 @media screen{body{margin:24px auto;max-width:1200px;padding:0 16px}}
 h1{border-bottom:3px solid #6a1b9a;padding-bottom:8px;color:#6a1b9a;font-size:24px;margin:0 0 8px}
 h2{color:#6a1b9a;margin:18px 0 6px;font-size:17px;page-break-after:avoid}
 table{border-collapse:collapse;width:100%;table-layout:fixed;margin-top:6px}
 th,td{border:1px solid #ccc;padding:5px 7px;text-align:left;vertical-align:top;overflow-wrap:anywhere;word-break:break-word}
 th{background:#6a1b9a;color:#fff;font-size:11px}
 thead{display:table-header-group}
 tr{page-break-inside:avoid}
 .sev{display:inline-block;color:#fff;padding:2px 7px;border-radius:3px;font-weight:bold;font-size:10px}
 .critical{background:#7b0000}.high{background:#d32f2f}.medium{background:#f57c00}
 .low{background:#fbc02d;color:#222}.info{background:#607d8b}
 .fp{display:inline-block;color:#fff;padding:1px 6px;border-radius:3px;font-size:10px;font-weight:bold}
 .fp-low{background:#2e7d32}.fp-medium{background:#f57c00}.fp-high{background:#c62828}.fp-unknown{background:#607d8b}
 .meta{color:#555;margin:0}
 .small{color:#666;font-size:10px}
 .note{border-left:4px solid #6a1b9a;background:#f6f0fa;padding:8px 12px;margin:10px 0}
 ol{margin:4px 0 0 18px;padding:0}
</style></head><body>
<h1>Llama AI Analysis Report</h1>
<p class="meta">Target: <b>{{ target }}</b> &nbsp;|&nbsp; Generated: {{ generated }} &nbsp;|&nbsp; Model: <b>{{ ai.model }}</b> (running locally)</p>
<div class="note"><b>AI-generated content.</b> This analysis was written by a small language model from the scan results.
It can be wrong or incomplete. Severity ratings come from the scanner, not the AI. Verify every item before acting on it.</div>

<h2>Executive Summary</h2>
{% if ai.summary %}<p>{{ ai.summary }}</p>{% else %}<p class="small">No summary was generated.</p>{% endif %}

<h2>Suggested Action Plan</h2>
{% if ai.plan %}<ol>{% for st in ai.plan %}<li><b>{{ st.step }}</b>{% if st.why %} - {{ st.why }}{% endif %}</li>{% endfor %}</ol>
{% else %}<p class="small">No action plan was generated.</p>{% endif %}

<h2>Advice per Finding</h2>
{% if rows %}
<table><colgroup><col style="width:7%"><col style="width:16%"><col style="width:20%"><col style="width:17%"><col style="width:20%"><col style="width:20%"></colgroup>
<thead><tr><th>Severity</th><th>Finding</th><th>What it means</th><th>How to verify</th><th>How to fix</th><th>Chance it is a false positive</th></tr></thead><tbody>
{% for r in rows %}
<tr><td><span class="sev {{ r.severity }}">{{ r.severity|upper }}</span></td>
<td><b>{{ r.title }}</b><br><span class="small">{{ r.affected }}</span></td>
<td>{{ r.explain }}</td><td>{{ r.verify }}</td><td>{{ r.fix }}</td>
<td><span class="fp fp-{{ r.false_positive }}">{{ r.false_positive|upper }}</span><br>{{ r.reason }}</td></tr>
{% endfor %}</tbody></table>
{% else %}<p class="small">No per-finding advice was generated.</p>{% endif %}

{% if problems %}<h2>Scanner problems the AI was told about</h2><ul>{% for r in problems %}<li>{{ r.tool }} on {{ r.target }}: {{ r.status }}{% if r.note %} - {{ r.note }}{% endif %}</li>{% endfor %}</ul>{% endif %}

<p class="small" style="margin-top:18px">Generated by recon_wizard.py and llm_advisor.py. All analysis ran on this computer;
no scan data was sent to an online service. For authorized testing only.</p>
</body></html>"""


def ai_rows(c: dict) -> list:
    """One row per grouped finding that has AI advice."""
    rows = []
    for i, g in enumerate(c["groups"]):
        a = ai_note(c, i)
        if a:
            rows.append(dict(severity=g["severity"], title=g["title"], affected=g["affected"], **a))
    return rows


def render_ai_html(c: dict) -> str:
    from jinja2 import Environment
    problems = [r for r in c["runs"] if r["status"] != "ok"]
    return Environment(autoescape=True).from_string(HTML_AI).render(
        target=c["target"], generated=c["generated"], ai=c["ai"], rows=ai_rows(c), problems=problems)


def export_llama_pdf(c, path):
    if not c.get("ai"):
        raise RuntimeError("No AI advice yet - run Step 3 > AI advice > Full analysis first.")
    if have("weasyprint"):
        try:
            from weasyprint import HTML
            HTML(string=render_ai_html(c)).write_pdf(str(path))
            return "weasyprint"
        except OSError:
            pass
    if not have("reportlab"):
        raise RuntimeError("PDF needs: pip install weasyprint   (or: pip install reportlab)")
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    ai, purple = c["ai"], colors.HexColor("#6a1b9a")
    ss = getSampleStyleSheet()
    small = ss["BodyText"].clone("small", fontSize=8, leading=10)
    P = lambda t, st=small: Paragraph(xml_escape(str(t)), st)
    fp_color = {"low": "#2e7d32", "medium": "#f57c00", "high": "#c62828", "unknown": "#607d8b"}

    story = [Paragraph("Llama AI Analysis Report", ss["Title"]),
             P(f"Target: {c['target']}   |   Generated: {c['generated']}   |   Model: {ai['model']} (running locally)", ss["BodyText"]),
             Spacer(1, 6),
             P("AI-generated content. Written by a small language model from the scan results; it can be wrong or "
               "incomplete. Severity ratings come from the scanner, not the AI. Verify every item before acting.", ss["BodyText"]),
             Spacer(1, 8), Paragraph("Executive Summary", ss["Heading2"]),
             P(ai["summary"] or "No summary was generated.", ss["BodyText"]),
             Paragraph("Suggested Action Plan", ss["Heading2"])]
    story += [P(f"{i}. {st['step']} - {st['why']}", ss["BodyText"]) for i, st in enumerate(ai["plan"], 1)] \
        or [P("No action plan was generated.", ss["BodyText"])]
    story.append(Paragraph("Advice per Finding", ss["Heading2"]))

    rows = ai_rows(c)
    if rows:
        data = [["Severity", "Finding", "What it means", "How to verify", "How to fix", "False-positive chance"]]
        style = [("GRID", (0, 0), (-1, -1), 0.4, colors.grey), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                 ("BACKGROUND", (0, 0), (-1, 0), purple), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white)]
        for n, r in enumerate(rows, 1):
            data.append([P(r["severity"].upper()), P(f"{r['title']}  ({r['affected']})"), P(r["explain"]),
                         P(r["verify"]), P(r["fix"]), P(f"{r['false_positive'].upper()} - {r['reason']}")])
            style.append(("BACKGROUND", (0, n), (0, n), colors.HexColor("#" + SEV_COLORS[r["severity"]])))
            style.append(("BACKGROUND", (5, n), (5, n), colors.HexColor(fp_color.get(r["false_positive"], "#607d8b"))))
            style.append(("TEXTCOLOR", (5, n), (5, n), colors.white))
        t = Table(data, colWidths=[50, 140, 170, 130, 150, 130], repeatRows=1)
        t.setStyle(TableStyle(style))
        story.append(t)
    else:
        story.append(P("No per-finding advice was generated.", ss["BodyText"]))
    story += [Spacer(1, 10), P("Generated by recon_wizard.py and llm_advisor.py. All analysis ran on this computer; "
                               "no scan data was sent to an online service. For authorized testing only.", small)]
    SimpleDocTemplate(str(path), pagesize=landscape(A4), leftMargin=24, rightMargin=24,
                      topMargin=24, bottomMargin=24).build(story)
    return "reportlab"


def save_llama_pdf() -> bool:
    """Write the standalone Llama PDF for the current findings. Returns True on success."""
    c = build_ctx()
    if not c.get("ai"):
        print("  No AI advice for the current findings yet - run 'Full analysis' first.")
        return False
    out = Path(state["general"]["output"])
    out.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", state["target"] or "target")
    path = out / f"llama_report_{safe}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    try:
        with Spinner("Creating Llama PDF report"):
            export_llama_pdf(c, path)
    except Exception as e:
        print(f"  Could not create the Llama PDF: {e}")
        return False
    print(f"  Saved: {path.resolve()}")
    return True


def build_ctx() -> dict:
    groups = group_findings(state["findings"])
    counts = {s: sum(1 for g in groups if g["severity"] == s) for s in rp.SEVERITIES}
    urgent = [g["title"] for g in groups if g["severity"] in ("critical", "high")]
    medium = [g["title"] for g in groups if g["severity"] == "medium"]
    base = (f"{len(groups)} distinct finding(s) were identified on {len(state['hosts'])} host(s), "
            f"from {len(state['findings'])} raw observation(s).")
    if urgent:
        risk = f"{len(urgent)} critical/high-severity issue(s) should be fixed first."
    elif medium:
        risk = "No critical or high issues were found, but medium-risk items need review."
    else:
        risk = "No significant issues were identified by the automated checks."
    os_guess = {f.host: f.title.replace("OS guess: ", "") for f in state["findings"] if f.source == "nmap-os"}
    return dict(target=state["target"], generated=datetime.now().strftime("%Y-%m-%d %H:%M"),
                tools=state["tools_used"] or ["nmap"], hosts=state["hosts"], groups=groups,
                severities=rp.SEVERITIES, counts=counts, summary_sentence=f"{base} {risk}",
                top_issues=(urgent + medium)[:5], os_guess=os_guess, runs=state["runs"],
                raw=state["findings"], ai=current_ai(groups))


# ---------------------------------------------------------------------
# HTML (also the source for PDF via WeasyPrint): landscape page, fixed columns
# ---------------------------------------------------------------------
HTML_V2 = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Assessment Report - {{ target }}</title>
<style>
 @page{size:A4 landscape;margin:12mm}
 *{box-sizing:border-box}
 body{font-family:Arial,Helvetica,sans-serif;color:#222;font-size:12px;line-height:1.35;margin:0}
 @media screen{body{margin:24px auto;max-width:1200px;padding:0 16px}}
 h1{border-bottom:3px solid #1a3a5c;padding-bottom:8px;color:#1a3a5c;font-size:24px;margin:0 0 8px}
 h2{color:#1a3a5c;margin:20px 0 6px;font-size:17px;page-break-after:avoid}
 h3{margin:12px 0 4px;font-size:13px;page-break-after:avoid}
 table{border-collapse:collapse;width:100%;table-layout:fixed;margin-top:6px}
 th,td{border:1px solid #ccc;padding:5px 7px;text-align:left;vertical-align:top;overflow-wrap:anywhere;word-break:break-word}
 th{background:#1a3a5c;color:#fff;font-size:11px}
 thead{display:table-header-group}
 tr{page-break-inside:avoid}
 .sev{display:inline-block;color:#fff;padding:2px 7px;border-radius:3px;font-weight:bold;font-size:10px}
 .critical{background:#7b0000}.high{background:#d32f2f}.medium{background:#f57c00}
 .low{background:#fbc02d;color:#222}.info{background:#607d8b}
 .cards{display:flex;gap:10px;margin:10px 0}
 .card{flex:1;padding:10px;border-radius:6px;color:#fff;text-align:center}
 .card.low{color:#222}
 .card b{display:block;font-size:24px}
 .meta{color:#555;font-size:12px;margin:0}
 .small{color:#666;font-size:10px}
 .ok{color:#2e7d32;font-weight:bold}.bad{color:#c62828;font-weight:bold}
 pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:10px;background:#f5f5f5;padding:8px;border:1px solid #ddd}
 ol{margin:4px 0 0 18px;padding:0}
 .ai{border-left:4px solid #6a1b9a;background:#f6f0fa;padding:8px 12px;margin:8px 0}
 .ai h3{margin:0 0 4px;color:#6a1b9a}
 .tag{display:inline-block;background:#6a1b9a;color:#fff;font-size:9px;padding:1px 6px;border-radius:3px;margin-right:4px}
 .aibox{margin-top:5px;padding:5px 7px;background:#f6f0fa;border-left:3px solid #6a1b9a;font-size:10px}
</style></head><body>
<h1>Security Assessment Report</h1>
<p class="meta">Target: <b>{{ target }}</b> &nbsp;|&nbsp; Generated: {{ generated }} &nbsp;|&nbsp; Tools: {{ tools|join(", ") }}</p>

<h2>Executive Summary</h2>
<p>{{ summary_sentence }}</p>
<div class="cards">
{% for s in severities %}<div class="card {{ s }}"><b>{{ counts[s] }}</b>{{ s|capitalize }}</div>{% endfor %}
</div>
{% if top_issues %}<p><b>Priority issues</b></p><ol>{% for t in top_issues %}<li>{{ t }}</li>{% endfor %}</ol>{% endif %}
{% if ai and (ai.summary or ai.plan) %}
<div class="ai"><h3><span class="tag">AI-generated</span>Llama analysis</h3>
{% if ai.summary %}<p>{{ ai.summary }}</p>{% endif %}
{% if ai.plan %}<p><b>Suggested action plan</b></p><ol>{% for st in ai.plan %}<li><b>{{ st.step }}</b>{% if st.why %} - {{ st.why }}{% endif %}</li>{% endfor %}</ol>{% endif %}
<p class="small">Written by {{ ai.model }} running locally. A second opinion only - verify before acting.</p></div>
{% endif %}

<h2>Hosts &amp; Open Ports</h2>
{% for h in hosts %}
<h3>{{ h.address }}{% if h.hostname %} ({{ h.hostname }}){% endif %}{% if os_guess.get(h.address) %} &nbsp;<span class="small">OS guess: {{ os_guess[h.address] }}</span>{% endif %}</h3>
<table><colgroup><col style="width:9%"><col style="width:9%"><col style="width:20%"><col style="width:62%"></colgroup>
<thead><tr><th>Port</th><th>Protocol</th><th>Service</th><th>Version / Banner</th></tr></thead><tbody>
{% for p in h.open_ports %}<tr><td>{{ p.port }}</td><td>{{ p.proto }}</td><td>{{ p.service }}</td><td>{{ p.banner or "-" }}</td></tr>
{% endfor %}</tbody></table>
{% endfor %}

<h2>Findings (grouped, sorted by severity)</h2>
{% if groups %}
<table><colgroup><col style="width:8%"><col style="width:22%"><col style="width:14%"><col style="width:30%"><col style="width:26%"></colgroup>
<thead><tr><th>Severity</th><th>Finding</th><th>Affected</th><th>Evidence</th><th>Recommendation</th></tr></thead><tbody>
{% for g in groups %}
<tr><td><span class="sev {{ g.severity }}">{{ g.severity|upper }}</span></td>
<td><b>{{ g.title }}</b><br><span class="small">{{ g.source }}{% if g.cvss %} &middot; CVSS {{ g.cvss }}{% endif %}</span></td>
<td>{{ g.affected }}</td><td>{{ g.evidence }}</td><td>{{ g.fix }}{% if g.ai %}
<div class="aibox"><span class="tag">AI</span><b>Meaning:</b> {{ g.ai.explain }}<br><b>Verify:</b> {{ g.ai.verify }}<br><b>Fix:</b> {{ g.ai.fix }}<br><b>False-positive chance:</b> {{ g.ai.false_positive }} - {{ g.ai.reason }}</div>{% endif %}</td></tr>
{% endfor %}</tbody></table>
{% else %}<p>No findings were recorded.</p>{% endif %}

<h2>Scan Coverage</h2>
<p class="small">What each tool actually did. A tool with no results is listed here with its status, so gaps are visible.</p>
{% if runs %}
<table><colgroup><col style="width:9%"><col style="width:24%"><col style="width:11%"><col style="width:8%"><col style="width:15%"><col style="width:33%"></colgroup>
<thead><tr><th>Tool</th><th>Target</th><th>Status</th><th>Time</th><th>Results</th><th>Notes</th></tr></thead><tbody>
{% for r in runs %}
<tr><td>{{ r.tool }}</td><td>{{ r.target }}</td><td class="{{ 'ok' if r.status == 'ok' else 'bad' }}">{{ r.status }}</td>
<td>{{ r.time }}</td><td>{{ r.results or "-" }}</td><td>{{ r.note or "-" }}</td></tr>
{% endfor %}</tbody></table>
<h3>Commands run</h3>
<pre>{% for r in runs %}{{ r.command }}
{% endfor %}</pre>
{% else %}<p>No scan records available.</p>{% endif %}

<p class="small" style="margin-top:18px">Automated results can include false positives and must be validated manually.
&quot;Likely vulnerable&quot; means the check could not confirm the issue. Open ports are listed in the hosts tables above.
Generated by recon_wizard.py for authorized testing only.</p>
</body></html>"""


def render_html(c: dict) -> str:
    from jinja2 import Environment
    groups = [dict(g, ai=ai_note(c, i)) for i, g in enumerate(c["groups"])]
    return Environment(autoescape=True).from_string(HTML_V2).render(**dict(c, groups=groups))


def csv_safe(v) -> str:
    s = "" if v is None else str(v)
    if s == "-":
        return ""                                  # empty placeholder
    return "'" + s if s[:1] in ("=", "+", "-", "@") else s   # neutralize spreadsheet formulas


def export_html(c, path):
    Path(path).write_text(render_html(c), encoding="utf-8")


def export_json(c, path):
    Path(path).write_text(json.dumps({
        "target": c["target"], "generated": c["generated"],
        "hosts": [asdict(h) for h in c["hosts"]],
        "findings": [asdict(f) for f in c["raw"]],
        "groups": c["groups"], "runs": c["runs"],
        "ai": ({"model": c["ai"]["model"], "summary": c["ai"]["summary"], "plan": c["ai"]["plan"],
                "findings": {str(k): v for k, v in c["ai"]["findings"].items()}} if c.get("ai") else None)},
        indent=2), encoding="utf-8")


def export_csv(c, path):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["severity", "finding", "affected", "evidence", "recommendation", "cvss", "source"])
        for g in c["groups"]:
            w.writerow([g["severity"], csv_safe(g["title"]), g["affected"], csv_safe(g["evidence"]),
                        g["fix"], g["cvss"] or "", g["source"]])


def export_txt(c, path):
    L = ["SECURITY ASSESSMENT REPORT", f"Target: {c['target']}", f"Generated: {c['generated']}",
         f"Tools: {', '.join(c['tools'])}", "", "SUMMARY", c["summary_sentence"],
         "  " + "  ".join(f"{s}={n}" for s, n in c["counts"].items())]
    if c["top_issues"]:
        L += ["", "PRIORITY ISSUES"] + [f"  {i}. {t}" for i, t in enumerate(c["top_issues"], 1)]
    if c.get("ai") and (c["ai"]["summary"] or c["ai"]["plan"]):
        L += ["", f"AI ANALYSIS (AI-generated by {c['ai']['model']}; verify before acting)"]
        if c["ai"]["summary"]:
            L += ["  " + c["ai"]["summary"]]
        L += [f"  {i}. {st['step']} - {st['why']}" for i, st in enumerate(c["ai"]["plan"], 1)]
    L += ["", "HOSTS"]
    for h in c["hosts"]:
        L.append(f"  {h.address} {h.hostname} {('- ' + c['os_guess'][h.address]) if c['os_guess'].get(h.address) else ''}".rstrip())
        L += [f"    {p['port']}/{p['proto']} {p['service']} {p['banner']}" for p in h.open_ports]
    L += ["", "FINDINGS"]
    for i, g in enumerate(c["groups"]):
        L += [f"  [{g['severity'].upper()}] {g['title']}  ({g['source']})",
              f"      Affected : {g['affected']}", f"      Evidence : {g['evidence']}",
              f"      Fix      : {g['fix']}"]
        a = ai_note(c, i)
        if a:
            L += [f"      AI ({c['ai']['model']}): {ai_line(a)}"]
    L += ["", "SCAN COVERAGE"]
    L += [f"  {r['tool']:<9} {r['target']:<30} {r['status']:<12} {r['time']}  {r['results']}  {r['note']}"
          for r in c["runs"]]
    Path(path).write_text("\n".join(L) + "\n", encoding="utf-8")


def export_md(c, path):
    cell = lambda s: str(s).replace("|", "\\|").replace("\n", " ")
    L = ["# Security Assessment Report", "", f"**Target:** {c['target']}  ",
         f"**Generated:** {c['generated']}  ", f"**Tools:** {', '.join(c['tools'])}", "",
         "## Executive Summary", "", c["summary_sentence"], "",
         "| " + " | ".join(s.capitalize() for s in c["severities"]) + " |",
         "|" + "---|" * len(c["severities"]),
         "| " + " | ".join(str(c["counts"][s]) for s in c["severities"]) + " |", ""]
    if c["top_issues"]:
        L += ["**Priority issues**", ""] + [f"{i}. {t}" for i, t in enumerate(c["top_issues"], 1)] + [""]
    if c.get("ai") and (c["ai"]["summary"] or c["ai"]["plan"]):
        L += [f"## AI Analysis", "", f"> **AI-generated** by {c['ai']['model']} running locally. Verify before acting.", ""]
        if c["ai"]["summary"]:
            L += [c["ai"]["summary"], ""]
        if c["ai"]["plan"]:
            L += ["**Suggested action plan**", ""] + [f"{i}. **{st['step']}** - {st['why']}" for i, st in enumerate(c["ai"]["plan"], 1)] + [""]
    L += ["## Hosts & Open Ports", ""]
    for h in c["hosts"]:
        os_txt = f" - OS guess: {c['os_guess'][h.address]}" if c["os_guess"].get(h.address) else ""
        L += [f"### {h.address} {h.hostname}{os_txt}", "", "| Port | Proto | Service | Version |", "|---|---|---|---|"]
        L += [f"| {p['port']} | {p['proto']} | {cell(p['service'])} | {cell(p['banner'])} |" for p in h.open_ports]
        L.append("")
    L += ["## Findings", "", "| Severity | Finding | Affected | Evidence | Recommendation |", "|---|---|---|---|---|"]
    L += [f"| {g['severity'].upper()} | **{cell(g['title'])}** ({g['source']}) | {cell(g['affected'])} | "
          f"{cell(g['evidence'])} | {cell(g['fix'])}"
          + (f" <br>**AI:** {cell(ai_line(ai_note(c, i)))}" if ai_note(c, i) else "") + " |"
          for i, g in enumerate(c["groups"])]
    L += ["", "## Scan Coverage", "", "| Tool | Target | Status | Time | Results | Notes |", "|---|---|---|---|---|---|"]
    L += [f"| {r['tool']} | {cell(r['target'])} | {r['status']} | {r['time']} | {cell(r['results'])} | {cell(r['note'])} |"
          for r in c["runs"]]
    L += ["", "*Automated results can include false positives and must be validated manually.*"]
    Path(path).write_text("\n".join(L) + "\n", encoding="utf-8")


def export_pdf(c, path):
    if have("weasyprint"):
        try:
            from weasyprint import HTML
            HTML(string=render_html(c)).write_pdf(str(path))
            return "weasyprint"
        except OSError:
            pass   # missing system libs -> try reportlab
    if not have("reportlab"):
        raise RuntimeError("PDF needs: pip install weasyprint   (or: pip install reportlab)")
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    ss = getSampleStyleSheet()
    small = ss["BodyText"].clone("small", fontSize=8, leading=10)
    P = lambda s, st=small: Paragraph(xml_escape(str(s)), st)
    head = colors.HexColor("#1a3a5c")
    grid = [("GRID", (0, 0), (-1, -1), 0.4, colors.grey), ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("BACKGROUND", (0, 0), (-1, 0), head), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white)]

    story = [Paragraph("Security Assessment Report", ss["Title"]),
             P(f"Target: {c['target']}   |   Generated: {c['generated']}   |   Tools: {', '.join(c['tools'])}", ss["BodyText"]),
             Spacer(1, 8), Paragraph("Executive Summary", ss["Heading2"]),
             P(c["summary_sentence"], ss["BodyText"]), Spacer(1, 6)]
    cnt = Table([[s.capitalize() for s in c["severities"]], [c["counts"][s] for s in c["severities"]]])
    style = [("GRID", (0, 0), (-1, -1), 0.5, colors.grey), ("ALIGN", (0, 0), (-1, -1), "CENTER")]
    for i, s in enumerate(c["severities"]):
        style += [("BACKGROUND", (i, 0), (i, 0), colors.HexColor("#" + SEV_COLORS[s])),
                  ("TEXTCOLOR", (i, 0), (i, 0), colors.white)]
    cnt.setStyle(TableStyle(style))
    story.append(cnt)
    if c["top_issues"]:
        story += [Spacer(1, 6), P("Priority issues:", ss["BodyText"])]
        story += [P(f"{i}. {t}", ss["BodyText"]) for i, t in enumerate(c["top_issues"], 1)]
    if c.get("ai") and (c["ai"]["summary"] or c["ai"]["plan"]):
        story += [Spacer(1, 8), Paragraph("AI Analysis (AI-generated - verify before acting)", ss["Heading3"])]
        if c["ai"]["summary"]:
            story.append(P(c["ai"]["summary"], ss["BodyText"]))
        story += [P(f"{i}. {st['step']} - {st['why']}", ss["BodyText"]) for i, st in enumerate(c["ai"]["plan"], 1)]
        story.append(P(f"Written by {c['ai']['model']} running locally.", small))

    story += [Spacer(1, 8), Paragraph("Hosts &amp; Open Ports", ss["Heading2"])]
    for h in c["hosts"]:
        os_txt = f"  -  OS guess: {c['os_guess'][h.address]}" if c["os_guess"].get(h.address) else ""
        story.append(Paragraph(xml_escape(f"{h.address} {h.hostname}{os_txt}"), ss["Heading3"]))
        rows = [["Port", "Proto", "Service", "Version"]] + [
            [P(p["port"]), P(p["proto"]), P(p["service"]), P(p["banner"] or "-")] for p in h.open_ports]
        t = Table(rows, colWidths=[50, 50, 120, 520], repeatRows=1)
        t.setStyle(TableStyle(grid))
        story += [t, Spacer(1, 6)]

    story.append(Paragraph("Findings (grouped, sorted by severity)", ss["Heading2"]))
    rows = [["Severity", "Finding", "Affected", "Evidence", "Recommendation"]]
    for g in c["groups"]:
        title = f"{g['title']}  [{g['source']}" + (f", CVSS {g['cvss']}" if g["cvss"] else "") + "]"
        a = ai_note(c, len(rows) - 1)
        fix = g["fix"] + (f"  [AI: {ai_line(a)}]" if a else "")
        rows.append([P(g["severity"].upper()), P(title), P(g["affected"]), P(g["evidence"]), P(fix)])
    t = Table(rows, colWidths=[52, 170, 110, 240, 168], repeatRows=1)
    style = list(grid)
    for i, g in enumerate(c["groups"], 1):
        style.append(("BACKGROUND", (0, i), (0, i), colors.HexColor("#" + SEV_COLORS[g["severity"]])))
    t.setStyle(TableStyle(style))
    story.append(t)

    story += [Spacer(1, 10), Paragraph("Scan Coverage", ss["Heading2"])]
    rows = [["Tool", "Target", "Status", "Time", "Results", "Notes"]] + [
        [P(r["tool"]), P(r["target"]), P(r["status"]), P(r["time"]), P(r["results"] or "-"), P(r["note"] or "-")]
        for r in c["runs"]]
    t = Table(rows, colWidths=[55, 160, 70, 45, 110, 350], repeatRows=1)
    t.setStyle(TableStyle(grid))
    story += [t, Spacer(1, 6), Paragraph("Commands run", ss["Heading3"])]
    story += [Paragraph(xml_escape(r["command"]), ss["Code"].clone("c", fontSize=7, leading=9)) for r in c["runs"]]
    story += [Spacer(1, 8), P("Automated results can include false positives and must be validated manually.", ss["BodyText"])]
    SimpleDocTemplate(str(path), pagesize=landscape(A4), leftMargin=24, rightMargin=24,
                      topMargin=24, bottomMargin=24).build(story)
    return "reportlab"


def export_docx(c, path):
    if not have("docx"):
        raise RuntimeError("Word export needs: pip install python-docx")
    from docx import Document
    from docx.enum.section import WD_ORIENT
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
    from docx.shared import Pt

    def shade(cell, hex_):
        shd = OxmlElement("w:shd")
        shd.set(qn("w:val"), "clear")
        shd.set(qn("w:color"), "auto")
        shd.set(qn("w:fill"), hex_)
        cell._tc.get_or_add_tcPr().append(shd)

    def table(headers, rows, sev_col=None):
        t = doc.add_table(rows=1, cols=len(headers))
        t.style = "Table Grid"
        for i, head in enumerate(headers):
            t.rows[0].cells[i].text = head
            shade(t.rows[0].cells[i], "D9E2F3")
        for row in rows:
            cells = t.add_row().cells
            for i, val in enumerate(row):
                cells[i].text = str(val)
            if sev_col is not None:
                shade(cells[sev_col], SEV_COLORS[str(row[sev_col]).lower()])
        return t

    doc = Document()
    sec = doc.sections[0]
    sec.orientation = WD_ORIENT.LANDSCAPE
    sec.page_width, sec.page_height = sec.page_height, sec.page_width
    doc.styles["Normal"].font.size = Pt(10)

    doc.add_heading("Security Assessment Report", 0)
    doc.add_paragraph(f"Target: {c['target']}\nGenerated: {c['generated']}\nTools: {', '.join(c['tools'])}")
    doc.add_heading("Executive Summary", 1)
    doc.add_paragraph(c["summary_sentence"])
    t = doc.add_table(rows=2, cols=len(c["severities"]))
    t.style = "Table Grid"
    for i, s in enumerate(c["severities"]):
        t.cell(0, i).text = s.capitalize()
        t.cell(1, i).text = str(c["counts"][s])
        shade(t.cell(0, i), SEV_COLORS[s])
    if c["top_issues"]:
        doc.add_paragraph("Priority issues:")
        for tt in c["top_issues"]:
            doc.add_paragraph(tt, style="List Number")
    if c.get("ai") and (c["ai"]["summary"] or c["ai"]["plan"]):
        doc.add_heading("AI Analysis (AI-generated)", 2)
        doc.add_paragraph(f"Written by {c['ai']['model']} running locally. A second opinion only - verify before acting.")
        if c["ai"]["summary"]:
            doc.add_paragraph(c["ai"]["summary"])
        for st in c["ai"]["plan"]:
            doc.add_paragraph(f"{st['step']} - {st['why']}", style="List Number 2")

    doc.add_heading("Hosts & Open Ports", 1)
    for h in c["hosts"]:
        os_txt = f" - OS guess: {c['os_guess'][h.address]}" if c["os_guess"].get(h.address) else ""
        doc.add_heading(f"{h.address} {h.hostname}{os_txt}".strip(), 2)
        table(("Port", "Proto", "Service", "Version"),
              [(p["port"], p["proto"], p["service"], p["banner"] or "-") for p in h.open_ports])

    doc.add_heading("Findings (grouped, sorted by severity)", 1)
    table(("Severity", "Finding", "Affected", "Evidence", "Recommendation"),
          [(g["severity"].upper(), f"{g['title']} [{g['source']}" + (f", CVSS {g['cvss']}" if g["cvss"] else "") + "]",
            g["affected"], g["evidence"],
            g["fix"] + (f"\nAI: {ai_line(ai_note(c, i))}" if ai_note(c, i) else ""))
           for i, g in enumerate(c["groups"])], sev_col=0)

    doc.add_heading("Scan Coverage", 1)
    table(("Tool", "Target", "Status", "Time", "Results", "Notes"),
          [(r["tool"], r["target"], r["status"], r["time"], r["results"] or "-", r["note"] or "-") for r in c["runs"]])
    doc.add_paragraph("\nAutomated results can include false positives and must be validated manually.")
    doc.save(str(path))


FORMATS = [
    ("1", "HTML", "html", export_html),
    ("2", "PDF", "pdf", export_pdf),
    ("3", "Word (.docx)", "docx", export_docx),
    ("4", "Markdown", "md", export_md),
    ("5", "CSV (grouped findings, opens in Excel)", "csv", export_csv),
    ("6", "JSON (reusable with recon.py report/diff)", "json", export_json),
    ("7", "Plain text", "txt", export_txt),
    ("8", "Llama AI report (PDF, AI analysis only)", "llama.pdf", export_llama_pdf),
]


def format_note(ext: str) -> str:
    if ext == "llama.pdf":
        has = current_ai(group_findings(state["findings"])) is not None
        return "" if has else "  (needs AI advice first: Step 3 > option 3)"
    if ext == "pdf" and not (have("weasyprint") or have("reportlab")):
        return "  (needs: pip install weasyprint or reportlab)"
    if ext == "docx" and not have("docx"):
        return "  (needs: pip install python-docx)"
    return ""


def step_report():
    banner(4, "REPORT FORMAT")
    if not state["findings"]:
        print("  Nothing to report yet. Run a scan first.")
        return 3
    print("  Choose one or more formats (e.g. 1,3,6) or 'a' for all:\n")
    fmt_style = {"html": "nikto", "pdf": "exit", "docx": "nmap", "md": "target", "csv": "next",
                 "json": "all", "txt": "plain", "llama.pdf": "ai"}
    for num, name, ext, _ in FORMATS:
        print(menu_item(num, name, fmt_style.get(ext, "plain")) + paint(format_note(ext), "yellow"))
    print(menu_item("a", "All formats", "report"))
    print(menu_item("0", "Back to Step 3", "back"))
    choice = ask("\nSelect").lower().replace(" ", "")
    if choice == "0":
        return 3
    has_ai = current_ai(group_findings(state["findings"])) is not None
    picks = [f for f in FORMATS if (choice == "a" and (has_ai or f[2] != "llama.pdf"))
             or f[0] in choice.split(",")]
    if not picks:
        print("  No valid format selected.")
        return 4

    out = Path(state["general"]["output"])
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", state["target"] or "target")
    ctx = build_ctx()
    written = []
    for _, name, ext, fn in picks:
        path = (out / f"llama_report_{safe}_{stamp}.pdf" if ext == "llama.pdf"
                else out / f"report_{safe}_{stamp}.{ext}")
        try:
            with Spinner(f"Creating {name}"):
                fn(ctx, path)
            written.append(path)
        except Exception as e:
            print(f"  Could not create {name}: {e}")
    if written:
        state["reported"] = True
        print("\n  Saved:")
        for p in written:
            print(f"    {p.resolve()}")
    return 3


# =====================================================================
# Step screens
# =====================================================================
def confirm_exit() -> bool:
    if state["findings"] and not state["reported"]:
        return yes("  You have findings that were not exported. Exit anyway?")
    return True


def step_setup():
    banner(1, "SETUP")
    show_menu([("1", "Set target & scope", "target"),
               ("2", "Settings (all tool flags, wordlist, timeouts)", "settings"),
               ("3", "Check installed tools", "check"), ("4", "Continue to Step 2 (Scan)", "next"),
               ("0", "Exit", "exit")])
    c = ask("\nSelect")
    if c == "1":
        set_target()
    elif c == "2":
        settings_menu()
    elif c == "3":
        check_tools()
    elif c == "4":
        return 2 if need_target() else 1
    elif c == "0":
        return 0 if confirm_exit() else 1
    else:
        print("  Invalid choice.")
    return 1


def step_scan():
    banner(2, "SCAN")
    show_menu([("1", "Use Nmap (AUTO = all flags by itself, or Manual)", "nmap"),
               ("2", "Use Nikto (AUTO or Manual)", "nikto"),
               ("3", "Use Gobuster (AUTO or Manual)", "gobuster"),
               ("4", "Run all, fully AUTO (Nmap -> Nikto + Gobuster)", "all"),
               ("5", "Continue to Step 3 (Results)", "next"), ("6", "Back to Step 1 (Setup)", "back"),
               ("0", "Exit", "exit")])
    c = ask("\nSelect")
    if c == "1":
        do_nmap()
    elif c == "2":
        do_web_tool("nikto")
    elif c == "3":
        do_web_tool("gobuster")
    elif c == "4":
        do_all()
    elif c == "5":
        return 3
    elif c == "6":
        return 1
    elif c == "0":
        return 0 if confirm_exit() else 2
    else:
        print("  Invalid choice.")
    return 2


def step_results():
    banner(3, "RESULTS")
    show_menu([("1", "View findings", "view"), ("2", "Generate report (choose format)", "report"),
               ("3", "AI advice from local Llama (summary, fixes, false positives, Q&A)", "ai"),
               ("4", "Back to Step 2 (Scan)", "back"), ("0", "Exit", "exit")])
    c = ask("\nSelect")
    if c == "1":
        view_findings()
    elif c == "2":
        return 4
    elif c == "3":
        ai_menu()
    elif c == "4":
        return 2
    elif c == "0":
        return 0 if confirm_exit() else 3
    else:
        print("  Invalid choice.")
    return 3


def main():
    print(paint("RECON WIZARD", "bold", "cyan") + paint(" - for authorized testing only.", "yellow"))
    steps = {1: step_setup, 2: step_scan, 3: step_results, 4: step_report}
    step = 1
    while step:
        step = steps[step]()
    print(paint("Bye.", "bold", "cyan"))


if __name__ == "__main__":
    main()
