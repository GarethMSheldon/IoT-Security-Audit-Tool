#!/usr/bin/env python3
"""
OT / ICS / SCADA / IoT Security Auditor
Unified version: dark amber theme, enhanced protocol coverage, concurrent scanning.
Export formats: CSV, JSON, XML, PDF (requires reportlab).
Fixed false positives: HTTP/HTTPS probes only report actual web services.
Requirements: Python 3.7+, built-in modules (tkinter, socket, etc.), reportlab optional.
"""

import sys
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading
import socket
import struct
import ipaddress
import datetime
import queue
import time
import urllib.request
import urllib.error
import base64
import csv
import json
import xml.etree.ElementTree as ET
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─────────────────────────────────────────────────────────────────────────────
# REQUIREMENTS CHECK – safe startup
# ─────────────────────────────────────────────────────────────────────────────
def check_requirements():
    """Verify that all required modules are available. Warn about missing optional ones."""
    missing_optional = []
    # Check for reportlab (optional)
    try:
        import reportlab
    except ImportError:
        missing_optional.append("reportlab (PDF export disabled)")
    
    # All other modules are built-in or provided by Python standard library.
    # No mandatory missing modules.
    
    if missing_optional:
        print("WARNING: Optional modules missing: " + ", ".join(missing_optional))
        # Don't exit, just inform user later via GUI
        return False, missing_optional
    return True, []

# Try to import reportlab for PDF export
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

# ─────────────────────────────────────────────────────────────────────────────
# COLOR PALETTE – industrial amber-on-black (enhanced contrast)
# ─────────────────────────────────────────────────────────────────────────────
C = {
    "bg":        "#0a0c0f",
    "bg2":       "#111418",
    "bg3":       "#1a1f26",
    "panel":     "#141820",
    "border":    "#2a3040",
    "amber":     "#f5a623",
    "amber_dim": "#8a5c10",
    "cyan":      "#00d9ff",
    "cyan_dim":  "#005f6b",
    "red":       "#ff3b3b",
    "orange":    "#ff7a00",
    "green":     "#00e676",
    "yellow":    "#ffe066",
    "white":     "#e8eaf0",
    "grey":      "#a0a8b0",
    "grey2":     "#3a4050",
}

FONT_MONO   = ("Courier New", 9)
FONT_MONO_B = ("Courier New", 9, "bold")
FONT_HEAD   = ("Courier New", 13, "bold")
FONT_SUB    = ("Courier New", 10, "bold")
FONT_LABEL  = ("Courier New", 9)
FONT_SMALL  = ("Courier New", 8)

# ─────────────────────────────────────────────────────────────────────────────
# PROTOCOL DEFINITIONS – merged, deduplicated
# ─────────────────────────────────────────────────────────────────────────────
OT_PROTOCOLS = [
    {"name": "Modbus TCP",        "port": 502,   "transport": "tcp",
     "category": "ICS/PLC",
     "probe": "modbus",
     "risk": "CRITICAL – unauthenticated read/write of registers"},
    {"name": "S7comm (Siemens)",  "port": 102,   "transport": "tcp",
     "category": "ICS/PLC",
     "probe": "s7",
     "risk": "CRITICAL – exposes Siemens PLC CPU info, memory areas"},
    {"name": "DNP3",              "port": 20000, "transport": "tcp",
     "category": "SCADA/RTU",
     "probe": "dnp3",
     "risk": "HIGH – DNP3 has no authentication in most deployments"},
    {"name": "IEC 60870-5-104",   "port": 2404,  "transport": "tcp",
     "category": "SCADA",
     "probe": "iec104",
     "risk": "HIGH – unencrypted SCADA control protocol"},
    {"name": "OPC UA",            "port": 4840,  "transport": "tcp",
     "category": "ICS/OPC",
     "probe": "opcua",
     "risk": "MEDIUM – check if security mode is None/sign only"},
    {"name": "EtherNet/IP (CIP)", "port": 44818, "transport": "tcp",
     "category": "ICS/PLC",
     "probe": "enip",
     "risk": "CRITICAL – Rockwell/Allen-Bradley PLC CIP session"},
    {"name": "BACnet/IP",         "port": 47808, "transport": "udp",
     "category": "BAS",
     "probe": "bacnet",
     "risk": "HIGH – building automation, unauthenticated WhoIs"},
    {"name": "Profinet DCP",      "port": 34980, "transport": "udp",
     "category": "ICS",
     "probe": "profinet",
     "risk": "HIGH – exposes device names & Siemens firmware info"},
    {"name": "Modbus UDP",        "port": 502,   "transport": "udp",
     "category": "ICS/PLC",
     "probe": "modbus_udp",
     "risk": "CRITICAL – some RTUs use UDP Modbus"},
    {"name": "MQTT",              "port": 1883,  "transport": "tcp",
     "category": "IoT",
     "probe": "mqtt",
     "risk": "HIGH – plaintext IoT messaging, no auth by default"},
    {"name": "MQTTS",             "port": 8883,  "transport": "tcp",
     "category": "IoT",
     "probe": "tcp_banner",
     "risk": "LOW – MQTT over TLS (verify cert validity)"},
    {"name": "CoAP",              "port": 5683,  "transport": "udp",
     "category": "IoT",
     "probe": "coap",
     "risk": "HIGH – IoT constrained app protocol, no encryption"},
    {"name": "Telnet",            "port": 23,    "transport": "tcp",
     "category": "Management",
     "probe": "tcp_banner",
     "risk": "CRITICAL – cleartext remote access"},
    {"name": "FTP",               "port": 21,    "transport": "tcp",
     "category": "Management",
     "probe": "tcp_banner",
     "risk": "HIGH – cleartext file transfer"},
    {"name": "HTTP HMI",          "port": 80,    "transport": "tcp",
     "category": "HMI/Web",
     "probe": "http",
     "risk": "HIGH – unencrypted HMI web interface"},
    {"name": "HTTPS HMI",         "port": 443,   "transport": "tcp",
     "category": "HMI/Web",
     "probe": "https",
     "risk": "LOW – HTTPS (check cert & auth)"},
    {"name": "HTTP Alt",          "port": 8080,  "transport": "tcp",
     "category": "HMI/Web",
     "probe": "http",
     "risk": "MEDIUM – alternate HTTP port"},
    {"name": "HTTPS Alt",         "port": 8443,  "transport": "tcp",
     "category": "HMI/Web",
     "probe": "https",
     "risk": "MEDIUM – alternate HTTPS port"},
    {"name": "Siemens S7 Plus",   "port": 102,   "transport": "tcp",
     "category": "ICS/PLC",
     "probe": "s7",
     "risk": "CRITICAL – S7+ extended protocol"},
    {"name": "SRTP (GE Fanuc)",   "port": 18245, "transport": "tcp",
     "category": "ICS/PLC",
     "probe": "tcp_banner",
     "risk": "HIGH – GE PACSystems SRTP protocol"},
    {"name": "Crimson v3 (Red Lion)", "port": 789, "transport": "tcp",
     "category": "ICS/HMI",
     "probe": "tcp_banner",
     "risk": "HIGH – Red Lion HMI Crimson v3"},
    {"name": "FINS (Omron)",      "port": 9600,  "transport": "udp",
     "category": "ICS/PLC",
     "probe": "fins",
     "risk": "CRITICAL – Omron PLC FINS, no auth"},
    {"name": "Melsec-Q (Mitsubishi)", "port": 5007, "transport": "tcp",
     "category": "ICS/PLC",
     "probe": "tcp_banner",
     "risk": "HIGH – Mitsubishi Melsec Q-series PLC"},
]

DEFAULT_CREDS = [
    {"user": "admin",         "pass": "admin",        "vendor": "Generic"},
    {"user": "admin",         "pass": "password",     "vendor": "Generic"},
    {"user": "admin",         "pass": "",             "vendor": "Generic"},
    {"user": "admin",         "pass": "1234",         "vendor": "Generic"},
    {"user": "admin",         "pass": "12345",        "vendor": "Generic"},
    {"user": "root",          "pass": "root",         "vendor": "Linux"},
    {"user": "root",          "pass": "123456",       "vendor": "Linux"},
    {"user": "root",          "pass": "",             "vendor": "Linux"},
    {"user": "user",          "pass": "user",         "vendor": "Generic"},
    {"user": "support",       "pass": "support",      "vendor": "Siemens"},
    {"user": "engineer",      "pass": "engineer",     "vendor": "Rockwell"},
    {"user": "Administrator", "pass": "",             "vendor": "Windows HMI"},
    {"user": "guest",         "pass": "guest",        "vendor": "Generic"},
    {"user": "operator",      "pass": "operator",     "vendor": "SCADA"},
    {"user": "service",       "pass": "service",      "vendor": "Vendor"},
    {"user": "admin",         "pass": "admin123",     "vendor": "Generic"},
    {"user": "admin",         "pass": "system",       "vendor": "Siemens"},
]

# ─────────────────────────────────────────────────────────────────────────────
# PROBE FUNCTIONS – all fixed, with safe socket handling and no false positives
# ─────────────────────────────────────────────────────────────────────────────

def _tcp_connect(ip, port, timeout=2.0):
    """Create TCP socket and connect, return socket or raise exception."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((ip, port))
    return sock

def probe_tcp_open(ip, port, timeout=2.0):
    """Check if TCP port is open and optionally grab a banner."""
    try:
        with _tcp_connect(ip, port, timeout) as s:
            s.settimeout(1.0)
            try:
                banner = s.recv(256)
                printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in banner[:80])
                return True, f"open – banner: {printable.strip()}" if printable.strip() else "open"
            except socket.timeout:
                return True, "open (no banner received)"
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False, ""

def probe_modbus(ip, port=502, timeout=2.0):
    try:
        with _tcp_connect(ip, port, timeout) as s:
            pkt = bytes([0x00,0x01,0x00,0x00,0x00,0x06,0x01,0x03,0x00,0x00,0x00,0x01])
            s.sendall(pkt)
            s.settimeout(1.5)
            resp = s.recv(256)
            if len(resp) >= 8 and resp[7] == 0x03:
                unit = resp[6]
                return True, f"Modbus RTU unit={unit} – read holding reg OK – UNAUTHENTICATED"
            elif len(resp) > 0:
                return True, "port open – partial Modbus response"
            return True, "port open – no Modbus data"
    except Exception:
        return False, ""

def probe_modbus_udp(ip, port=502, timeout=2.0):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        pkt = bytes([0x00,0x01,0x00,0x00,0x00,0x06,0x01,0x03,0x00,0x00,0x00,0x01])
        sock.sendto(pkt, (ip, port))
        try:
            resp, _ = sock.recvfrom(256)
            sock.close()
            if len(resp) >= 8 and resp[7] == 0x03:
                return True, f"Modbus UDP unit={resp[6]} – UNAUTHENTICATED"
            elif len(resp) > 0:
                return True, "UDP Modbus – partial response"
        except socket.timeout:
            pass
        sock.close()
        return False, ""
    except Exception:
        return False, ""

def probe_s7(ip, port=102, timeout=2.0):
    try:
        with _tcp_connect(ip, port, timeout) as s:
            pkt = bytes([0x03,0x00,0x00,0x16,0x11,0xE0,0x00,0x00,0x00,0x01,0x00,
                         0xC0,0x01,0x0A,0xC1,0x02,0x01,0x00,0xC2,0x02,0x01,0x02])
            s.sendall(pkt)
            s.settimeout(1.5)
            resp = s.recv(128)
            if len(resp) >= 4 and resp[0] == 0x03:
                return True, "Siemens S7 PLC – TPKT/COTP connection accepted – UNAUTHENTICATED"
            return True, "port 102 open – possible Siemens device"
    except Exception:
        return False, ""

def probe_dnp3(ip, port=20000, timeout=2.0):
    try:
        with _tcp_connect(ip, port, timeout) as s:
            pkt = bytes([0x05,0x64,0x05,0xC0,0xFF,0xFF,0x00,0x00,0x65,0x6E])
            s.sendall(pkt)
            s.settimeout(1.5)
            resp = s.recv(64)
            if len(resp) >= 2 and resp[0] == 0x05 and resp[1] == 0x64:
                src = struct.unpack_from('<H', resp, 4)[0] if len(resp) >= 6 else 0
                return True, f"DNP3 RTU/IED src_addr={src} – no authentication (SA by default off)"
            return True, "port open – possible DNP3 device"
    except Exception:
        return False, ""

def probe_iec104(ip, port=2404, timeout=2.0):
    try:
        with _tcp_connect(ip, port, timeout) as s:
            pkt = bytes([0x68,0x04,0x07,0x00,0x00,0x00])
            s.sendall(pkt)
            s.settimeout(1.5)
            resp = s.recv(32)
            if len(resp) >= 1 and resp[0] == 0x68:
                return True, "IEC 60870-5-104 slave – STARTDT accepted – unencrypted SCADA"
            return True, "port open – possible IEC104 device"
    except Exception:
        return False, ""

def probe_opcua(ip, port=4840, timeout=2.0):
    try:
        with _tcp_connect(ip, port, timeout) as s:
            endpoint = f"opc.tcp://{ip}:{port}".encode()
            ep_len = len(endpoint)
            msg_size = 28 + ep_len
            hello = struct.pack('<4sIIIII', b'HEL ', msg_size, 0,
                                65536, 65536, ep_len) + endpoint
            s.sendall(hello)
            s.settimeout(1.5)
            resp = s.recv(64)
            if len(resp) >= 4:
                msg_type = resp[:3]
                if msg_type in (b'ACK', b'ERR', b'OPN', b'HEL'):
                    return True, f"OPC UA server – response type={msg_type.decode()} – check security mode"
            return True, "port open – possible OPC UA"
    except Exception:
        return False, ""

def probe_enip(ip, port=44818, timeout=2.0):
    try:
        with _tcp_connect(ip, port, timeout) as s:
            req = bytes([0x65,0x00,0x04,0x00,0x00,0x00,0x00,0x00,
                         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                         0x01,0x00,0x00,0x00])
            s.sendall(req)
            s.settimeout(1.5)
            resp = s.recv(64)
            if len(resp) >= 4 and resp[0] == 0x65:
                session = struct.unpack_from('<I', resp, 4)[0] if len(resp) >= 8 else 0
                return True, f"EtherNet/IP (CIP) – session=0x{session:08X} – Rockwell/Allen-Bradley"
            return True, "port open – possible EtherNet/IP"
    except Exception:
        return False, ""

def probe_bacnet(ip, port=47808, timeout=2.0):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        whoIs = bytes([0x81,0x0a,0x00,0x08,0x01,0x20,0xff,0xff])
        sock.sendto(whoIs, (ip, port))
        resp, addr = sock.recvfrom(256)
        sock.close()
        if resp and resp[0] == 0x81:
            return True, f"BACnet/IP device – I-Am from {addr[0]} – building automation"
        return True, "BACnet port responded"
    except Exception:
        return False, ""

def probe_profinet(ip, port=34980, timeout=2.0):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        ident = bytes([0xfe,0xfe,0x05,0x00,0x00,0x00,0x00,0x00,
                       0x00,0x01,0x00,0x00,0x00,0x04,0xff,0xff])
        sock.sendto(ident, (ip, port))
        try:
            resp, _ = sock.recvfrom(256)
            sock.close()
            if resp:
                return True, "Profinet DCP – device identity response received"
        except socket.timeout:
            pass
        sock.close()
        return False, ""
    except Exception:
        return False, ""

def probe_coap(ip, port=5683, timeout=2.0):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        coap = bytes([0x40,0x01,0x00,0x01,0xbb,0x2e,0x77,0x65,
                      0x6c,0x6c,0x2d,0x6b,0x6e,0x6f,0x77,0x6e,
                      0x04,0x63,0x6f,0x72,0x65])
        sock.sendto(coap, (ip, port))
        resp, _ = sock.recvfrom(512)
        sock.close()
        if resp:
            return True, "CoAP server – IoT device, no encryption"
        return False, ""
    except Exception:
        return False, ""

def probe_mqtt(ip, port=1883, timeout=2.0):
    try:
        with _tcp_connect(ip, port, timeout) as s:
            cid = b'ot-auditor'
            rem = 10 + len(cid)
            conn = bytes([0x10, rem, 0x00, 4]) + b'MQTT' + bytes([0x04, 0x02, 0x00, 0x3c, 0x00, len(cid)]) + cid
            s.sendall(conn)
            s.settimeout(1.5)
            r = s.recv(16)
            if len(r) >= 4 and r[0] == 0x20:
                rc = r[3]
                if rc == 0:
                    return True, "MQTT broker – anonymous CONNECT accepted (NO AUTH)"
                else:
                    return True, f"MQTT broker – auth required (rc={rc})"
            return True, "Port open – possible MQTT broker"
    except Exception:
        return False, ""

def probe_fins(ip, port=9600, timeout=2.0):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        fins = bytes([0x80,0x00,0x02,0x00,0x00,0x00,
                      0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                      0x01,0x01,0x82,0x00,0x00,0x00,0x00,0x01])
        sock.sendto(fins, (ip, port))
        resp, _ = sock.recvfrom(256)
        sock.close()
        if resp:
            return True, "Omron FINS – PLC responding – no authentication"
        return False, ""
    except Exception:
        return False, ""

def probe_http(ip, port=80, https=False, timeout=3.0, cred_test=False):
    """
    Only return True if an actual HTTP/HTTPS response is received.
    No false positive for just open port.
    """
    scheme = "https" if https else "http"
    url = f"{scheme}://{ip}:{port}/"
    # Use a custom context to avoid certificate validation issues
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": "OT-Scanner/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx if https else None) as r:
            body = r.read(2048).decode(errors='replace')
            title = ""
            if "<title" in body.lower():
                start = body.lower().index("<title") + 7
                end_tag = body.lower().find("</title>", start)
                if end_tag > start:
                    title = body[start:end_tag].strip()[:60]
            server = r.headers.get("Server", "")
            result = f"{'HTTPS' if https else 'HTTP'} HMI – status={r.status}"
            if title:
                result += f" title=\"{title}\""
            if server:
                result += f" server={server}"
            cred_result = None
            if cred_test:
                cred_result = test_http_creds(ip, port, https, timeout)
                if cred_result:
                    result += f" | ⚠ {cred_result}"
            return True, result
    except (urllib.error.URLError, socket.timeout, ConnectionError):
        # No valid HTTP response: do NOT report as finding
        return False, ""

def test_http_creds(ip, port, https, timeout=3.0):
    scheme = "https" if https else "http"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    for cred in DEFAULT_CREDS:
        url = f"{scheme}://{ip}:{port}/"
        token = base64.b64encode(f"{cred['user']}:{cred['pass']}".encode()).decode()
        req = urllib.request.Request(url, headers={
            "Authorization": f"Basic {token}",
            "User-Agent": "OT-Scanner/1.0"
        })
        try:
            with urllib.request.urlopen(req, timeout=timeout,
                                         context=ctx if https else None) as r:
                if r.status == 200:
                    return f"DEFAULT CREDS WORK: {cred['user']}/{cred['pass']} [{cred['vendor']}]"
        except Exception:
            continue
    return None

def run_probe(proto_def, ip, timeout, cred_test):
    p = proto_def["probe"]
    port = proto_def["port"]
    transport = proto_def["transport"]
    try:
        if p == "modbus":       return probe_modbus(ip, port, timeout)
        elif p == "modbus_udp": return probe_modbus_udp(ip, port, timeout)
        elif p == "s7":         return probe_s7(ip, port, timeout)
        elif p == "dnp3":       return probe_dnp3(ip, port, timeout)
        elif p == "iec104":     return probe_iec104(ip, port, timeout)
        elif p == "opcua":      return probe_opcua(ip, port, timeout)
        elif p == "enip":       return probe_enip(ip, port, timeout)
        elif p == "bacnet":     return probe_bacnet(ip, port, timeout)
        elif p == "profinet":   return probe_profinet(ip, port, timeout)
        elif p == "coap":       return probe_coap(ip, port, timeout)
        elif p == "mqtt":       return probe_mqtt(ip, port, timeout)
        elif p == "fins":       return probe_fins(ip, port, timeout)
        elif p == "http":
            return probe_http(ip, port, False, timeout, cred_test)
        elif p == "https":
            return probe_http(ip, port, True, timeout, cred_test)
        elif p == "tcp_banner":
            if transport == "tcp":
                return probe_tcp_open(ip, port, timeout)
            return False, ""
        else:
            return probe_tcp_open(ip, port, timeout)
    except Exception as e:
        return False, f"probe error: {e}"

# ─────────────────────────────────────────────────────────────────────────────
# IP RANGE EXPANSION
# ─────────────────────────────────────────────────────────────────────────────

def expand_targets(target_str):
    targets = []
    for part in target_str.replace(" ", "").split(","):
        if not part:
            continue
        try:
            if "/" in part:
                net = ipaddress.ip_network(part, strict=False)
                # Limit to a reasonable number of hosts
                hosts = list(net.hosts())
                if len(hosts) > 1024:
                    raise ValueError(f"Range {part} has {len(hosts)} hosts – max 1024")
                targets.extend(str(h) for h in hosts)
            elif "-" in part and part.count(".") == 3:
                base, end = part.rsplit(".", 1)
                start_oct, end_oct = end.split("-") if "-" in end else (end, end)
                for i in range(int(start_oct), int(end_oct) + 1):
                    targets.append(f"{base}.{i}")
            else:
                ipaddress.ip_address(part)  # validate
                targets.append(part)
        except ValueError as e:
            raise ValueError(f"Invalid target '{part}': {e}")
    # Deduplicate while preserving order
    return list(dict.fromkeys(targets))

# ─────────────────────────────────────────────────────────────────────────────
# RISK SCORING
# ─────────────────────────────────────────────────────────────────────────────

RISK_WEIGHT = {
    "CRITICAL": 40,
    "HIGH":     25,
    "MEDIUM":   10,
    "LOW":       5,
    "INFO":      2,
}

def score_findings(findings):
    total = 0
    for _, _, risk in findings:
        for level, weight in RISK_WEIGHT.items():
            if risk.startswith(level):
                total += weight
                break
    return min(total, 100)

def risk_label(score):
    if score == 0:   return "SECURE",   C["green"]
    if score < 20:   return "LOW",      C["yellow"]
    if score < 50:   return "MEDIUM",   C["orange"]
    if score < 75:   return "HIGH",     C["red"]
    return               "CRITICAL",   "#ff0000"

# ─────────────────────────────────────────────────────────────────────────────
# MAIN APPLICATION – enhanced UI with bigger buttons and export options
# ─────────────────────────────────────────────────────────────────────────────

class OTAuditorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("OT/ICS/SCADA/IoT SECURITY AUDITOR  ·  v1.2")
        self.root.geometry("1400x950")
        self.root.minsize(1200, 800)
        self.root.configure(bg=C["bg"])

        # Check requirements and show warning if PDF not available
        ok, missing = check_requirements()
        if not PDF_AVAILABLE:
            messagebox.showwarning("Missing Optional Module",
                                   "PDF export requires 'reportlab'.\n"
                                   "Install with: pip install reportlab\n"
                                   "Other export formats (CSV, JSON, XML) are still available.")

        self.scan_thread = None
        self.stop_event = threading.Event()
        self.log_queue = queue.Queue()
        self.results = []
        self.all_findings = []
        self._report_content = ""

        self._build_ui()
        self._schedule_log_flush()

    # ── UI BUILDER ────────────────────────────────────────────────────────────

    def _build_ui(self):
        self._build_header()
        self._build_main_pane()
        self._build_status_bar()

    def _build_header(self):
        hdr = tk.Frame(self.root, bg="#090b0e", height=68)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)

        tk.Label(hdr, text="◈ OT / ICS / SCADA / IoT  SECURITY AUDITOR",
                 bg="#090b0e", fg=C["amber"],
                 font=("Courier New", 16, "bold")).pack(side="left", padx=24, pady=18)

        tk.Label(hdr, text="v1.2 · Industrial Protocol Discovery & Hardening Assessment",
                 bg="#090b0e", fg=C["grey"],
                 font=("Courier New", 10)).pack(side="left", padx=0, pady=18)

        self.lbl_time = tk.Label(hdr, text="", bg="#090b0e", fg=C["amber_dim"],
                                  font=FONT_SMALL)
        self.lbl_time.pack(side="right", padx=24)
        self._tick()

    def _tick(self):
        self.lbl_time.config(text=datetime.datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))
        self.root.after(1000, self._tick)

    def _build_main_pane(self):
        main = tk.Frame(self.root, bg=C["bg"])
        main.pack(fill="both", expand=True)

        # LEFT PANEL – controls (wider)
        left = tk.Frame(main, bg=C["bg2"], width=360)
        left.pack(side="left", fill="y")
        left.pack_propagate(False)

        self._build_target_section(left)
        self._build_protocol_section(left)
        self._build_options_section(left)
        self._build_action_buttons(left)

        # DIVIDER
        tk.Frame(main, bg=C["border"], width=2).pack(side="left", fill="y")

        # RIGHT PANEL – results
        right = tk.Frame(main, bg=C["bg"])
        right.pack(side="left", fill="both", expand=True)

        self._build_results_panel(right)

    def _section_label(self, parent, text):
        f = tk.Frame(parent, bg=C["bg2"])
        f.pack(fill="x", padx=12, pady=(12, 4))
        tk.Label(f, text=f"▸ {text}", bg=C["bg2"], fg=C["amber"],
                 font=FONT_SUB).pack(side="left")
        tk.Frame(f, bg=C["amber_dim"], height=1).pack(side="left", fill="x",
                                                        expand=True, padx=(6, 0))

    def _build_target_section(self, parent):
        self._section_label(parent, "TARGET")
        tf = tk.Frame(parent, bg=C["bg2"])
        tf.pack(fill="x", padx=12)

        tk.Label(tf, text="IP / CIDR / Range:", bg=C["bg2"], fg=C["white"],
                 font=FONT_LABEL).pack(anchor="w")
        self.entry_target = tk.Entry(tf, bg=C["bg3"], fg=C["cyan"],
                                      insertbackground=C["cyan"],
                                      font=FONT_MONO, relief="flat",
                                      highlightthickness=1,
                                      highlightbackground=C["border"],
                                      highlightcolor=C["amber"])
        self.entry_target.insert(0, "192.168.1.1")
        self.entry_target.pack(fill="x", pady=(2, 8))

        tk.Label(tf, text="Examples:  192.168.1.0/24  ·  10.0.0.1-254  ·  172.16.0.5",
                 bg=C["bg2"], fg=C["grey"], font=FONT_SMALL).pack(anchor="w", pady=(0, 4))

        tf2 = tk.Frame(parent, bg=C["bg2"])
        tf2.pack(fill="x", padx=12, pady=(4, 8))
        tk.Label(tf2, text="Timeout (ms):", bg=C["bg2"], fg=C["white"],
                 font=FONT_LABEL).pack(side="left")
        self.entry_timeout = tk.Entry(tf2, bg=C["bg3"], fg=C["cyan"],
                                       insertbackground=C["cyan"],
                                       font=FONT_MONO, width=7, relief="flat",
                                       highlightthickness=1,
                                       highlightbackground=C["border"])
        self.entry_timeout.insert(0, "2000")
        self.entry_timeout.pack(side="left", padx=(6, 0))

        tk.Label(tf2, text="  Threads:", bg=C["bg2"], fg=C["white"],
                 font=FONT_LABEL).pack(side="left")
        self.entry_threads = tk.Entry(tf2, bg=C["bg3"], fg=C["cyan"],
                                       insertbackground=C["cyan"],
                                       font=FONT_MONO, width=5, relief="flat",
                                       highlightthickness=1,
                                       highlightbackground=C["border"])
        self.entry_threads.insert(0, "50")
        self.entry_threads.pack(side="left", padx=(6, 0))

    def _build_protocol_section(self, parent):
        self._section_label(parent, "PROTOCOLS")
        pf = tk.Frame(parent, bg=C["bg2"])
        pf.pack(fill="both", expand=True, padx=12, pady=4)

        # Scrollable area for protocols
        canvas = tk.Canvas(pf, bg=C["bg2"], highlightthickness=0)
        scrollbar = ttk.Scrollbar(pf, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg=C["bg2"])
        scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0,0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.proto_vars = {}
        cats = {}
        for p in OT_PROTOCOLS:
            cats.setdefault(p["category"], []).append(p)

        self.var_all = tk.BooleanVar(value=True)
        all_btn = tk.Checkbutton(scrollable_frame, text="☑ ALL PROTOCOLS", variable=self.var_all,
                       bg=C["bg2"], fg=C["amber"], selectcolor=C["bg3"],
                       activebackground=C["bg2"], activeforeground=C["amber"],
                       font=("Courier New", 9, "bold"),
                       command=self._toggle_all)
        all_btn.pack(anchor="w", pady=(0, 6))

        for cat, protos in cats.items():
            cf = tk.Frame(scrollable_frame, bg=C["bg2"])
            cf.pack(fill="x", pady=2)
            tk.Label(cf, text=f"  {cat}", bg=C["bg2"], fg=C["grey"],
                     font=FONT_SMALL).pack(anchor="w")
            for p in protos:
                key = f"{p['name']}_{p['port']}"
                if key in self.proto_vars:
                    continue
                var = tk.BooleanVar(value=True)
                self.proto_vars[key] = (var, p)
                cb = tk.Checkbutton(cf, text=f"    {p['name']} :{p['port']}",
                                    variable=var, bg=C["bg2"], fg=C["white"],
                                    selectcolor=C["bg3"],
                                    activebackground=C["bg2"],
                                    activeforeground=C["cyan"],
                                    font=FONT_SMALL)
                cb.pack(anchor="w")

    def _toggle_all(self):
        state = self.var_all.get()
        for var, _ in self.proto_vars.values():
            var.set(state)

    def _build_options_section(self, parent):
        self._section_label(parent, "OPTIONS")
        of = tk.Frame(parent, bg=C["bg2"])
        of.pack(fill="x", padx=12, pady=4)

        self.var_cred_test = tk.BooleanVar(value=True)
        tk.Checkbutton(of, text="Test default credentials (HTTP/HTTPS)",
                       variable=self.var_cred_test,
                       bg=C["bg2"], fg=C["white"], selectcolor=C["bg3"],
                       activebackground=C["bg2"], activeforeground=C["cyan"],
                       font=FONT_LABEL).pack(anchor="w", pady=1)

        self.var_save_csv = tk.BooleanVar(value=True)
        tk.Checkbutton(of, text="Auto-save CSV results",
                       variable=self.var_save_csv,
                       bg=C["bg2"], fg=C["white"], selectcolor=C["bg3"],
                       activebackground=C["bg2"], activeforeground=C["cyan"],
                       font=FONT_LABEL).pack(anchor="w", pady=1)

        self.var_save_report = tk.BooleanVar(value=True)
        tk.Checkbutton(of, text="Auto-save text report",
                       variable=self.var_save_report,
                       bg=C["bg2"], fg=C["white"], selectcolor=C["bg3"],
                       activebackground=C["bg2"], activeforeground=C["cyan"],
                       font=FONT_LABEL).pack(anchor="w", pady=1)

    def _build_action_buttons(self, parent):
        bf = tk.Frame(parent, bg=C["bg2"])
        bf.pack(fill="x", padx=12, pady=12)

        # START SCAN – bigger and more prominent
        self.btn_scan = tk.Button(bf, text="▶  START SCAN",
                                   bg=C["amber"], fg="#000",
                                   font=("Courier New", 12, "bold"),
                                   relief="flat", cursor="hand2",
                                   command=self._start_scan,
                                   activebackground=C["amber_dim"],
                                   activeforeground="#fff",
                                   pady=12)
        self.btn_scan.pack(fill="x", pady=(0, 6))

        self.btn_stop = tk.Button(bf, text="■  STOP",
                                   bg=C["grey2"], fg=C["white"],
                                   font=("Courier New", 11, "bold"),
                                   relief="flat", cursor="hand2",
                                   command=self._stop_scan,
                                   state="disabled",
                                   pady=8)
        self.btn_stop.pack(fill="x", pady=(0, 6))

        # Export frame with multiple format buttons
        export_frame = tk.Frame(bf, bg=C["bg2"])
        export_frame.pack(fill="x", pady=(4, 4))
        tk.Label(export_frame, text="Export as:", bg=C["bg2"], fg=C["grey"],
                 font=FONT_SMALL).pack(side="left", padx=(0, 8))
        for fmt, cmd in [("CSV", self._export_csv), ("JSON", self._export_json),
                         ("XML", self._export_xml), ("PDF", self._export_pdf)]:
            btn = tk.Button(export_frame, text=fmt, bg=C["bg3"], fg=C["cyan"],
                            font=FONT_SMALL, relief="flat", cursor="hand2",
                            command=cmd, padx=8, pady=2)
            btn.pack(side="left", padx=2)

        self.btn_clear = tk.Button(bf, text="✕  CLEAR ALL",
                                    bg=C["bg3"], fg=C["grey"],
                                    font=FONT_LABEL, relief="flat",
                                    cursor="hand2",
                                    command=self._clear,
                                    pady=6)
        self.btn_clear.pack(fill="x", pady=(8, 0))

    def _build_results_panel(self, parent):
        style = ttk.Style()
        style.theme_use("default")
        style.configure("TNotebook", background=C["bg"],
                        borderwidth=0, tabmargins=0)
        style.configure("TNotebook.Tab",
                        background=C["bg3"], foreground=C["grey"],
                        font=FONT_MONO_B, padding=(20, 8),
                        borderwidth=0)
        style.map("TNotebook.Tab",
                  background=[("selected", C["bg2"])],
                  foreground=[("selected", C["amber"])])

        self.nb = ttk.Notebook(parent, style="TNotebook")
        self.nb.pack(fill="both", expand=True)

        tab_log = tk.Frame(self.nb, bg=C["bg"])
        self.nb.add(tab_log, text=" LIVE LOG ")
        self._build_log_tab(tab_log)

        tab_findings = tk.Frame(self.nb, bg=C["bg"])
        self.nb.add(tab_findings, text=" FINDINGS ")
        self._build_findings_tab(tab_findings)

        tab_risk = tk.Frame(self.nb, bg=C["bg"])
        self.nb.add(tab_risk, text=" RISK SUMMARY ")
        self._build_risk_tab(tab_risk)

        tab_report = tk.Frame(self.nb, bg=C["bg"])
        self.nb.add(tab_report, text=" FULL REPORT ")
        self._build_report_tab(tab_report)

    def _build_log_tab(self, parent):
        self.log_text = scrolledtext.ScrolledText(
            parent, bg=C["bg"], fg=C["white"],
            font=FONT_MONO, relief="flat", wrap="word",
            insertbackground=C["amber"],
            selectbackground=C["amber_dim"])
        self.log_text.pack(fill="both", expand=True, padx=4, pady=4)
        self.log_text.config(state="disabled")
        self.log_text.tag_configure("head",  foreground=C["amber"],   font=FONT_MONO_B)
        self.log_text.tag_configure("found", foreground=C["cyan"],    font=FONT_MONO_B)
        self.log_text.tag_configure("warn",  foreground=C["orange"])
        self.log_text.tag_configure("crit",  foreground=C["red"],     font=FONT_MONO_B)
        self.log_text.tag_configure("ok",    foreground=C["green"])
        self.log_text.tag_configure("grey",  foreground=C["grey"])
        self.log_text.tag_configure("info",  foreground=C["white"])

    def _build_findings_tab(self, parent):
        style = ttk.Style()
        style.configure("OT.Treeview",
                        background=C["bg"], foreground=C["white"],
                        fieldbackground=C["bg"], font=FONT_MONO,
                        rowheight=24, borderwidth=0)
        style.configure("OT.Treeview.Heading",
                        background=C["bg3"], foreground=C["amber"],
                        font=FONT_MONO_B, relief="flat")
        style.map("OT.Treeview", background=[("selected", C["amber_dim"])])

        cols = ("IP", "Protocol", "Port", "Category", "Risk", "Detail")
        self.tree = ttk.Treeview(parent, columns=cols, show="headings",
                                  style="OT.Treeview")
        widths = [120, 170, 60, 100, 90, 620]
        for col, w in zip(cols, widths):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=w, minwidth=40)

        vsb = ttk.Scrollbar(parent, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(parent, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        hsb.pack(side="bottom", fill="x")
        vsb.pack(side="right", fill="y")
        self.tree.pack(fill="both", expand=True)

        self.tree.tag_configure("crit",   foreground=C["red"])
        self.tree.tag_configure("high",   foreground=C["orange"])
        self.tree.tag_configure("medium", foreground=C["yellow"])
        self.tree.tag_configure("low",    foreground=C["green"])

    def _build_risk_tab(self, parent):
        self.risk_text = scrolledtext.ScrolledText(
            parent, bg=C["bg"], fg=C["white"],
            font=FONT_MONO, relief="flat", wrap="word")
        self.risk_text.pack(fill="both", expand=True, padx=6, pady=6)
        self.risk_text.config(state="disabled")
        self.risk_text.tag_configure("head",  foreground=C["amber"],  font=("Courier New", 11, "bold"))
        self.risk_text.tag_configure("crit",  foreground=C["red"],    font=FONT_MONO_B)
        self.risk_text.tag_configure("high",  foreground=C["orange"])
        self.risk_text.tag_configure("med",   foreground=C["yellow"])
        self.risk_text.tag_configure("low",   foreground=C["green"])
        self.risk_text.tag_configure("sub",   foreground=C["cyan"],   font=FONT_MONO_B)
        self.risk_text.tag_configure("grey",  foreground=C["grey"])

    def _build_report_tab(self, parent):
        self.report_text = scrolledtext.ScrolledText(
            parent, bg=C["bg"], fg=C["white"],
            font=FONT_MONO, relief="flat", wrap="word")
        self.report_text.pack(fill="both", expand=True, padx=6, pady=6)
        self.report_text.config(state="disabled")

    def _build_status_bar(self):
        sb = tk.Frame(self.root, bg="#090b0e", height=32)
        sb.pack(fill="x", side="bottom")
        sb.pack_propagate(False)

        self.lbl_status = tk.Label(sb, text="READY", bg="#090b0e",
                                    fg=C["green"], font=FONT_SMALL)
        self.lbl_status.pack(side="left", padx=16, pady=6)

        self.lbl_progress = tk.Label(sb, text="", bg="#090b0e",
                                      fg=C["grey"], font=FONT_SMALL)
        self.lbl_progress.pack(side="left", padx=20)

        self.progress_var = tk.DoubleVar(value=0)
        self.progress_bar = ttk.Progressbar(sb, variable=self.progress_var,
                                             maximum=100, length=300,
                                             mode="determinate")
        self.progress_bar.pack(side="right", padx=16, pady=6)

        self.lbl_found = tk.Label(sb, text="Devices found: 0",
                                   bg="#090b0e", fg=C["amber"], font=FONT_SMALL)
        self.lbl_found.pack(side="right", padx=12)

    # ── SCAN ENGINE ─────────────────────────────────────────────────────────

    def _start_scan(self):
        target_str = self.entry_target.get().strip()
        if not target_str:
            messagebox.showwarning("Input Required", "Enter a target IP / CIDR / range.")
            return
        try:
            targets = expand_targets(target_str)
            if not targets:
                messagebox.showwarning("No Targets", "No valid IP addresses found.")
                return
        except ValueError as e:
            messagebox.showerror("Invalid Target", str(e))
            return

        try:
            timeout = int(self.entry_timeout.get()) / 1000.0
            if timeout <= 0:
                raise ValueError
            threads = int(self.entry_threads.get())
            if threads < 1 or threads > 200:
                raise ValueError
        except ValueError:
            messagebox.showerror("Config Error", "Timeout (>0 ms) and Threads (1-200) must be valid integers.")
            return

        selected_protos = [p for (var, p) in self.proto_vars.values() if var.get()]
        seen = set()
        protos = []
        for p in selected_protos:
            key = (p["port"], p["transport"], p["probe"])
            if key not in seen:
                seen.add(key)
                protos.append(p)

        if not protos:
            messagebox.showwarning("No Protocols", "Select at least one protocol.")
            return

        self._clear_results()
        self.stop_event.clear()
        self.results = []
        self.all_findings = []

        self.btn_scan.config(state="disabled")
        self.btn_stop.config(state="normal")
        self._set_status("SCANNING…", C["amber"])

        cred_test = self.var_cred_test.get()

        self.scan_thread = threading.Thread(
            target=self._scan_worker,
            args=(targets, protos, timeout, threads, cred_test),
            daemon=True)
        self.scan_thread.start()

    def _scan_worker(self, targets, protos, timeout, max_threads, cred_test):
        total_tasks = len(targets) * len(protos)
        completed = 0
        devices_found = 0
        start_time = time.time()

        self._log(f"{'='*70}", "head")
        self._log(f"  OT SECURITY SCAN  STARTED  {datetime.datetime.now():%Y-%m-%d %H:%M:%S}", "head")
        self._log(f"  Targets: {len(targets)}  |  Protocols: {len(protos)}  |  Threads: {max_threads}", "head")
        self._log(f"{'='*70}", "head")

        for ip in targets:
            if self.stop_event.is_set():
                break

            ip_findings = []
            self._log(f"\n  Scanning {ip}…", "grey")

            with ThreadPoolExecutor(max_workers=min(max_threads, len(protos))) as ex:
                futures = {ex.submit(run_probe, p, ip, timeout, cred_test): p
                           for p in protos}
                for fut in as_completed(futures):
                    if self.stop_event.is_set():
                        break
                    p = futures[fut]
                    completed += 1
                    try:
                        found, detail = fut.result()
                    except Exception as e:
                        found, detail = False, str(e)

                    if found:
                        risk = p["risk"]
                        self._log(f"    ✦ [{p['category']}] {p['name']} :{p['port']}  →  {detail}", "found")
                        self._log(f"      Risk: {risk}", "crit" if "CRITICAL" in risk else
                                  "warn" if "HIGH" in risk else "info")
                        ip_findings.append((p["name"], detail, risk, p["port"], p["category"]))
                        self.all_findings.append({
                            "ip": ip, "protocol": p["name"], "port": p["port"],
                            "category": p["category"], "risk": risk, "detail": detail
                        })
                        risk_tag = ("crit" if "CRITICAL" in risk else
                                    "high" if "HIGH" in risk else
                                    "medium" if "MEDIUM" in risk else "low")
                        self.root.after(0, lambda ip=ip, p=p, detail=detail,
                                        risk=risk, rt=risk_tag:
                                        self.tree.insert("", "end",
                                            values=(ip, p["name"], p["port"],
                                                    p["category"],
                                                    risk.split("–")[0].strip(),
                                                    detail),
                                            tags=(rt,)))

                    pct = (completed / total_tasks) * 100
                    self.root.after(0, self.progress_var.set, pct)
                    self.root.after(0, self.lbl_progress.config,
                                    {"text": f"{completed}/{total_tasks} checks"})

            if ip_findings:
                devices_found += 1
                risk_score = score_findings([(n, d, r) for n, d, r, _, _ in ip_findings])
                label, _ = risk_label(risk_score)
                self.results.append({
                    "ip": ip, "findings": ip_findings, "risk_score": risk_score,
                    "risk_label": label
                })
                self._log(f"  ► {ip} – {len(ip_findings)} service(s) found  Risk={label} ({risk_score})", "found")
                self.root.after(0, self.lbl_found.config,
                                {"text": f"Devices found: {devices_found}"})
            else:
                self._log(f"  ○ {ip} – no OT services detected", "grey")

        elapsed = time.time() - start_time
        self._log(f"\n{'='*70}", "head")
        self._log(f"  SCAN COMPLETE  {elapsed:.1f}s  |  Devices with OT services: {devices_found}", "head")
        self._log(f"{'='*70}", "head")

        self.root.after(0, self._scan_finished, devices_found)

    def _scan_finished(self, devices_found):
        self.btn_scan.config(state="normal")
        self.btn_stop.config(state="disabled")
        status = f"DONE – {devices_found} device(s) found" if devices_found else "DONE – no OT services detected"
        self._set_status(status, C["green"] if devices_found == 0 else C["amber"])
        self._build_risk_summary()
        self._build_full_report()
        if self.var_save_csv.get() and self.all_findings:
            self._auto_save_csv()
        if self.var_save_report.get() and self.results:
            self._auto_save_report()
        self.nb.select(2)

    def _stop_scan(self):
        self.stop_event.set()
        self.btn_stop.config(state="disabled")
        self._set_status("STOPPED", C["red"])

    # ── LOGGING ───────────────────────────────────────────────────────────────

    def _log(self, msg, tag="info"):
        self.log_queue.put((msg + "\n", tag))

    def _schedule_log_flush(self):
        self._flush_log()
        self.root.after(100, self._schedule_log_flush)

    def _flush_log(self):
        self.log_text.config(state="normal")
        while not self.log_queue.empty():
            msg, tag = self.log_queue.get_nowait()
            self.log_text.insert("end", msg, tag)
        self.log_text.see("end")
        self.log_text.config(state="disabled")

    # ── RISK SUMMARY ─────────────────────────────────────────────────────────

    def _build_risk_summary(self):
        rt = self.risk_text
        rt.config(state="normal")
        rt.delete("1.0", "end")

        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        rt.insert("end", f"{'═'*68}\n", "head")
        rt.insert("end", f"  RISK SUMMARY REPORT  ·  {ts}\n", "head")
        rt.insert("end", f"  Target: {self.entry_target.get()}\n", "head")
        rt.insert("end", f"{'═'*68}\n\n", "head")

        if not self.results:
            rt.insert("end", "  No OT/ICS/IoT services detected.\n", "low")
            rt.config(state="disabled")
            return

        crit_hosts = [r for r in self.results if r["risk_label"] == "CRITICAL"]
        high_hosts = [r for r in self.results if r["risk_label"] == "HIGH"]
        med_hosts  = [r for r in self.results if r["risk_label"] in ("MEDIUM",)]
        low_hosts  = [r for r in self.results if r["risk_label"] in ("LOW", "SECURE")]

        rt.insert("end", f"  ◆ Total devices with OT services : {len(self.results)}\n", "sub")
        rt.insert("end", f"  ◆ Total individual findings      : {len(self.all_findings)}\n\n", "sub")

        rt.insert("end", f"  Risk distribution:\n", "sub")
        rt.insert("end", f"    ● CRITICAL : {len(crit_hosts)} host(s)\n", "crit")
        rt.insert("end", f"    ● HIGH     : {len(high_hosts)} host(s)\n", "high")
        rt.insert("end", f"    ● MEDIUM   : {len(med_hosts)} host(s)\n", "med")
        rt.insert("end", f"    ● LOW      : {len(low_hosts)} host(s)\n\n", "low")

        for res in sorted(self.results, key=lambda x: -x["risk_score"]):
            ip = res["ip"]
            rl = res["risk_label"]
            rs = res["risk_score"]
            tag = ("crit" if rl == "CRITICAL" else
                   "high" if rl == "HIGH" else
                   "med" if rl == "MEDIUM" else "low")
            rt.insert("end", f"  {'─'*64}\n", "grey")
            rt.insert("end", f"  IP: {ip}   Risk: {rl} (score {rs}/100)\n", tag)
            for name, detail, risk, port, cat in res["findings"]:
                rt.insert("end", f"    → {name} :{port}  [{cat}]\n", "sub")
                rt.insert("end", f"      {detail}\n", "grey")
                rt.insert("end", f"      Risk: {risk}\n\n", tag)

        rt.insert("end", f"\n{'═'*68}\n", "head")
        rt.insert("end", "  RECOMMENDATIONS\n", "head")
        rt.insert("end", "  ─────────────────────────────────────────────────────────────\n", "grey")

        recs = [
            ("crit", "Change ALL default credentials immediately (Mirai botnet risk)"),
            ("crit", "Disable or firewall Modbus/DNP3/IEC104/FINS – unauthenticated PLC access"),
            ("crit", "Implement network segmentation (Purdue/ISA-95 model)"),
            ("high", "Replace cleartext protocols: Telnet → SSH, FTP → SFTP, HTTP → HTTPS"),
            ("high", "Enable S7 access protection on Siemens PLCs"),
            ("high", "Deploy OPC UA with SecurityMode = SignAndEncrypt (not None)"),
            ("high", "Isolate BACnet/Profinet to VLAN – no internet exposure"),
            ("med",  "Deploy OT-specific IDS (Zeek/Snort with ICS rule sets)"),
            ("med",  "Enable DNP3 Secure Authentication v5 (SAv5)"),
            ("med",  "Regularly patch PLC firmware and HMI software"),
            ("med",  "Implement MQTT authentication + TLS (port 8883)"),
            ("low",  "Conduct periodic vulnerability assessments with ICS-CERT advisories"),
            ("low",  "Document asset inventory (CMDB) and maintain change management"),
        ]
        for tag, rec in recs:
            prefix = "[CRITICAL]" if tag=='crit' else "[HIGH]   " if tag=='high' else "[MEDIUM] " if tag=='med' else "[LOW]    "
            rt.insert("end", f"  {prefix} {rec}\n", tag)

        rt.insert("end", f"\n  Frameworks: IEC 62443 · NIST SP 800-82 · NERC-CIP · ISA/IEC 62443\n", "grey")
        rt.insert("end", f"{'═'*68}\n", "head")
        rt.config(state="disabled")

    # ── FULL REPORT ───────────────────────────────────────────────────────────

    def _build_full_report(self):
        lines = []
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        lines.append("=" * 80)
        lines.append("OT / ICS / SCADA / IoT SECURITY AUDIT REPORT")
        lines.append(f"Generated: {ts}")
        lines.append(f"Target:    {self.entry_target.get()}")
        lines.append(f"Scanner:   OT Security Auditor v1.2")
        lines.append("=" * 80)
        lines.append("")

        if not self.results:
            lines.append("No OT/ICS/IoT services detected.")
        else:
            lines.append("EXECUTIVE SUMMARY")
            lines.append(f"  Devices with OT services : {len(self.results)}")
            lines.append(f"  Total findings           : {len(self.all_findings)}")
            lines.append(f"  Critical hosts           : {sum(1 for r in self.results if r['risk_label']=='CRITICAL')}")
            lines.append("")
            lines.append("DETAILED FINDINGS")
            lines.append("-" * 80)
            for res in sorted(self.results, key=lambda x: -x["risk_score"]):
                lines.append(f"\nIP Address : {res['ip']}")
                lines.append(f"Risk Level : {res['risk_label']}  (score {res['risk_score']}/100)")
                for name, detail, risk, port, cat in res["findings"]:
                    lines.append(f"  Protocol : {name} (port {port}) [{cat}]")
                    lines.append(f"  Detail   : {detail}")
                    lines.append(f"  Risk     : {risk}")
                    lines.append("")
            lines.append("=" * 80)
            lines.append("RECOMMENDATIONS")
            lines.append("-" * 80)
            lines.append("1. Implement network segmentation (Purdue/ISA-95 model)")
            lines.append("2. Change all default credentials immediately")
            lines.append("3. Disable unauthenticated industrial protocols from internet exposure")
            lines.append("4. Replace cleartext management protocols (Telnet/FTP/HTTP)")
            lines.append("5. Deploy OT-aware IDS/IPS (Zeek, Snort ICS rules, Claroty, Nozomi)")
            lines.append("6. Enable encrypted variants: OPC UA SignAndEncrypt, MQTTS, HTTPS")
            lines.append("7. Patch PLC firmware per ICS-CERT advisories regularly")
            lines.append("8. Maintain asset inventory (CMDB) aligned to IEC 62443")
            lines.append("=" * 80)
            lines.append("Standards Reference: IEC 62443 / NIST SP 800-82 / NERC-CIP / ISA-99")
            lines.append("=" * 80)

        self._report_content = "\n".join(lines)

        rt = self.report_text
        rt.config(state="normal")
        rt.delete("1.0", "end")
        rt.insert("end", self._report_content)
        rt.config(state="disabled")

    # ── EXPORT FORMATS ────────────────────────────────────────────────────────

    def _export_csv(self):
        if not self.all_findings:
            messagebox.showinfo("No Data", "Run a scan first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")],
            initialfile=f"OT_Scan_{datetime.datetime.now():%Y%m%d_%H%M%S}.csv")
        if path:
            self._write_csv(path)
            messagebox.showinfo("Exported", f"CSV saved to:\n{path}")

    def _export_json(self):
        if not self.all_findings:
            messagebox.showinfo("No Data", "Run a scan first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".json",
            filetypes=[("JSON files", "*.json")],
            initialfile=f"OT_Scan_{datetime.datetime.now():%Y%m%d_%H%M%S}.json")
        if path:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.all_findings, f, indent=2)
            messagebox.showinfo("Exported", f"JSON saved to:\n{path}")

    def _export_xml(self):
        if not self.all_findings:
            messagebox.showinfo("No Data", "Run a scan first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".xml",
            filetypes=[("XML files", "*.xml")],
            initialfile=f"OT_Scan_{datetime.datetime.now():%Y%m%d_%H%M%S}.xml")
        if path:
            root = ET.Element("OTAudit")
            root.set("generated", datetime.datetime.now().isoformat())
            for f in self.all_findings:
                finding = ET.SubElement(root, "finding")
                for k, v in f.items():
                    child = ET.SubElement(finding, k)
                    child.text = str(v)
            tree = ET.ElementTree(root)
            tree.write(path, encoding="utf-8", xml_declaration=True)
            messagebox.showinfo("Exported", f"XML saved to:\n{path}")

    def _export_pdf(self):
        if not self.all_findings:
            messagebox.showinfo("No Data", "Run a scan first.")
            return
        if not PDF_AVAILABLE:
            messagebox.showerror("Missing Library", "PDF export requires reportlab.\nInstall with: pip install reportlab")
            return
        path = filedialog.asksaveasfilename(defaultextension=".pdf",
            filetypes=[("PDF files", "*.pdf")],
            initialfile=f"OT_Report_{datetime.datetime.now():%Y%m%d_%H%M%S}.pdf")
        if path:
            doc = SimpleDocTemplate(path, pagesize=letter)
            styles = getSampleStyleSheet()
            title_style = ParagraphStyle(name='Title', parent=styles['Heading1'], fontSize=16, textColor=colors.darkblue)
            story = []
            story.append(Paragraph("OT / ICS / SCADA / IoT Security Audit Report", title_style))
            story.append(Spacer(1, 0.2*inch))
            story.append(Paragraph(f"Generated: {datetime.datetime.now()}", styles['Normal']))
            story.append(Paragraph(f"Target: {self.entry_target.get()}", styles['Normal']))
            story.append(Spacer(1, 0.2*inch))
            if self.results:
                story.append(Paragraph(f"Devices with OT services: {len(self.results)}", styles['Normal']))
                story.append(Paragraph(f"Total findings: {len(self.all_findings)}", styles['Normal']))
                story.append(Spacer(1, 0.2*inch))
                for res in sorted(self.results, key=lambda x: -x["risk_score"]):
                    story.append(Paragraph(f"<b>IP: {res['ip']}   Risk: {res['risk_label']} ({res['risk_score']}/100)</b>", styles['Normal']))
                    for name, detail, risk, port, cat in res["findings"]:
                        story.append(Paragraph(f"• {name} :{port} [{cat}]", styles['Normal']))
                        story.append(Paragraph(f"  {detail}", styles['Italic']))
                        story.append(Paragraph(f"  Risk: {risk}", styles['Normal']))
                        story.append(Spacer(1, 0.1*inch))
                    story.append(Spacer(1, 0.2*inch))
            else:
                story.append(Paragraph("No OT/ICS/IoT services detected.", styles['Normal']))
            doc.build(story)
            messagebox.showinfo("Exported", f"PDF saved to:\n{path}")

    # ── AUTO-SAVE and helpers ─────────────────────────────────────────────────

    def _auto_save_csv(self):
        fname = f"OT_Scan_{datetime.datetime.now():%Y%m%d_%H%M%S}.csv"
        self._write_csv(fname)
        self._log(f"\n  CSV auto-saved: {fname}", "ok")

    def _auto_save_report(self):
        fname = f"OT_Report_{datetime.datetime.now():%Y%m%d_%H%M%S}.txt"
        self._write_report(fname)
        self._log(f"  Report auto-saved: {fname}", "ok")

    def _write_csv(self, path):
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["ip","protocol","port","category","risk","detail"])
            writer.writeheader()
            writer.writerows(self.all_findings)

    def _write_report(self, path):
        content = getattr(self, "_report_content", "No report generated yet.")
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)

    def _set_status(self, msg, color):
        self.lbl_status.config(text=msg, fg=color)

    def _clear(self):
        self._clear_results()
        self.results = []
        self.all_findings = []
        self._report_content = ""
        self.lbl_found.config(text="Devices found: 0")
        self.progress_var.set(0)
        self.lbl_progress.config(text="")
        self._set_status("READY", C["green"])

    def _clear_results(self):
        self.log_text.config(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.config(state="disabled")
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.risk_text.config(state="normal")
        self.risk_text.delete("1.0", "end")
        self.risk_text.config(state="disabled")
        self.report_text.config(state="normal")
        self.report_text.delete("1.0", "end")
        self.report_text.config(state="disabled")

def main():
    root = tk.Tk()
    app = OTAuditorApp(root)
    root.update_idletasks()
    w, h = root.winfo_width(), root.winfo_height()
    sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
    root.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")
    root.mainloop()

if __name__ == "__main__":
    main()
