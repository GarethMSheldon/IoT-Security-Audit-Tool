
# OT/ICS Security Auditor – Python GUI Edition

A comprehensive Python-based security assessment toolkit for OT (Operational Technology), ICS (Industrial Control Systems), SCADA, and IoT devices. Performs deep discovery of industrial protocols, checks for default credentials, insecure configurations, and missing encryption – all through a modern dark‑amber graphical interface.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/Python-3.7%2B-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)
![Version](https://img.shields.io/badge/version-v1.2-green.svg)

---

## Overview

This tool provides an intuitive GUI for active reconnaissance on OT networks. It supports 20+ industrial protocols, concurrent scanning, real‑time progress, and risk scoring. Results can be exported to CSV, JSON, XML, and PDF (optional).

**Supported Protocols (23+):**
- Modbus TCP/UDP (port 502)
- S7comm / S7 Plus (Siemens, port 102)
- DNP3 (port 20000)
- IEC 60870-5-104 (port 2404)
- OPC UA (port 4840)
- EtherNet/IP (CIP, port 44818)
- BACnet/IP (UDP 47808)
- Profinet DCP (UDP 34980)
- MQTT (1883) / MQTTS (8883)
- CoAP (UDP 5683)
- FINS (Omron, UDP 9600)
- Telnet, FTP, HTTP/HTTPS (80,443,8080,8443)
- SRTP (GE Fanuc, 18245)
- Crimson v3 (Red Lion, 789)
- Melsec-Q (Mitsubishi, 5007)
- and more…

**Key Features:**
- 🖥️ **Dark amber GUI** – easy on the eyes, industrial‑themed
- ⚡ **Concurrent scanning** – adjustable thread pool (default 50)
- 📡 **Real‑time log & findings table** – instant feedback
- 🔐 **Default credential test** – checks 16+ common passwords on HTTP/HTTPS interfaces
- 📊 **Risk scoring** – per‑device and overall (0–100, 4 risk tiers)
- 📄 **Multi‑format export** – CSV, JSON, XML, and PDF (requires `reportlab`)
- 🗺️ **Flexible target input** – single IP, CIDR (e.g., 192.168.1.0/24), range (10.0.0.1-254)
- 🔄 **Cancel button** – stop long scans gracefully
- 📈 **Built‑in recommendations** – based on IEC 62443, NIST SP 800-82

---

## Installation

### Clone the repository

```bash
git clone https://github.com/GarethMSheldon/IoT-Security-Audit-Tool.git
cd IoT-Security-Audit-Tool
```

### Dependencies

The tool uses only the Python standard library plus `tkinter` (included with Python). For PDF export, install `reportlab` (optional):

```bash
pip install reportlab
```

On **Linux**, you may need to install `python3-tk` separately:

```bash
sudo apt-get install python3-tk   # Debian/Ubuntu
sudo dnf install python3-tkinter   # Fedora
```

On **Windows** and **macOS**, tkinter is included by default.

---

## Running the Tool

```bash
python IoTSecurityAuditor.py
```

No command‑line arguments required – everything is configured inside the GUI.

---

## Using the GUI

### Main Layout

- **Left panel** – target entry, protocol selection, scan options, and action buttons.
- **Right panel** – tabbed view: Live Log, Findings Table, Risk Summary, Full Report.

### Step‑by‑Step Scan

1. **Enter target** – single IP (e.g., `192.168.1.100`), CIDR (`192.168.1.0/24`), or range (`10.0.0.1-254`). Separate multiple targets with commas.
2. **Adjust timeout & threads** – timeout in milliseconds (default 2000), threads (default 50).
3. **Select protocols** – use “☑ ALL PROTOCOLS” or pick individual ones.
4. **Enable optional tests** – “Test default credentials” (recommended).
5. **Click “START SCAN”** – watch the live log and progress bar.
6. **After scan finishes**, review findings in the “FINDINGS” tab, “RISK SUMMARY”, and “FULL REPORT”.
7. **Export results** – use the CSV, JSON, XML, or PDF buttons.

### Understanding Risk Scores

| Score Range | Risk Level | Color |
|-------------|------------|-------|
| 0–19        | SECURE / LOW | Green / Yellow |
| 20–49       | MEDIUM       | Orange |
| 50–74       | HIGH         | Red |
| 75–100      | CRITICAL     | Bright Red |

The score is weighted by protocol risk labels (CRITICAL=40, HIGH=25, MEDIUM=10, LOW=5, INFO=2).

### Recommendations

The tool includes a static list of best‑practice remediations based on detected protocols. Always combine automated scanning with manual validation.

---

## Command Line Mode

For scripting or headless environments, the same script supports a CLI mode:

```bash
python IoTSecurityAuditor.py --cli --target 192.168.1.0/24 --cred-test
```

Available arguments:

| Argument | Description |
|----------|-------------|
| `--cli` | Enable command‑line interface (no GUI) |
| `--target` (or `-t`) | Single IP, CIDR, or range |
| `--outfile` (or `-o`) | Output CSV file path |
| `--timeout` (or `-to`) | Timeout in milliseconds |
| `--cred-test` | Test default credentials on web interfaces |
| `--detailed` | Show verbose output |

---

## Output Files

When a scan finishes, the tool can automatically save:

- **CSV** – machine‑readable list of all findings.
- **Text report** – human‑readable summary (auto‑saved if enabled).

Manual exports (CSV, JSON, XML, PDF) are available via the export buttons.

Example CSV columns:

```text
ip,protocol,port,category,risk,detail
192.168.1.10,Modbus TCP,502,ICS/PLC,CRITICAL – unauthenticated read/write of registers,Modbus RTU unit=1...
```

---

## Troubleshooting

### GUI does not appear / tkinter missing

- **Linux:** Install `python3-tk` as shown above.
- **Windows/macOS:** Reinstall Python and ensure “tcl/tk” is selected.

### PDF export fails

Install `reportlab`:

```bash
pip install reportlab
```

### Scan finds no devices

- Verify the target range is correct.
- Check firewall rules – probes require outbound access to the specified ports.
- Increase timeout (e.g., 3000–5000 ms) for slow industrial networks.
- Some devices may not respond to the default probes (non‑standard implementations).

### “Partial Modbus response” messages

The device may be using a different unit identifier or require a different function code. Manual verification is advised.

---

## Repository Structure

```text
IoT-Security-Audit-Tool/
├── IoTSecurityAuditor.py       # Main GUI / CLI scanner
├── README.md                   # This file
├── license_file.md             # MIT License
└── (other assets)
```

---

## Contributing

Contributions are welcome. Please follow these guidelines:

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/new-probe`).
3. Ensure your code works on Python 3.7+ without external dependencies (except `reportlab` for PDF).
4. Add comments for any new protocol probes.
5. Test the GUI on at least one platform (Windows/Linux/macOS).
6. Submit a pull request with a clear description.

**Planned improvements:**
- Support for additional OT protocols (e.g., CANopen, Profibus)
- Active vulnerability checks (CVE‑specific probes)
- TLS/encryption detection for Modbus/TLS and OPC UA
- Export to DOCX
- Dark theme toggle

---

## License

This project is licensed under the MIT License – see the [license_file.md](license_file.md) for details.

You are free to use, modify, and distribute this software for any purpose, subject to the terms of the MIT License.

---

## Disclaimer

This tool performs active network reconnaissance. Use only on networks you own or have explicit permission to test. The authors assume no liability for misuse or damage caused by this software.

---

## Authors & Acknowledgments

- **Original PowerShell versions** – Gareth Sheldon
- **Python GUI port & unification** – Gareth Sheldon and community

Inspired by real‑world OT security assessments, industrial protocol specifications, and the need for a cross‑platform, no‑dependency auditing tool.

Special thanks to the tkinter community and industrial control system security researchers.

---

## Contact & Support

- **Issues**: [GitHub Issues](https://github.com/GarethMSheldon/IoT-Security-Audit-Tool/issues)
- **Discussions**: [GitHub Discussions](https://github.com/GarethMSheldon/IoT-Security-Audit-Tool/discussions)

---

**Last Updated**: April 26, 2026  
**Current Version**: v1.2  
**Maintained By**: Gareth Sheldon
