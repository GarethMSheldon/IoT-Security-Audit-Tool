# IoT Security Audit Tool

A professional-grade PowerShell GUI tool for auditing IoT device security configurations. Designed for IT professionals, security consultants, and system administrators to assess compliance with industry security best practices.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey.svg)

## 🔒 Overview

The IoT Security Auditor provides comprehensive security assessment across multiple domains:

- **Endpoint Hardening** - Secure boot, firmware verification, port management
- **Network Security** - Gateway filtering, SSL inspection, firewall configuration
- **Data Protection** - Transport encryption, data-at-rest security, PKI
- **Access Control** - API authentication, MFA, credential management

## ✨ Features

- ✅ **100-Point Scoring System** - Weighted security assessment with risk levels
- ✅ **Multi-Category Analysis** - Evaluates 5 critical security domains
- ✅ **Professional Reporting** - Detailed reports with critical issues, warnings, and passes
- ✅ **Export Functionality** - Save timestamped audit reports for compliance documentation
- ✅ **Dark Theme UI** - Professional interface optimized for IT environments
- ✅ **Color-Coded Results** - Visual risk indicators (green/yellow/orange/red)

## 📋 Requirements

- **Operating System**: Windows 10/11 or Windows Server 2016+
- **PowerShell**: Version 5.1 or higher
- **Execution Policy**: Must allow script execution (see Installation)

## 🚀 Installation

### Option 1: Clone Repository

```bash
git clone https://github.com/yourusername/iot-security-auditor.git
cd iot-security-auditor
```

### Option 2: Download Release

Download the latest release from the [Releases](../../releases) page and extract to your preferred location.

### Configure PowerShell Execution Policy

```powershell
# Check current policy
Get-ExecutionPolicy

# Set policy to allow local scripts (run as Administrator)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

## 📖 Usage

### Running the Tool

```powershell
# Navigate to the directory
cd path\to\iot-security-auditor

# Run the script
.\IoTSecurityAuditor.ps1
```

### Workflow

1. **Enter Device Information**
   - Device Name/ID
   - Device Type (Sensor, Gateway, Camera, etc.)

2. **Configure Security Settings**
   - Check applicable security controls across all categories
   - Select transport protocols and API authentication methods

3. **Run Audit**
   - Click "RUN SECURITY AUDIT" button
   - Review color-coded results and security score

4. **Export Report**
   - Click "EXPORT REPORT" to save audit findings
   - Reports include timestamp and full assessment details

## 📊 Scoring System

| Score Range | Risk Level | Description |
|-------------|-----------|-------------|
| 85-100 | **LOW** | Device meets enterprise security standards |
| 65-84 | **MEDIUM** | Security gaps present - remediation recommended |
| 40-64 | **HIGH** | Significant vulnerabilities - immediate action required |
| 0-39 | **CRITICAL** | Severe deficiencies - device should NOT be deployed |

## 🔍 Security Categories

### Endpoint Hardening (25 points)
- Secure Boot (8 pts)
- Firmware Signature Verification (8 pts)
- Unused Ports Disabled (5 pts)
- Endpoint Malware Protection (4 pts)

### Network & Gateway Security (20 points)
- Secure Web Gateway (7 pts)
- Deep SSL/TLS Inspection (5 pts)
- VPN Configuration (4 pts)
- Network Firewall (4 pts)

### Data Protection (25 points)
- Transport Encryption - TLS 1.3 (10 pts)
- Data at Rest Encryption (8 pts)
- Asymmetric Key Exchange (4 pts)
- Secure Storage Monitoring (3 pts)

### Access Control (30 points)
- API Authentication (15 pts)
- Multi-Factor Authentication (10 pts)
- Default Credentials Changed (5 pts)
- **Penalty**: Default credentials active (-20 pts)

## 🎯 Use Cases

- **Pre-Deployment Audits** - Assess device security before production deployment
- **Compliance Verification** - Document adherence to security frameworks (NERC-CIP, NIST)
- **Vulnerability Assessment** - Identify security gaps in existing IoT infrastructure
- **Security Training** - Demonstrate security best practices to development teams
- **Vendor Evaluation** - Compare security posture of different IoT products

## 📁 Repository Structure

```
iot-security-auditor/
├── IoTSecurityAuditor.ps1    # Main application script
├── README.md                  # This file
├── LICENSE                    # MIT License
├── CHANGELOG.md              # Version history
├── docs/
│   ├── USAGE_GUIDE.md        # Detailed usage instructions
│   ├── SECURITY_FRAMEWORK.md # Security assessment methodology
│   └── screenshots/          # Application screenshots
├── examples/
│   ├── sample_reports/       # Example audit reports
│   └── test_scenarios.md     # Common test scenarios
└── .github/
    └── ISSUE_TEMPLATE.md     # Issue reporting template
```

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Development Guidelines

- Follow PowerShell best practices and style guidelines
- Maintain backward compatibility with PowerShell 5.1
- Test on multiple Windows versions
- Update documentation for new features
- Include comments for complex logic

## 🐛 Troubleshooting

### Script Won't Run

**Issue**: "Cannot be loaded because running scripts is disabled"

**Solution**: 
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Form Doesn't Display

**Issue**: GUI window doesn't appear

**Solution**: Ensure you're running PowerShell (not PowerShell ISE) and Windows Forms assemblies are available.

### Unicode Characters Display Incorrectly

**Issue**: Symbols appear as boxes or question marks

**Solution**: This version uses ASCII-only characters. If issues persist, check console font settings.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 References

- [NIST IoT Security Guidelines](https://www.nist.gov/programs-projects/nist-cybersecurity-iot-program)
- [OWASP IoT Security](https://owasp.org/www-project-internet-of-things/)
- [Fortinet IoT Security Best Practices](https://www.fortinet.com/)
- [NERC-CIP Standards](https://www.nerc.com/pa/Stand/Pages/CIPStandards.aspx)

## 👥 Authors

- **Your Name** - Initial work

## 🙏 Acknowledgments

- Based on industry security frameworks including NERC-CIP and Fortinet IoT Security Guidelines
- Inspired by real-world IoT security challenges in enterprise environments
- Thanks to the PowerShell community for GUI development resources

## 📮 Contact

- **Issues**: [GitHub Issues](../../issues)
- **Discussions**: [GitHub Discussions](../../discussions)
- **Email**: your.email@example.com

---

**⚠️ Disclaimer**: This tool provides security assessment guidance based on configuration inputs. It does not perform active network scanning or penetration testing. Always conduct comprehensive security testing before deploying IoT devices in production environments.
