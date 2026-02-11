# IoT/OT Security Auditor Suite (Work in Progress)


A comprehensive PowerShell-based security assessment toolkit for IoT and OT devices. Choose the version that matches your organization's needs - from essential security controls to enterprise-grade compliance with Microsoft Defender integration.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey.svg)
![Version](https://img.shields.io/badge/latest-v3.0-green.svg)

---

## 🎯 Choose Your Version

This repository contains **two powerful versions** of the IoT Security Auditor. Select the one that best fits your environment:

### 📦 Version Comparison

| Feature | **v2.0 Enhanced** | **v3.0 Enterprise (Defender)** |
|---------|-------------------|-------------------------------|
| **Best For** | General IT/ITAM Teams | Microsoft 365 E5 Customers |
| Target Devices | All IoT Devices | Enterprise IoT + OT/Industrial |
| Governance Frameworks | ✅ COBIT, ITIL, NIST, ISO 27001 | ✅ + IEC 62443 (OT) |
| Asset Discovery | ✅ CMDB Integration | ✅ + Automated Network Discovery |
| Microsoft Defender Integration | ❌ | ✅ Full Integration |
| Compliance Tracking | ✅ GDPR, HIPAA, PCI-DSS, ISO 27001 | ✅ Same + License Tracking |
| Security Challenges Coverage | Standard | ✅ Enterprise IoT Specific |
| Disaster Recovery | ✅ | ✅ |
| Vulnerability Management | Basic | ✅ Advanced (Defender Portal) |
| OT-Specific Controls | Limited | ✅ IT/OT Segmentation, IEC 62443 |
| Threat Detection | Manual Assessment | ✅ Real-time (MDE/Defender for IoT) |
| Advanced Hunting | ❌ | ✅ |
| Scoring System | 100 points | 100 points (Defender-weighted) |

---

## 🚀 Quick Start

### Option 1: Clone Repository

```bash
git clone https://github.com/yourusername/iot-security-auditor-suite.git
cd iot-security-auditor-suite
```

### Option 2: Download Release

Download the latest release from the [Releases](../../releases) page.

### Configure PowerShell

```powershell
# Check current execution policy
Get-ExecutionPolicy

# Allow script execution (run as Administrator)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Run Your Chosen Version

```powershell
# For v2.0 Enhanced (ITAM-focused)
.\IoT_Security_Auditor_Enhanced.ps1

# For v3.0 Enterprise (Microsoft Defender Integration)
.\IoT_Security_Auditor_v3_Defender.ps1
```

---

## 📋 Version Details

### 🔷 Version 2.0 - Enhanced Edition (ITAM Focus)

**Perfect for organizations implementing IT Asset Management and governance frameworks.**

#### Key Features
- ✅ **IT Governance & Policy Framework**
  - COBIT, ITIL, NIST CSF, ISO/IEC 27001 alignment
  - Security policy documentation tracking
  - IT roles and responsibilities verification

- ✅ **Asset Management & Discovery**
  - CMDB integration with Asset ID tracking
  - Location tracking
  - Automated discovery monitoring
  - Asset lifecycle management

- ✅ **Disaster Recovery & Business Continuity**
  - Documented backup plan verification
  - Off-site/cloud backup assessment
  - Recovery drill tracking
  - Business Continuity Plan (BCP) status

- ✅ **Regulatory Compliance Mapping**
  - GDPR (Data Privacy)
  - HIPAA (Healthcare)
  - ISO 27001 (Security Standards)
  - PCI-DSS (Payment Processing)
  - NIST Cybersecurity Framework

- ✅ **Enhanced Security Controls**
  - Patch management tracking
  - Network segmentation/VLANs
  - Intrusion Detection Systems (IDS)
  - Role-Based Access Control (RBAC)
  - Access logs and audit trails

#### Best Use Cases
- Organizations implementing ITAM platforms (Virima, ServiceNow, etc.)
- Compliance-driven environments (healthcare, finance, retail)
- IT teams without Microsoft E5 licensing
- General IoT device security assessments
- Multi-vendor device environments

#### Scoring Breakdown (100 points)
- IT Governance: 10 points
- Asset Management: 5 points
- Endpoint Hardening: 15 points
- Network Security: 15 points
- Data Protection: 15 points
- Access Control: 20 points
- Disaster Recovery: 10 points
- Regulatory Compliance: 10 points

---

### 🔶 Version 3.0 - Enterprise Edition (Microsoft Defender)

**Designed for Microsoft 365 E5 customers leveraging Defender for Endpoint and Defender for IoT.**

#### Key Features
- ✅ **Microsoft Defender for IoT Integration**
  - License tracking (None, MDE P2, Enterprise IoT Add-on, E5)
  - Defender for Endpoint agent monitoring
  - Defender for IoT sensor integration
  - Real-time threat detection assessment
  - Security recommendations tracking from Defender portal

- ✅ **Enterprise IoT Security Challenges**
  - Visibility into unmanaged devices
  - Complex device authentication (beyond passwords)
  - Data encryption for sensitive IoT data
  - Built-in security control verification
  - Computational capacity assessment

- ✅ **OT-Specific Security**
  - Industrial controller and SCADA system support
  - IT/OT network segmentation requirements
  - IEC 62443 framework alignment
  - Critical infrastructure protection

- ✅ **Advanced Threat Protection**
  - Vulnerability scanning integration
  - Advanced threat hunting capabilities
  - Defender portal integration for recommendations
  - Real-time alert monitoring

- ✅ **Device Type Specialization**
  - Enterprise IoT (VoIP, Printers, Smart TVs)
  - OT - Industrial Controllers
  - OT - SCADA Systems
  - Camera/Surveillance
  - Medical Devices
  - Building Automation

#### Best Use Cases
- Microsoft 365 E5/E5 Security customers
- Organizations with Defender for Endpoint deployments
- Industrial/OT environments (manufacturing, utilities, energy)
- Critical infrastructure protection
- Healthcare with connected medical devices
- Building management systems
- Environments requiring IT/OT segmentation

#### Scoring Breakdown (100 points)
- Microsoft Defender Integration: 15 points
- Asset Discovery & Visibility: 10 points
- Enterprise IoT Challenges: 10 points
- IT Governance: 8 points
- Endpoint Hardening & Vulnerability Mgmt: 12 points
- Network & Gateway Security: 12 points
- Data Protection: 10 points
- Access Control & Authentication: 13 points
- Disaster Recovery: 10 points (inherited from v2.0)

#### Defender Integration Status Report
The v3.0 audit includes comprehensive Defender status:
- License type and available capabilities
- MDE agent deployment status
- Defender for IoT sensor deployment
- Device discovery status
- Threat detection active/inactive
- Vulnerability management status
- Security recommendations tracking

---

## 📊 Risk Assessment Scoring

Both versions use the same 4-tier risk classification:

| Score Range | Risk Level | Status | Recommendation |
|-------------|-----------|---------|----------------|
| **85-100** | 🟢 LOW | COMPLIANT | Device meets enterprise standards - approved for deployment |
| **70-84** | 🟡 MEDIUM | PARTIALLY COMPLIANT | Security gaps present - remediation required before production |
| **50-69** | 🟠 HIGH | NON-COMPLIANT | Significant vulnerabilities - immediate remediation required |
| **0-49** | 🔴 CRITICAL | NON-COMPLIANT | Severe deficiencies - device MUST NOT be deployed |

---

## 📖 Detailed Usage Guide

### Step 1: Select Version Based on Environment

**Choose v2.0 Enhanced if you:**
- Need general IoT security assessment
- Are implementing ITAM platforms
- Don't have Microsoft Defender licensing
- Focus on compliance frameworks (GDPR, HIPAA, PCI-DSS)
- Manage diverse device types from multiple vendors

**Choose v3.0 Enterprise if you:**
- Have Microsoft 365 E5 or E5 Security licensing
- Use Defender for Endpoint or Defender for IoT
- Manage OT/industrial control systems
- Need IT/OT network segmentation
- Require real-time threat detection
- Want integration with Microsoft Defender portal

### Step 2: Run the Audit

#### For v2.0 Enhanced

1. **Launch the tool**
   ```powershell
   .\IoT_Security_Auditor_Enhanced.ps1
   ```

2. **Fill in device information:**
   - Device Name/ID
   - Device Type (Smart Sensor, Gateway, Camera, etc.)
   - Asset ID (CMDB reference)
   - Location

3. **Configure settings across sections:**
   - **Governance**: Select framework (COBIT, ITIL, NIST, ISO 27001)
   - **Asset Management**: Enable automated discovery if applicable
   - **Endpoint Hardening**: Check security controls (Secure Boot, signed firmware, etc.)
   - **Network Security**: Configure gateways, firewalls, segmentation
   - **Data Protection**: Select transport protocol and encryption settings
   - **Access Control**: Choose API authentication method, enable MFA
   - **Disaster Recovery**: Verify backup and BCP plans
   - **Compliance**: Check applicable regulations

4. **Run audit and export**

#### For v3.0 Enterprise (Defender)

1. **Launch the tool**
   ```powershell
   .\IoT_Security_Auditor_v3_Defender.ps1
   ```

2. **Fill in device information:**
   - Device Name/ID
   - Device Type (Enterprise IoT vs OT types)
   - Asset ID (CMDB reference)
   - Network Location
   - **Defender License** (None, MDE P2, Enterprise IoT Add-on, E5)

3. **Configure Defender monitoring:**
   - ☑ Automated Discovery
   - ☑ Monitored by Defender for Endpoint Agent
   - ☑ Monitored by Defender for IoT

4. **Address Enterprise IoT Challenges:**
   - Device visibility
   - Strong authentication
   - Data encryption
   - Built-in security controls
   - Computational capacity

5. **Configure all security sections** (similar to v2.0 but with additional OT-specific controls)

6. **Run comprehensive audit**
   - Review Defender integration status
   - Check available capabilities based on license
   - Review recommended actions for Defender deployment

### Step 3: Interpret Results

Both versions provide:
- ✅ **Security score** (0-100 with percentage)
- ✅ **Risk level** (Low/Medium/High/Critical)
- ✅ **Critical issues** - Immediate action required
- ✅ **Warnings** - Remediation recommended
- ✅ **Passed controls** - Verified security measures

**v3.0 additionally provides:**
- 📊 Microsoft Defender integration status dashboard
- 📋 Available capabilities per license tier
- 🔧 Specific Defender deployment recommendations
- 🔗 Links to Defender for IoT documentation

### Step 4: Export and Share

```powershell
# Reports are automatically named with timestamp:
# IoT_Security_Audit_DeviceName_20260128_143022.txt
# IoT_OT_Security_Audit_DeviceName_20260128_143022.txt
```

Share reports with:
- Security teams for remediation planning
- Compliance officers for regulatory documentation
- Management for risk assessment
- Vendors for security verification

---

## 📁 Repository Structure

```
iot-security-auditor-suite/
├── IoT_Security_Auditor_Enhanced.ps1          # v2.0 - ITAM Focus
├── IoT_Security_Auditor_v3_Defender.ps1       # v3.0 - Microsoft Defender
├── README.md                                   # This file
├── LICENSE                                     # MIT License
├── CHANGELOG.md                               # Version history
├── docs/
│   ├── v2-USAGE_GUIDE.md                     # Detailed v2.0 guide
│   ├── v3-USAGE_GUIDE.md                     # Detailed v3.0 guide
│   ├── SECURITY_FRAMEWORK.md                 # Assessment methodology
│   ├── COMPLIANCE_MAPPING.md                 # Regulatory framework mapping
│   ├── DEFENDER_INTEGRATION.md               # Microsoft Defender setup guide
│   └── screenshots/
│       ├── v2-interface.png
│       ├── v2-report-sample.png
│       ├── v3-interface.png
│       └── v3-defender-status.png
├── examples/
│   ├── sample_reports/
│   │   ├── v2-compliant-device.txt
│   │   ├── v2-high-risk-device.txt
│   │   ├── v3-ot-device-compliant.txt
│   │   └── v3-enterprise-iot-critical.txt
│   ├── test_scenarios_v2.md
│   └── test_scenarios_v3.md
├── templates/
│   ├── governance-policies/
│   │   ├── iot-security-policy-template.md
│   │   └── ot-security-policy-template.md
│   └── remediation-plans/
│       ├── critical-issues-remediation.md
│       └── defender-deployment-plan.md
└── .github/
    ├── ISSUE_TEMPLATE/
    │   ├── bug_report.md
    │   ├── feature_request.md
    │   └── version_comparison.md
    ├── PULL_REQUEST_TEMPLATE.md
    └── workflows/
        └── powershell-lint.yml
```

---

## 🔍 Security Assessment Domains

### Common to Both Versions

#### 1. Endpoint Hardening
- ✅ Secure Boot verification
- ✅ Firmware signature validation
- ✅ Network port management
- ✅ Endpoint protection (malware/AV)
- ✅ Patch management processes

#### 2. Network & Gateway Security
- ✅ Secure Web Gateway (SWG)
- ✅ SSL/TLS deep inspection
- ✅ VPN for remote access
- ✅ Network firewall configuration
- ✅ Network segmentation (VLANs)
- ✅ Intrusion Detection/Prevention (IDS/IPS)

#### 3. Data Protection
- ✅ Transport encryption (TLS 1.2/1.3)
- ✅ Data at rest encryption (AES-256)
- ✅ PKI and asymmetric cryptography
- ✅ Secure storage monitoring

#### 4. Access Control & Authentication
- ✅ API authentication (Basic, API Keys, OAuth, Certificates)
- ✅ Multi-Factor Authentication (MFA)
- ✅ Default credential management
- ✅ Role-Based Access Control (RBAC)
- ✅ Access logging and audit trails

### v2.0 Enhanced Additions

#### 5. IT Governance
- ✅ Framework selection (COBIT, ITIL, NIST CSF, ISO 27001)
- ✅ Policy documentation
- ✅ Role definitions
- ✅ Change management

#### 6. Asset Management
- ✅ CMDB integration
- ✅ Asset ID tracking
- ✅ Automated discovery
- ✅ Location tracking

#### 7. Disaster Recovery & Business Continuity
- ✅ Backup plan documentation
- ✅ Off-site/cloud backup
- ✅ Recovery testing
- ✅ Business Continuity Plan (BCP)

#### 8. Regulatory Compliance
- ✅ GDPR (EU data privacy)
- ✅ HIPAA (US healthcare)
- ✅ ISO 27001 (information security)
- ✅ PCI-DSS (payment card industry)
- ✅ NIST Cybersecurity Framework

### v3.0 Enterprise Additions

#### 9. Microsoft Defender Integration
- ✅ License tracking (None, MDE P2, Enterprise IoT Add-on, E5)
- ✅ Defender for Endpoint agent monitoring
- ✅ Defender for IoT deployment
- ✅ Device discovery automation
- ✅ Real-time threat detection

#### 10. Enterprise IoT Security Challenges
- ✅ Unmanaged device visibility
- ✅ Complex device authentication
- ✅ Sensitive data encryption
- ✅ Built-in security controls
- ✅ Computational capacity verification

#### 11. OT-Specific Controls
- ✅ IT/OT network segmentation
- ✅ IEC 62443 framework alignment
- ✅ SCADA system security
- ✅ Industrial controller hardening
- ✅ Critical infrastructure protection

#### 12. Advanced Threat Protection
- ✅ Vulnerability scanning integration
- ✅ Security recommendations (Defender portal)
- ✅ Advanced threat hunting
- ✅ Alert monitoring

---

## 🎯 Use Cases

### Version 2.0 Enhanced

✅ **Healthcare Providers**
- HIPAA compliance verification
- Medical device security assessment
- Patient data protection validation

✅ **Financial Institutions**
- PCI-DSS compliance for payment terminals
- IoT device inventory management
- Data encryption verification

✅ **Retail Organizations**
- Point-of-sale system security
- Smart shelf and inventory device assessment
- Multi-location device tracking

✅ **General IT Departments**
- Pre-deployment security assessments
- CMDB integration and asset tracking
- Governance framework implementation

### Version 3.0 Enterprise (Defender)

✅ **Manufacturing Plants**
- Industrial controller security (IEC 62443)
- IT/OT network segmentation verification
- SCADA system protection

✅ **Energy & Utilities**
- Critical infrastructure protection
- OT device monitoring with Defender for IoT
- Real-time threat detection

✅ **Smart Buildings**
- Building automation system (BAS) security
- HVAC and lighting control assessment
- Enterprise IoT device discovery

✅ **Microsoft 365 E5 Customers**
- Leveraging existing Defender investments
- Unified security across IT and IoT/OT
- Advanced threat hunting capabilities

✅ **Healthcare with Connected Devices**
- Medical IoT device monitoring
- Defender for Endpoint integration
- Real-time alert management

---

## 📊 Compliance Framework Mapping

### v2.0 Enhanced - Regulatory Compliance

| Framework | Focus Area | Key Requirements Assessed |
|-----------|-----------|--------------------------|
| **GDPR** | Data Privacy | Encryption, access control, data classification, audit logs |
| **HIPAA** | Healthcare Data | PHI protection, encryption, access control, audit trails |
| **ISO 27001** | Information Security | Security policies, risk management, asset management, ISMS |
| **PCI-DSS** | Payment Card Data | Network segmentation, encryption, access control, logging |
| **NIST CSF** | Cybersecurity | Identify, Protect, Detect, Respond, Recover functions |

### v3.0 Enterprise - Additional Frameworks

| Framework | Focus Area | Key Requirements Assessed |
|-----------|-----------|--------------------------|
| **IEC 62443** | OT/Industrial Security | IT/OT segmentation, zone isolation, secure development |
| **NERC-CIP** | Critical Infrastructure | Physical security, electronic security perimeters, incident response |

---

## 🛠️ Advanced Configuration

### Integration with ITAM Platforms (v2.0)

The Enhanced edition can integrate with:
- **Virima** - CMDB and asset discovery
- **ServiceNow** - IT asset management
- **Device42** - Infrastructure management
- **BMC Discovery** - Network discovery

**Integration workflow:**
1. Run automated discovery in your ITAM platform
2. Export device inventory with Asset IDs
3. Input Asset ID into auditor for tracking
4. Export audit report for CMDB attachment

### Microsoft Defender Integration (v3.0)

**Prerequisites:**
- Microsoft 365 E5 or E5 Security license
- Defender for Endpoint P2 (included in E5)
- Optional: Enterprise IoT add-on or Defender for IoT

**Setup workflow:**
1. Deploy Defender for Endpoint agents to manageable devices
2. Configure Defender for IoT sensors for OT networks
3. Enable device discovery in Microsoft 365 Defender portal
4. Access device inventory at: **Assets > Devices > IoT devices**
5. Review alerts, recommendations, and vulnerabilities
6. Use auditor to assess configuration compliance

**Defender Portal Integration Points:**
- Device discovery and inventory
- Security alerts triggered by IoT assets
- Security recommendations for IoT devices
- Vulnerability discovery and tracking
- Advanced hunting queries for custom rules

---

## 🐛 Troubleshooting

### Common Issues - Both Versions

#### Script Execution Policy Error

**Error**: `"Cannot be loaded because running scripts is disabled on this system"`

**Solution**:
```powershell
# Check current policy
Get-ExecutionPolicy

# Set to RemoteSigned (recommended)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Or set to Bypass for single execution
powershell.exe -ExecutionPolicy Bypass -File .\IoT_Security_Auditor_Enhanced.ps1
```

#### GUI Not Displaying

**Issue**: Form window doesn't appear or immediately closes

**Solutions**:
1. Verify you're using PowerShell.exe (not PowerShell ISE)
   ```powershell
   # Launch with explicit exe
   powershell.exe .\IoT_Security_Auditor_Enhanced.ps1
   ```

2. Check for .NET Framework errors:
   ```powershell
   # Verify Windows Forms is available
   Add-Type -AssemblyName System.Windows.Forms
   ```

3. Run as Administrator if permissions issues occur

#### Export Function Not Working

**Issue**: "Access Denied" or file not created

**Solutions**:
- Verify you have write permissions to the selected directory
- Choose a different save location (Documents folder recommended)
- Run PowerShell as Administrator

### Version-Specific Issues

#### v2.0 - CMDB Integration Issues

**Issue**: Asset IDs not being recognized

**Solution**: Ensure Asset IDs match your CMDB format:
- No special characters that might conflict
- Use alphanumeric identifiers
- Match your organization's naming convention

#### v3.0 - Defender Integration Confusion

**Issue**: Unsure which Defender license you have

**Solution**:
```powershell
# Check Microsoft 365 admin center
# Navigate to: Billing > Your Products > Microsoft 365 E5/E5 Security

# Or check Defender portal
# https://security.microsoft.com > Settings > Endpoints > Licenses
```

**Issue**: Device not showing in Defender portal

**Solution**:
1. Verify Defender for Endpoint agent is installed:
   ```powershell
   # Check if MDE service is running
   Get-Service -Name Sense
   ```

2. Check device onboarding status in Defender portal
3. For OT devices, verify Defender for IoT sensor deployment

---

## 🔐 Security Best Practices

### Before Running Audits

1. **Verify script integrity**
   ```powershell
   # Get file hash to verify authenticity
   Get-FileHash .\IoT_Security_Auditor_Enhanced.ps1 -Algorithm SHA256
   ```

2. **Review script contents** - PowerShell scripts should always be reviewed before execution

3. **Use in isolated environment first** - Test in dev/staging before production

### During Audits

1. **Document assumptions** - Note any controls you can't verify directly
2. **Cross-reference with actual device configs** - The tool assesses based on inputs
3. **Involve device owners** - Ensure accurate information
4. **Take screenshots** - Capture results for audit trails

### After Audits

1. **Secure audit reports** - Contains sensitive security information
2. **Track remediation** - Use reports to drive security improvements
3. **Schedule regular re-audits** - Quarterly or after significant changes
4. **Share with stakeholders** - Security teams, compliance, management

---

## 📚 Documentation

### Quick Reference Guides

- **[v2.0 Usage Guide](docs/v2-USAGE_GUIDE.md)** - Step-by-step walkthrough
- **[v3.0 Usage Guide](docs/v3-USAGE_GUIDE.md)** - Defender integration guide
- **[Security Framework](docs/SECURITY_FRAMEWORK.md)** - Assessment methodology
- **[Compliance Mapping](docs/COMPLIANCE_MAPPING.md)** - Regulatory alignment
- **[Defender Integration](docs/DEFENDER_INTEGRATION.md)** - Microsoft setup guide

### Sample Reports

Review example audit outputs:
- [v2.0 Compliant Device](examples/sample_reports/v2-compliant-device.txt)
- [v2.0 High Risk Device](examples/sample_reports/v2-high-risk-device.txt)
- [v3.0 OT Device Compliant](examples/sample_reports/v3-ot-device-compliant.txt)
- [v3.0 Critical IoT Device](examples/sample_reports/v3-enterprise-iot-critical.txt)

---

## 🤝 Contributing

We welcome contributions! Here's how you can help:

### Reporting Issues

Use our GitHub issue templates:
- [Bug Report](.github/ISSUE_TEMPLATE/bug_report.md) - Report functionality problems
- [Feature Request](.github/ISSUE_TEMPLATE/feature_request.md) - Suggest enhancements
- [Version Comparison](.github/ISSUE_TEMPLATE/version_comparison.md) - Discuss version features

### Submitting Pull Requests

1. Fork the repository
2. Create a feature branch:
   ```bash
   git checkout -b feature/YourFeatureName
   ```
3. Make your changes following our guidelines
4. Test on PowerShell 5.1 and 7.x
5. Update documentation
6. Submit PR with clear description

### Development Guidelines

#### Code Style
- Follow PowerShell best practices
- Use approved verbs for functions
- Comment complex logic
- Maintain backward compatibility with PS 5.1

#### Testing Requirements
- Test on Windows 10 and Windows 11
- Test on Windows Server 2016+
- Verify both PowerShell 5.1 and 7.x
- Test with various license scenarios (v3.0)

#### Documentation
- Update README for new features
- Add examples for complex functionality
- Include screenshots for UI changes
- Update CHANGELOG.md

---

## 📈 Roadmap

### Planned Features

#### Version 2.x Enhancements
- [ ] Export to DOCX/PDF formats
- [ ] Batch audit multiple devices
- [ ] Integration with ServiceNow API
- [ ] Custom scoring weight configuration
- [ ] Multi-language support

#### Version 3.x Enhancements
- [ ] Direct Defender API integration
- [ ] Automated vulnerability pull from Defender
- [ ] Real-time alert correlation
- [ ] Advanced hunting query generator
- [ ] Defender for Cloud integration

#### Future Versions
- [ ] Web-based interface option
- [ ] Scheduled automated audits
- [ ] Email report distribution
- [ ] Dashboard with trending
- [ ] Machine learning risk prediction

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

**Key points:**
- ✅ Free to use for commercial and personal projects
- ✅ Modify and distribute as needed
- ✅ No warranty provided
- ✅ Attribution appreciated but not required

---

## 🔗 References & Resources

### Standards & Frameworks

- **[NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)** - Core security framework
- **[ISO/IEC 27001](https://www.iso.org/isoiec-27001-information-security.html)** - Information security standard
- **[IEC 62443](https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series-of-standards)** - Industrial automation security
- **[OWASP IoT Security](https://owasp.org/www-project-internet-of-things/)** - IoT security project

### Microsoft Resources

- **[Microsoft Defender for IoT Documentation](https://learn.microsoft.com/defender-iot)** - Official docs
- **[Microsoft Defender for Endpoint](https://learn.microsoft.com/microsoft-365/security/defender-endpoint/)** - MDE setup
- **[Microsoft 365 Defender Portal](https://security.microsoft.com)** - Security center
- **[Enterprise IoT Security](https://learn.microsoft.com/defender-iot/organizations/enterprise-iot-overview)** - IoT protection

### Compliance Resources

- **[GDPR Compliance](https://gdpr.eu/)** - EU data protection
- **[HIPAA Guidance](https://www.hhs.gov/hipaa/index.html)** - US healthcare privacy
- **[PCI-DSS Standards](https://www.pcisecuritystandards.org/)** - Payment card security
- **[NERC-CIP](https://www.nerc.com/pa/Stand/Pages/CIPStandards.aspx)** - Critical infrastructure

### ITAM Platforms

- **[Virima](https://virima.com/)** - IT asset management
- **[ServiceNow ITAM](https://www.servicenow.com/products/it-asset-management.html)** - Enterprise ITAM
- **[Device42](https://www.device42.com/)** - Infrastructure management

---

## 👥 Authors & Acknowledgments

### Authors
- **Gareth Sheldon** - Initial development and v1.0-v3.0 releases
- **Contributors** - See [CONTRIBUTORS.md](CONTRIBUTORS.md)

### Acknowledgments

This project was inspired by and built upon:
- Real-world enterprise IoT security challenges
- ITAM best practices from Virima and industry leaders
- Microsoft Defender for IoT documentation
- IEC 62443 industrial security standards
- NIST Cybersecurity Framework guidance
- PowerShell community GUI development resources

Special thanks to:
- Microsoft Security team for Defender for IoT
- Industrial control system security researchers
- Healthcare IoT security practitioners
- The PowerShell community

---

## 📮 Contact & Support

### Get Help

- 📖 **Documentation**: Check the `/docs` folder
- 🐛 **Issues**: [GitHub Issues](../../issues)
- 💬 **Discussions**: [GitHub Discussions](../../discussions)
- ✉️ **Email**: security-auditor@example.com

### Community

- 🌟 **Star this repo** if you find it useful
- 🔔 **Watch** for updates and new releases
- 🍴 **Fork** to customize for your organization
- 📢 **Share** with colleagues in IT security

---

## ⚠️ Disclaimer

**Important Information:**

1. **Assessment Tool Only**: This tool provides security assessment guidance based on configuration inputs provided by the user. It does not perform active network scanning, penetration testing, or automated vulnerability detection.

2. **No Warranty**: Provided "as-is" without warranty of any kind. See LICENSE for details.

3. **Professional Review**: Audit results should be reviewed by qualified security professionals before making deployment decisions.

4. **Comprehensive Testing Required**: Always conduct thorough security testing (including penetration testing, vulnerability scanning, and code review) before deploying IoT/OT devices in production environments.

5. **Regulatory Compliance**: This tool assists with compliance assessment but does not guarantee regulatory compliance. Consult with compliance officers and legal counsel for regulatory requirements.

6. **Microsoft Integration**: v3.0's Microsoft Defender integration features require appropriate licensing and are subject to Microsoft's terms of service. This is an independent tool and is not officially affiliated with or endorsed by Microsoft Corporation.

7. **OT Environments**: Extra caution should be exercised when assessing operational technology (OT) environments. Ensure assessments comply with your organization's change management and safety procedures.

---

## 🎉 Getting Started

Choose your version and start securing your IoT/OT infrastructure today!

```powershell
# For general IT environments with ITAM focus
.\IoT_Security_Auditor_Enhanced.ps1

# For Microsoft 365 E5 customers with Defender
.\IoT_Security_Auditor_v3_Defender.ps1
```

**Questions?** Open an [issue](../../issues) or start a [discussion](../../discussions).

**Ready to contribute?** Check our [contribution guidelines](#contributing).

---

**Last Updated**: January 28, 2026  
**Current Version**: v3.0 (Enterprise Edition)  
**Maintained By**: Gareth Sheldon and contributors
