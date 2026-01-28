<#
.SYNOPSIS
    IoT/OT Device Security Auditor - Enterprise Edition v3.0
.DESCRIPTION
    A comprehensive security assessment tool for IoT/OT device configurations aligned with
    Microsoft Defender for IoT and enterprise security standards.
    Evaluates endpoint hardening, network security, encryption, compliance, device discovery,
    threat detection, vulnerability management, and Microsoft Defender integration.
.NOTES
    Author: Gareth Sheldon
    Version: 3.0
    Updated: 2026-01-28
    Compliance: GDPR, HIPAA, ISO 27001, PCI-DSS, NIST CSF
    Integration: Microsoft Defender for Endpoint, Microsoft Defender for IoT
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# --- Form Setup ---
$form = New-Object System.Windows.Forms.Form
$form.Text = "IoT/OT Security Auditor - Enterprise Edition v3.0"
$form.Size = New-Object System.Drawing.Size(950, 900)
$form.StartPosition = "CenterScreen"
$form.BackColor = "#2b2b2b"
$form.FormBorderStyle = "FixedDialog"
$form.MaximizeBox = $false

# --- Fonts ---
$headerFont = New-Object System.Drawing.Font("Segoe UI", 13, [System.Drawing.FontStyle]::Bold)
$labelFont = New-Object System.Drawing.Font("Segoe UI", 9)
$consFont = New-Object System.Drawing.Font("Consolas", 9)

# --- Header Panel ---
$pnlHeader = New-Object System.Windows.Forms.Panel
$pnlHeader.Location = New-Object System.Drawing.Point(0, 0)
$pnlHeader.Size = New-Object System.Drawing.Size(950, 70)
$pnlHeader.BackColor = "#1a1a1a"
$form.Controls.Add($pnlHeader)

$lblHeader = New-Object System.Windows.Forms.Label
$lblHeader.Text = "IOT/OT ENTERPRISE SECURITY ASSESSMENT v3.0"
$lblHeader.Location = New-Object System.Drawing.Point(20, 12)
$lblHeader.AutoSize = $true
$lblHeader.Font = $headerFont
$lblHeader.ForeColor = "#00d9ff"
$pnlHeader.Controls.Add($lblHeader)

$lblSubHeader = New-Object System.Windows.Forms.Label
$lblSubHeader.Text = "Microsoft Defender for IoT Integration | Enterprise IoT/OT Protection"
$lblSubHeader.Location = New-Object System.Drawing.Point(20, 40)
$lblSubHeader.AutoSize = $true
$lblSubHeader.Font = $labelFont
$lblSubHeader.ForeColor = "#cccccc"
$pnlHeader.Controls.Add($lblSubHeader)

# --- SECTION 1: Device Information & Discovery ---
$grpDevice = New-Object System.Windows.Forms.GroupBox
$grpDevice.Text = "Device Information & Asset Discovery"
$grpDevice.Location = New-Object System.Drawing.Point(20, 85)
$grpDevice.Size = New-Object System.Drawing.Size(900, 120)
$grpDevice.ForeColor = "#e0e0e0"
$grpDevice.Font = $labelFont
$form.Controls.Add($grpDevice)

$lblDevName = New-Object System.Windows.Forms.Label
$lblDevName.Text = "Device Name/ID:"
$lblDevName.Location = New-Object System.Drawing.Point(15, 25)
$lblDevName.AutoSize = $true
$lblDevName.ForeColor = "#e0e0e0"
$grpDevice.Controls.Add($lblDevName)

$txtDevName = New-Object System.Windows.Forms.TextBox
$txtDevName.Location = New-Object System.Drawing.Point(120, 22)
$txtDevName.Width = 180
$grpDevice.Controls.Add($txtDevName)

$lblDevType = New-Object System.Windows.Forms.Label
$lblDevType.Text = "Device Type:"
$lblDevType.Location = New-Object System.Drawing.Point(320, 25)
$lblDevType.AutoSize = $true
$lblDevType.ForeColor = "#e0e0e0"
$grpDevice.Controls.Add($lblDevType)

$cmbDevType = New-Object System.Windows.Forms.ComboBox
$cmbDevType.Location = New-Object System.Drawing.Point(405, 22)
$cmbDevType.Width = 200
$cmbDevType.DropDownStyle = "DropDownList"
$cmbDevType.Items.AddRange(@("Enterprise IoT (VoIP/Printer/Smart TV)", "OT - Industrial Controller", "OT - SCADA System", "Camera/Surveillance", "Medical Device", "Smart Sensor", "Building Automation", "Other Unmanaged Device"))
$cmbDevType.SelectedIndex = 0
$grpDevice.Controls.Add($cmbDevType)

$lblAssetID = New-Object System.Windows.Forms.Label
$lblAssetID.Text = "Asset ID (CMDB):"
$lblAssetID.Location = New-Object System.Drawing.Point(15, 55)
$lblAssetID.AutoSize = $true
$lblAssetID.ForeColor = "#e0e0e0"
$grpDevice.Controls.Add($lblAssetID)

$txtAssetID = New-Object System.Windows.Forms.TextBox
$txtAssetID.Location = New-Object System.Drawing.Point(120, 52)
$txtAssetID.Width = 180
$grpDevice.Controls.Add($txtAssetID)

$lblLocation = New-Object System.Windows.Forms.Label
$lblLocation.Text = "Network Location:"
$lblLocation.Location = New-Object System.Drawing.Point(320, 55)
$lblLocation.AutoSize = $true
$lblLocation.ForeColor = "#e0e0e0"
$grpDevice.Controls.Add($lblLocation)

$txtLocation = New-Object System.Windows.Forms.TextBox
$txtLocation.Location = New-Object System.Drawing.Point(435, 52)
$txtLocation.Width = 170
$grpDevice.Controls.Add($txtLocation)

$lblDefenderLicense = New-Object System.Windows.Forms.Label
$lblDefenderLicense.Text = "Defender License:"
$lblDefenderLicense.Location = New-Object System.Drawing.Point(625, 25)
$lblDefenderLicense.AutoSize = $true
$lblDefenderLicense.ForeColor = "#e0e0e0"
$grpDevice.Controls.Add($lblDefenderLicense)

$cmbDefenderLicense = New-Object System.Windows.Forms.ComboBox
$cmbDefenderLicense.Location = New-Object System.Drawing.Point(735, 22)
$cmbDefenderLicense.Width = 150
$cmbDefenderLicense.DropDownStyle = "DropDownList"
$cmbDefenderLicense.Items.AddRange(@("None", "MDE P2", "Enterprise IoT Add-on", "E5/E5 Security"))
$cmbDefenderLicense.SelectedIndex = 0
$grpDevice.Controls.Add($cmbDefenderLicense)

$chkAutoDiscovery = New-Object System.Windows.Forms.CheckBox
$chkAutoDiscovery.Text = "Automated Discovery (Network Scanning)"
$chkAutoDiscovery.Location = New-Object System.Drawing.Point(15, 85)
$chkAutoDiscovery.AutoSize = $true
$chkAutoDiscovery.ForeColor = "#e0e0e0"
$grpDevice.Controls.Add($chkAutoDiscovery)

$chkDefenderMonitored = New-Object System.Windows.Forms.CheckBox
$chkDefenderMonitored.Text = "Monitored by Defender for Endpoint Agent"
$chkDefenderMonitored.Location = New-Object System.Drawing.Point(320, 85)
$chkDefenderMonitored.AutoSize = $true
$chkDefenderMonitored.ForeColor = "#e0e0e0"
$grpDevice.Controls.Add($chkDefenderMonitored)

$chkDefenderIoT = New-Object System.Windows.Forms.CheckBox
$chkDefenderIoT.Text = "Monitored by Defender for IoT"
$chkDefenderIoT.Location = New-Object System.Drawing.Point(625, 85)
$chkDefenderIoT.AutoSize = $true
$chkDefenderIoT.ForeColor = "#e0e0e0"
$grpDevice.Controls.Add($chkDefenderIoT)

# --- SECTION 2: Enterprise IoT Security Challenges ---
$grpChallenges = New-Object System.Windows.Forms.GroupBox
$grpChallenges.Text = "Enterprise IoT/OT Security Controls"
$grpChallenges.Location = New-Object System.Drawing.Point(20, 215)
$grpChallenges.Size = New-Object System.Drawing.Size(440, 155)
$grpChallenges.ForeColor = "#e0e0e0"
$form.Controls.Add($grpChallenges)

$chkVisibility = New-Object System.Windows.Forms.CheckBox
$chkVisibility.Text = "Full Device Visibility (No Blind Spots)"
$chkVisibility.Location = New-Object System.Drawing.Point(15, 25)
$chkVisibility.AutoSize = $true
$chkVisibility.ForeColor = "#e0e0e0"
$grpChallenges.Controls.Add($chkVisibility)

$chkDeviceAuth = New-Object System.Windows.Forms.CheckBox
$chkDeviceAuth.Text = "Strong Device Authentication (Beyond Passwords)"
$chkDeviceAuth.Location = New-Object System.Drawing.Point(15, 50)
$chkDeviceAuth.AutoSize = $true
$chkDeviceAuth.ForeColor = "#e0e0e0"
$grpChallenges.Controls.Add($chkDeviceAuth)

$chkDataEncryption = New-Object System.Windows.Forms.CheckBox
$chkDataEncryption.Text = "Comprehensive Data Encryption"
$chkDataEncryption.Location = New-Object System.Drawing.Point(15, 75)
$chkDataEncryption.AutoSize = $true
$chkDataEncryption.ForeColor = "#e0e0e0"
$grpChallenges.Controls.Add($chkDataEncryption)

$chkBuiltInSecurity = New-Object System.Windows.Forms.CheckBox
$chkBuiltInSecurity.Text = "Built-in Security Controls (Not Legacy Device)"
$chkBuiltInSecurity.Location = New-Object System.Drawing.Point(15, 100)
$chkBuiltInSecurity.AutoSize = $true
$chkBuiltInSecurity.ForeColor = "#e0e0e0"
$grpChallenges.Controls.Add($chkBuiltInSecurity)

$chkComputeCapacity = New-Object System.Windows.Forms.CheckBox
$chkComputeCapacity.Text = "Adequate Compute for Security Measures"
$chkComputeCapacity.Location = New-Object System.Drawing.Point(15, 125)
$chkComputeCapacity.AutoSize = $true
$chkComputeCapacity.ForeColor = "#e0e0e0"
$grpChallenges.Controls.Add($chkComputeCapacity)

# --- SECTION 3: IT Governance ---
$grpGovernance = New-Object System.Windows.Forms.GroupBox
$grpGovernance.Text = "IT Governance & Policy Framework"
$grpGovernance.Location = New-Object System.Drawing.Point(470, 215)
$grpGovernance.Size = New-Object System.Drawing.Size(450, 155)
$grpGovernance.ForeColor = "#e0e0e0"
$form.Controls.Add($grpGovernance)

$lblFramework = New-Object System.Windows.Forms.Label
$lblFramework.Text = "Governance Framework:"
$lblFramework.Location = New-Object System.Drawing.Point(15, 25)
$lblFramework.AutoSize = $true
$lblFramework.ForeColor = "#e0e0e0"
$grpGovernance.Controls.Add($lblFramework)

$cmbFramework = New-Object System.Windows.Forms.ComboBox
$cmbFramework.Location = New-Object System.Drawing.Point(160, 22)
$cmbFramework.Width = 260
$cmbFramework.DropDownStyle = "DropDownList"
$cmbFramework.Items.AddRange(@("None", "COBIT", "ITIL", "NIST CSF", "ISO/IEC 27001", "IEC 62443 (OT)", "Custom Framework"))
$cmbFramework.SelectedIndex = 0
$grpGovernance.Controls.Add($cmbFramework)

$chkPolicyDoc = New-Object System.Windows.Forms.CheckBox
$chkPolicyDoc.Text = "IoT/OT Security Policies Documented"
$chkPolicyDoc.Location = New-Object System.Drawing.Point(15, 55)
$chkPolicyDoc.AutoSize = $true
$chkPolicyDoc.ForeColor = "#e0e0e0"
$grpGovernance.Controls.Add($chkPolicyDoc)

$chkRolesDefined = New-Object System.Windows.Forms.CheckBox
$chkRolesDefined.Text = "IT/OT Roles & Responsibilities Defined"
$chkRolesDefined.Location = New-Object System.Drawing.Point(15, 80)
$chkRolesDefined.AutoSize = $true
$chkRolesDefined.ForeColor = "#e0e0e0"
$grpGovernance.Controls.Add($chkRolesDefined)

$chkChangeManagement = New-Object System.Windows.Forms.CheckBox
$chkChangeManagement.Text = "Change Management Process Active"
$chkChangeManagement.Location = New-Object System.Drawing.Point(15, 105)
$chkChangeManagement.AutoSize = $true
$chkChangeManagement.ForeColor = "#e0e0e0"
$grpGovernance.Controls.Add($chkChangeManagement)

$chkRiskAssessment = New-Object System.Windows.Forms.CheckBox
$chkRiskAssessment.Text = "Regular IoT/OT Risk Assessments"
$chkRiskAssessment.Location = New-Object System.Drawing.Point(15, 130)
$chkRiskAssessment.AutoSize = $true
$chkRiskAssessment.ForeColor = "#e0e0e0"
$grpGovernance.Controls.Add($chkRiskAssessment)

# --- SECTION 4: Endpoint Hardening ---
$grpEndpoint = New-Object System.Windows.Forms.GroupBox
$grpEndpoint.Text = "Endpoint Hardening & Boot Security"
$grpEndpoint.Location = New-Object System.Drawing.Point(20, 380)
$grpEndpoint.Size = New-Object System.Drawing.Size(440, 130)
$grpEndpoint.ForeColor = "#e0e0e0"
$form.Controls.Add($grpEndpoint)

$chkSecureBoot = New-Object System.Windows.Forms.CheckBox
$chkSecureBoot.Text = "Secure Boot Enabled"
$chkSecureBoot.Location = New-Object System.Drawing.Point(15, 25)
$chkSecureBoot.AutoSize = $true
$chkSecureBoot.ForeColor = "#e0e0e0"
$grpEndpoint.Controls.Add($chkSecureBoot)

$chkSignedFW = New-Object System.Windows.Forms.CheckBox
$chkSignedFW.Text = "Firmware Signature Verification"
$chkSignedFW.Location = New-Object System.Drawing.Point(225, 25)
$chkSignedFW.AutoSize = $true
$chkSignedFW.ForeColor = "#e0e0e0"
$grpEndpoint.Controls.Add($chkSignedFW)

$chkClosedPorts = New-Object System.Windows.Forms.CheckBox
$chkClosedPorts.Text = "Unused Ports Disabled (TCP/UDP)"
$chkClosedPorts.Location = New-Object System.Drawing.Point(15, 50)
$chkClosedPorts.AutoSize = $true
$chkClosedPorts.ForeColor = "#e0e0e0"
$grpEndpoint.Controls.Add($chkClosedPorts)

$chkEndpointAV = New-Object System.Windows.Forms.CheckBox
$chkEndpointAV.Text = "Endpoint Malware Protection"
$chkEndpointAV.Location = New-Object System.Drawing.Point(225, 50)
$chkEndpointAV.AutoSize = $true
$chkEndpointAV.ForeColor = "#e0e0e0"
$grpEndpoint.Controls.Add($chkEndpointAV)

$chkPatchMgmt = New-Object System.Windows.Forms.CheckBox
$chkPatchMgmt.Text = "Patch Management Process"
$chkPatchMgmt.Location = New-Object System.Drawing.Point(15, 75)
$chkPatchMgmt.AutoSize = $true
$chkPatchMgmt.ForeColor = "#e0e0e0"
$grpEndpoint.Controls.Add($chkPatchMgmt)

$chkVulnScanning = New-Object System.Windows.Forms.CheckBox
$chkVulnScanning.Text = "Vulnerability Scanning Active"
$chkVulnScanning.Location = New-Object System.Drawing.Point(225, 75)
$chkVulnScanning.AutoSize = $true
$chkVulnScanning.ForeColor = "#e0e0e0"
$grpEndpoint.Controls.Add($chkVulnScanning)

$chkSecRecommendations = New-Object System.Windows.Forms.CheckBox
$chkSecRecommendations.Text = "Security Recommendations Tracked"
$chkSecRecommendations.Location = New-Object System.Drawing.Point(15, 100)
$chkSecRecommendations.AutoSize = $true
$chkSecRecommendations.ForeColor = "#e0e0e0"
$grpEndpoint.Controls.Add($chkSecRecommendations)

# --- SECTION 5: Network & Gateway ---
$grpNetwork = New-Object System.Windows.Forms.GroupBox
$grpNetwork.Text = "Network & Gateway Security"
$grpNetwork.Location = New-Object System.Drawing.Point(470, 380)
$grpNetwork.Size = New-Object System.Drawing.Size(450, 130)
$grpNetwork.ForeColor = "#e0e0e0"
$form.Controls.Add($grpNetwork)

$chkSWG = New-Object System.Windows.Forms.CheckBox
$chkSWG.Text = "Secure Web Gateway (SWG)"
$chkSWG.Location = New-Object System.Drawing.Point(15, 25)
$chkSWG.AutoSize = $true
$chkSWG.ForeColor = "#e0e0e0"
$grpNetwork.Controls.Add($chkSWG)

$chkSSLInspect = New-Object System.Windows.Forms.CheckBox
$chkSSLInspect.Text = "Deep SSL/TLS Inspection"
$chkSSLInspect.Location = New-Object System.Drawing.Point(235, 25)
$chkSSLInspect.AutoSize = $true
$chkSSLInspect.ForeColor = "#e0e0e0"
$grpNetwork.Controls.Add($chkSSLInspect)

$chkVPN = New-Object System.Windows.Forms.CheckBox
$chkVPN.Text = "VPN for Remote Access"
$chkVPN.Location = New-Object System.Drawing.Point(15, 50)
$chkVPN.AutoSize = $true
$chkVPN.ForeColor = "#e0e0e0"
$grpNetwork.Controls.Add($chkVPN)

$chkFirewall = New-Object System.Windows.Forms.CheckBox
$chkFirewall.Text = "Network Firewall Configured"
$chkFirewall.Location = New-Object System.Drawing.Point(235, 50)
$chkFirewall.AutoSize = $true
$chkFirewall.ForeColor = "#e0e0e0"
$grpNetwork.Controls.Add($chkFirewall)

$chkSegmentation = New-Object System.Windows.Forms.CheckBox
$chkSegmentation.Text = "Network Segmentation (IT/OT Isolation)"
$chkSegmentation.Location = New-Object System.Drawing.Point(15, 75)
$chkSegmentation.AutoSize = $true
$chkSegmentation.ForeColor = "#e0e0e0"
$grpNetwork.Controls.Add($chkSegmentation)

$chkIDS = New-Object System.Windows.Forms.CheckBox
$chkIDS.Text = "IDS/IPS System Active"
$chkIDS.Location = New-Object System.Drawing.Point(235, 75)
$chkIDS.AutoSize = $true
$chkIDS.ForeColor = "#e0e0e0"
$grpNetwork.Controls.Add($chkIDS)

$chkAdvancedHunting = New-Object System.Windows.Forms.CheckBox
$chkAdvancedHunting.Text = "Advanced Threat Hunting Enabled"
$chkAdvancedHunting.Location = New-Object System.Drawing.Point(15, 100)
$chkAdvancedHunting.AutoSize = $true
$chkAdvancedHunting.ForeColor = "#e0e0e0"
$grpNetwork.Controls.Add($chkAdvancedHunting)

# --- SECTION 6: Data Protection ---
$grpData = New-Object System.Windows.Forms.GroupBox
$grpData.Text = "Data Protection & Encryption"
$grpData.Location = New-Object System.Drawing.Point(20, 520)
$grpData.Size = New-Object System.Drawing.Size(900, 80)
$grpData.ForeColor = "#e0e0e0"
$form.Controls.Add($grpData)

$lblTransport = New-Object System.Windows.Forms.Label
$lblTransport.Text = "Transport Protocol:"
$lblTransport.Location = New-Object System.Drawing.Point(15, 25)
$lblTransport.AutoSize = $true
$lblTransport.ForeColor = "#e0e0e0"
$grpData.Controls.Add($lblTransport)

$cmbTransport = New-Object System.Windows.Forms.ComboBox
$cmbTransport.Location = New-Object System.Drawing.Point(130, 22)
$cmbTransport.Width = 200
$cmbTransport.DropDownStyle = "DropDownList"
$cmbTransport.Items.AddRange(@("HTTP (Plaintext)", "MQTT (No TLS)", "HTTPS (TLS 1.2)", "HTTPS (TLS 1.3)", "MQTTS (TLS 1.3)"))
$cmbTransport.SelectedIndex = 0
$grpData.Controls.Add($cmbTransport)

$chkDataAtRest = New-Object System.Windows.Forms.CheckBox
$chkDataAtRest.Text = "Data at Rest Encrypted (AES-256)"
$chkDataAtRest.Location = New-Object System.Drawing.Point(15, 52)
$chkDataAtRest.AutoSize = $true
$chkDataAtRest.ForeColor = "#e0e0e0"
$grpData.Controls.Add($chkDataAtRest)

$chkAsymmetric = New-Object System.Windows.Forms.CheckBox
$chkAsymmetric.Text = "PKI/Certificate-Based Auth"
$chkAsymmetric.Location = New-Object System.Drawing.Point(350, 25)
$chkAsymmetric.AutoSize = $true
$chkAsymmetric.ForeColor = "#e0e0e0"
$grpData.Controls.Add($chkAsymmetric)

$chkStorageProtect = New-Object System.Windows.Forms.CheckBox
$chkStorageProtect.Text = "Secure Storage with Monitoring"
$chkStorageProtect.Location = New-Object System.Drawing.Point(350, 52)
$chkStorageProtect.AutoSize = $true
$chkStorageProtect.ForeColor = "#e0e0e0"
$grpData.Controls.Add($chkStorageProtect)

$chkDataClassification = New-Object System.Windows.Forms.CheckBox
$chkDataClassification.Text = "Data Classification Policy"
$chkDataClassification.Location = New-Object System.Drawing.Point(590, 25)
$chkDataClassification.AutoSize = $true
$chkDataClassification.ForeColor = "#e0e0e0"
$grpData.Controls.Add($chkDataClassification)

# --- SECTION 7: Access Control & Authentication ---
$grpAuth = New-Object System.Windows.Forms.GroupBox
$grpAuth.Text = "Access Control & Authentication"
$grpAuth.Location = New-Object System.Drawing.Point(20, 610)
$grpAuth.Size = New-Object System.Drawing.Size(900, 80)
$grpAuth.ForeColor = "#e0e0e0"
$form.Controls.Add($grpAuth)

$lblAPI = New-Object System.Windows.Forms.Label
$lblAPI.Text = "API Authentication:"
$lblAPI.Location = New-Object System.Drawing.Point(15, 25)
$lblAPI.AutoSize = $true
$lblAPI.ForeColor = "#e0e0e0"
$grpAuth.Controls.Add($lblAPI)

$cmbAPI = New-Object System.Windows.Forms.ComboBox
$cmbAPI.Location = New-Object System.Drawing.Point(130, 22)
$cmbAPI.Width = 180
$cmbAPI.DropDownStyle = "DropDownList"
$cmbAPI.Items.AddRange(@("None/Public", "Basic Auth", "API Keys", "OAuth 2.0/Tokens", "Certificate-Based"))
$cmbAPI.SelectedIndex = 0
$grpAuth.Controls.Add($cmbAPI)

$chkMFA = New-Object System.Windows.Forms.CheckBox
$chkMFA.Text = "Multi-Factor Authentication"
$chkMFA.Location = New-Object System.Drawing.Point(335, 25)
$chkMFA.AutoSize = $true
$chkMFA.ForeColor = "#e0e0e0"
$grpAuth.Controls.Add($chkMFA)

$chkDefaultCreds = New-Object System.Windows.Forms.CheckBox
$chkDefaultCreds.Text = "Default Credentials Changed"
$chkDefaultCreds.Location = New-Object System.Drawing.Point(15, 50)
$chkDefaultCreds.AutoSize = $true
$chkDefaultCreds.ForeColor = "#e0e0e0"
$grpAuth.Controls.Add($chkDefaultCreds)

$chkRBAC = New-Object System.Windows.Forms.CheckBox
$chkRBAC.Text = "Role-Based Access Control (RBAC)"
$chkRBAC.Location = New-Object System.Drawing.Point(335, 50)
$chkRBAC.AutoSize = $true
$chkRBAC.ForeColor = "#e0e0e0"
$grpAuth.Controls.Add($chkRBAC)

$chkAccessLogs = New-Object System.Windows.Forms.CheckBox
$chkAccessLogs.Text = "Access Logs & Audit Trail"
$chkAccessLogs.Location = New-Object System.Drawing.Point(590, 25)
$chkAccessLogs.AutoSize = $true
$chkAccessLogs.ForeColor = "#e0e0e0"
$grpAuth.Controls.Add($chkAccessLogs)

$chkIdentityManagement = New-Object System.Windows.Forms.CheckBox
$chkIdentityManagement.Text = "Device Identity Management"
$chkIdentityManagement.Location = New-Object System.Drawing.Point(590, 50)
$chkIdentityManagement.AutoSize = $true
$chkIdentityManagement.ForeColor = "#e0e0e0"
$grpAuth.Controls.Add($chkIdentityManagement)

# --- Action Buttons ---
$btnAudit = New-Object System.Windows.Forms.Button
$btnAudit.Text = "RUN COMPREHENSIVE IOT/OT SECURITY AUDIT"
$btnAudit.Location = New-Object System.Drawing.Point(20, 700)
$btnAudit.Size = New-Object System.Drawing.Size(680, 45)
$btnAudit.BackColor = "#00d9ff"
$btnAudit.ForeColor = "#000000"
$btnAudit.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$btnAudit.FlatStyle = "Flat"
$form.Controls.Add($btnAudit)

$btnExport = New-Object System.Windows.Forms.Button
$btnExport.Text = "EXPORT REPORT"
$btnExport.Location = New-Object System.Drawing.Point(710, 700)
$btnExport.Size = New-Object System.Drawing.Size(210, 45)
$btnExport.BackColor = "#404040"
$btnExport.ForeColor = "#e0e0e0"
$btnExport.Font = $labelFont
$btnExport.FlatStyle = "Flat"
$btnExport.Enabled = $false
$form.Controls.Add($btnExport)

# --- Output Box ---
$txtOutput = New-Object System.Windows.Forms.TextBox
$txtOutput.Multiline = $true
$txtOutput.ScrollBars = "Vertical"
$txtOutput.Location = New-Object System.Drawing.Point(20, 755)
$txtOutput.Size = New-Object System.Drawing.Size(900, 105)
$txtOutput.Font = $consFont
$txtOutput.ReadOnly = $true
$txtOutput.BackColor = "#1a1a1a"
$txtOutput.ForeColor = "#00ff00"
$form.Controls.Add($txtOutput)

# --- Global Report Storage ---
$global:auditReport = ""

# --- Audit Logic ---
$btnAudit.Add_Click({
    $score = 0
    $maxScore = 100
    $criticalIssues = @()
    $warnings = @()
    $passes = @()
    
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("=" * 110)
    [void]$sb.AppendLine("IOT/OT ENTERPRISE SECURITY AUDIT REPORT - MICROSOFT DEFENDER FOR IOT ALIGNMENT")
    [void]$sb.AppendLine("=" * 110)
    [void]$sb.AppendLine("Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    [void]$sb.AppendLine("Device: $($txtDevName.Text)")
    [void]$sb.AppendLine("Type: $($cmbDevType.SelectedItem)")
    [void]$sb.AppendLine("Asset ID: $($txtAssetID.Text)")
    [void]$sb.AppendLine("Network Location: $($txtLocation.Text)")
    [void]$sb.AppendLine("Defender License: $($cmbDefenderLicense.SelectedItem)")
    [void]$sb.AppendLine("Governance Framework: $($cmbFramework.SelectedItem)")
    [void]$sb.AppendLine("-" * 110)
    
    # Microsoft Defender for IoT Integration (15 points)
    [void]$sb.AppendLine("`n[MICROSOFT DEFENDER FOR IOT INTEGRATION]")
    $defenderLicense = $cmbDefenderLicense.SelectedItem
    
    if ($defenderLicense -eq "E5/E5 Security") {
        $score += 7
        $passes += "E5 license active - includes MDE P2 + Enterprise IoT add-on (5 devices per user)"
    } elseif ($defenderLicense -eq "Enterprise IoT Add-on") {
        $score += 6
        $passes += "Enterprise IoT add-on license - full VM and security recommendations"
    } elseif ($defenderLicense -eq "MDE P2") {
        $score += 4
        $passes += "Microsoft Defender for Endpoint P2 - basic discovery and threat detection"
    } else {
        $criticalIssues += "CRITICAL: No Defender for IoT licensing - missing threat detection and device discovery"
    }
    
    if ($chkDefenderMonitored.Checked) {
        $score += 4
        $passes += "Device monitored by Defender for Endpoint agent - active threat detection"
    } else {
        $warnings += "WARNING: Device not monitored by MDE agent - limited visibility"
    }
    
    if ($chkDefenderIoT.Checked) {
        $score += 4
        $passes += "Device monitored by Defender for IoT - OT-specific threat protection"
    } else {
        if ($cmbDevType.SelectedItem -match "OT") {
            $criticalIssues += "CRITICAL: OT device not monitored by Defender for IoT - missing OT threat detection"
        }
    }
    
    # Asset Discovery & Visibility (10 points)
    [void]$sb.AppendLine("`n[ASSET DISCOVERY & VISIBILITY]")
    if ($chkAutoDiscovery.Checked) {
        $score += 4
        $passes += "Automated network discovery enabled - real-time device inventory"
    } else {
        $warnings += "WARNING: Manual asset tracking - risk of unmanaged devices and blind spots"
    }
    
    if ($chkVisibility.Checked) {
        $score += 3
        $passes += "Full device visibility achieved - no blind spots on network"
    } else {
        $criticalIssues += "CRITICAL: Lack of visibility into unmanaged devices - increased attack surface"
    }
    
    if ($txtAssetID.Text -ne "") {
        $score += 3
        $passes += "Device registered in CMDB with Asset ID: $($txtAssetID.Text)"
    } else {
        $warnings += "WARNING: Device not in CMDB - asset lifecycle not tracked"
    }
    
    # Enterprise IoT Security Challenges (10 points)
    [void]$sb.AppendLine("`n[ENTERPRISE IOT/OT SECURITY CHALLENGES ADDRESSED]")
    if ($chkDeviceAuth.Checked) {
        $score += 3
        $passes += "Strong device authentication beyond passwords implemented"
    } else {
        $criticalIssues += "CRITICAL: Weak device authentication - password-based models insufficient for IoT"
    }
    
    if ($chkDataEncryption.Checked) {
        $score += 2
        $passes += "Comprehensive data encryption protecting sensitive IoT data"
    } else {
        $criticalIssues += "CRITICAL: Insufficient data encryption - large amounts of sensitive data at risk"
    }
    
    if ($chkBuiltInSecurity.Checked) {
        $score += 3
        $passes += "Device has built-in security controls - not a legacy device"
    } else {
        $warnings += "WARNING: Lack of built-in security - legacy device vulnerable to attacks"
    }
    
    if ($chkComputeCapacity.Checked) {
        $score += 2
        $passes += "Adequate computational capacity for security measures"
    } else {
        $warnings += "WARNING: Limited compute capacity - difficult to implement encryption/authentication"
    }
    
    # IT Governance & Policy (8 points)
    [void]$sb.AppendLine("`n[IT GOVERNANCE & POLICY FRAMEWORK]")
    $framework = $cmbFramework.SelectedItem
    if ($framework -match "IEC 62443") {
        $score += 3
        $passes += "IEC 62443 OT security framework implemented - industry best practice"
    } elseif ($framework -ne "None") {
        $score += 2
        $passes += "Governance framework implemented: $framework"
    } else {
        $warnings += "WARNING: No formal governance framework for IoT/OT security"
    }
    
    if ($chkPolicyDoc.Checked) {
        $score += 2
        $passes += "IoT/OT security policies documented"
    } else {
        $warnings += "WARNING: IoT/OT security policies not documented"
    }
    
    if ($chkRolesDefined.Checked) {
        $score += 1
        $passes += "IT/OT roles and responsibilities defined"
    }
    
    if ($chkChangeManagement.Checked) {
        $score += 1
        $passes += "Change management process active"
    }
    
    if ($chkRiskAssessment.Checked) {
        $score += 1
        $passes += "Regular IoT/OT risk assessments conducted"
    } else {
        $warnings += "WARNING: No regular risk assessments - evolving threats not tracked"
    }
    
    # Endpoint Hardening & Vulnerability Management (12 points)
    [void]$sb.AppendLine("`n[ENDPOINT HARDENING & VULNERABILITY MANAGEMENT]")
    if ($chkSecureBoot.Checked) {
        $score += 3
        $passes += "Secure Boot enabled - root of trust established"
    } else {
        $criticalIssues += "CRITICAL: Secure Boot disabled - vulnerable to bootkit attacks"
    }
    
    if ($chkSignedFW.Checked) {
        $score += 3
        $passes += "Firmware signature verification active"
    } else {
        $criticalIssues += "CRITICAL: Unsigned firmware accepted - backdoor injection risk"
    }
    
    if ($chkClosedPorts.Checked) {
        $score += 1
        $passes += "Unused network ports disabled"
    }
    
    if ($chkEndpointAV.Checked) {
        $score += 1
        $passes += "Endpoint malware protection active"
    }
    
    if ($chkPatchMgmt.Checked) {
        $score += 2
        $passes += "Patch management process active - vulnerabilities addressed promptly"
    } else {
        $criticalIssues += "CRITICAL: No patch management - known vulnerabilities unaddressed"
    }
    
    if ($chkVulnScanning.Checked) {
        $score += 1
        $passes += "Vulnerability scanning active - proactive threat detection"
    } else {
        $warnings += "WARNING: No vulnerability scanning - unknown security gaps"
    }
    
    if ($chkSecRecommendations.Checked) {
        $score += 1
        $passes += "Security recommendations tracked and remediated (Defender portal integration)"
    } else {
        $warnings += "WARNING: Security recommendations not tracked - missing optimization opportunities"
    }
    
    # Network & Gateway Security (12 points)
    [void]$sb.AppendLine("`n[NETWORK & GATEWAY SECURITY]")
    if ($chkSWG.Checked) {
        $score += 2
        $passes += "Secure Web Gateway filtering traffic"
    }
    
    if ($chkSSLInspect.Checked) {
        $score += 1
        $passes += "Deep SSL/TLS inspection enabled"
    }
    
    if ($chkVPN.Checked) {
        $score += 1
        $passes += "VPN configured for remote access"
    }
    
    if ($chkFirewall.Checked) {
        $score += 2
        $passes += "Network firewall properly configured"
    } else {
        $criticalIssues += "CRITICAL: No network firewall configured"
    }
    
    if ($chkSegmentation.Checked) {
        $score += 3
        $passes += "Network segmentation with IT/OT isolation - critical for OT security"
    } else {
        if ($cmbDevType.SelectedItem -match "OT") {
            $criticalIssues += "CRITICAL: OT device on flat network - no IT/OT segmentation"
        } else {
            $warnings += "WARNING: No network segmentation - lateral movement risk"
        }
    }
    
    if ($chkIDS.Checked) {
        $score += 2
        $passes += "IDS/IPS system monitoring network activity"
    } else {
        $warnings += "WARNING: No IDS/IPS - attacks may go undetected"
    }
    
    if ($chkAdvancedHunting.Checked) {
        $score += 1
        $passes += "Advanced threat hunting enabled - proactive threat detection"
    }
    
    # Data Protection & Encryption (10 points)
    [void]$sb.AppendLine("`n[DATA PROTECTION & ENCRYPTION]")
    $transport = $cmbTransport.SelectedItem
    if ($transport -match "TLS 1.3") {
        $score += 5
        $passes += "Strong transport encryption (TLS 1.3)"
    } elseif ($transport -match "TLS 1.2") {
        $score += 3
        $warnings += "WARNING: TLS 1.2 acceptable but TLS 1.3 recommended"
    } else {
        $criticalIssues += "CRITICAL: Unencrypted transport - data vulnerable to interception"
    }
    
    if ($chkDataAtRest.Checked) {
        $score += 3
        $passes += "Data at rest encrypted (AES-256)"
    } else {
        $criticalIssues += "CRITICAL: Unencrypted storage - physical theft exposes data"
    }
    
    if ($chkAsymmetric.Checked) {
        $score += 1
        $passes += "PKI/Certificate-based authentication"
    }
    
    if ($chkStorageProtect.Checked) {
        $score += 1
        $passes += "Secure storage with monitoring"
    }
    
    if ($chkDataClassification.Checked) {
        $score += 1
        $passes += "Data classification policy implemented"
    }
    
    # Authentication & Access Control (13 points)
    [void]$sb.AppendLine("`n[ACCESS CONTROL & AUTHENTICATION]")
    $apiAuth = $cmbAPI.SelectedItem
    if ($apiAuth -match "Certificate|OAuth") {
        $score += 5
        $passes += "Strong API authentication: $apiAuth"
    } elseif ($apiAuth -match "API Keys") {
        $score += 3
        $warnings += "WARNING: API keys acceptable but certificate-based recommended"
    } elseif ($apiAuth -match "Basic") {
        $score += 1
        $warnings += "WARNING: Basic authentication weak"
    } else {
        $criticalIssues += "CRITICAL: No API authentication - public access vulnerability"
    }
    
    if ($chkMFA.Checked) {
        $score += 3
        $passes += "Multi-factor authentication enabled"
    } else {
        $warnings += "WARNING: MFA not enabled - single point of failure"
    }
    
    if ($chkDefaultCreds.Checked) {
        $score += 2
        $passes += "Default credentials changed"
    } else {
        $criticalIssues += "CRITICAL: Default credentials active - IMMEDIATE BOTNET RISK"
        $score -= 15
    }
    
    if ($chkRBAC.Checked) {
        $score += 1
        $passes += "Role-Based Access Control implemented"
    }
    
    if ($chkAccessLogs.Checked) {
        $score += 1
        $passes += "Access logs and audit trail maintained"
    }
    
    if ($chkIdentityManagement.Checked) {
        $score += 1
        $passes += "Device identity management implemented - addresses IoT authentication challenges"
    } else {
        $warnings += "WARNING: No device identity management - complex IoT authentication not addressed"
    }
    
    # Calculate final score
    $score = [Math]::Max(0, $score)
    $percentage = [Math]::Round(($score / $maxScore) * 100, 1)
    
    # Generate Report Sections
    if ($criticalIssues.Count -gt 0) {
        [void]$sb.AppendLine("`n[CRITICAL ISSUES - IMMEDIATE ACTION REQUIRED]")
        foreach ($issue in $criticalIssues) {
            [void]$sb.AppendLine("  [X] $issue")
        }
    }
    
    if ($warnings.Count -gt 0) {
        [void]$sb.AppendLine("`n[WARNINGS - REMEDIATION RECOMMENDED]")
        foreach ($warn in $warnings) {
            [void]$sb.AppendLine("  [!] $warn")
        }
    }
    
    if ($passes.Count -gt 0) {
        [void]$sb.AppendLine("`n[PASSED SECURITY CONTROLS]")
        foreach ($pass in $passes) {
            [void]$sb.AppendLine("  [+] $pass")
        }
    }
    
    # Final Assessment
    [void]$sb.AppendLine("`n" + "=" * 110)
    [void]$sb.AppendLine("ENTERPRISE IOT/OT SECURITY SCORE: $score / $maxScore ($percentage%)")
    [void]$sb.AppendLine("Critical Issues: $($criticalIssues.Count) | Warnings: $($warnings.Count) | Passed Controls: $($passes.Count)")
    
    if ($score -ge 85) {
        [void]$sb.AppendLine("RISK LEVEL: LOW")
        [void]$sb.AppendLine("COMPLIANCE STATUS: COMPLIANT")
        [void]$sb.AppendLine("RECOMMENDATION: Device meets enterprise IoT/OT security standards - approved for deployment")
        [void]$sb.AppendLine("NEXT STEPS: Continue Defender monitoring, conduct quarterly recertification")
        $txtOutput.ForeColor = "#00ff00"
    } elseif ($score -ge 70) {
        [void]$sb.AppendLine("RISK LEVEL: MEDIUM")
        [void]$sb.AppendLine("COMPLIANCE STATUS: PARTIALLY COMPLIANT")
        [void]$sb.AppendLine("RECOMMENDATION: Security gaps present - remediation required before production")
        [void]$sb.AppendLine("NEXT STEPS: Enable Defender for IoT, address warnings within 30 days")
        $txtOutput.ForeColor = "#ffaa00"
    } elseif ($score -ge 50) {
        [void]$sb.AppendLine("RISK LEVEL: HIGH")
        [void]$sb.AppendLine("COMPLIANCE STATUS: NON-COMPLIANT")
        [void]$sb.AppendLine("RECOMMENDATION: Significant vulnerabilities - immediate remediation required")
        [void]$sb.AppendLine("NEXT STEPS: Deploy Defender agents, implement segmentation, address critical issues")
        $txtOutput.ForeColor = "#ff6600"
    } else {
        [void]$sb.AppendLine("RISK LEVEL: CRITICAL")
        [void]$sb.AppendLine("COMPLIANCE STATUS: NON-COMPLIANT")
        [void]$sb.AppendLine("RECOMMENDATION: Device MUST NOT be deployed - severe security deficiencies")
        [void]$sb.AppendLine("NEXT STEPS: Complete security overhaul, enable Defender protection, executive review")
        $txtOutput.ForeColor = "#ff0000"
    }
    
    [void]$sb.AppendLine("`nMICROSOFT DEFENDER FOR IOT INTEGRATION STATUS:")
    [void]$sb.AppendLine("  License Type: $defenderLicense")
    [void]$sb.AppendLine("  MDE Agent: $(if($chkDefenderMonitored.Checked){'ACTIVE'}else{'NOT DEPLOYED'})")
    [void]$sb.AppendLine("  Defender for IoT: $(if($chkDefenderIoT.Checked){'ACTIVE'}else{'NOT DEPLOYED'})")
    [void]$sb.AppendLine("  Device Discovery: $(if($chkAutoDiscovery.Checked){'ENABLED'}else{'MANUAL ONLY'})")
    [void]$sb.AppendLine("  Threat Detection: $(if($chkDefenderMonitored.Checked -or $chkDefenderIoT.Checked){'ACTIVE'}else{'DISABLED'})")
    [void]$sb.AppendLine("  Vulnerability Management: $(if($chkVulnScanning.Checked){'ACTIVE'}else{'DISABLED'})")
    [void]$sb.AppendLine("  Security Recommendations: $(if($chkSecRecommendations.Checked){'TRACKED'}else{'NOT TRACKED'})")
    
    [void]$sb.AppendLine("`nKEY DEFENDER FOR IOT CAPABILITIES AVAILABLE:")
    if ($defenderLicense -match "E5|Enterprise IoT") {
        [void]$sb.AppendLine("  • Full enterprise IoT inventory in Assets > Devices > IoT devices")
        [void]$sb.AppendLine("  • IoT-specific alerts and threat detection")
        [void]$sb.AppendLine("  • Security recommendations for IoT assets")
        [void]$sb.AppendLine("  • Vulnerability discovery and tracking")
        [void]$sb.AppendLine("  • Advanced hunting queries for custom alert rules")
        [void]$sb.AppendLine("  • Integration with Microsoft 365 Defender portal")
    } elseif ($defenderLicense -eq "MDE P2") {
        [void]$sb.AppendLine("  • Basic device discovery")
        [void]$sb.AppendLine("  • Threat detection for managed/unmanaged devices")
        [void]$sb.AppendLine("  UPGRADE RECOMMENDED: Enable Enterprise IoT add-on for full capabilities")
    } else {
        [void]$sb.AppendLine("  NO DEFENDER PROTECTION - Device vulnerable to:")
        [void]$sb.AppendLine("    • Undetected IoT-specific attacks")
        [void]$sb.AppendLine("    • Missing from device inventory")
        [void]$sb.AppendLine("    • No vulnerability assessment")
        [void]$sb.AppendLine("    • No security recommendations")
    }
    
    [void]$sb.AppendLine("`nRECOMMENDED ACTIONS:")
    if ($defenderLicense -eq "None") {
        [void]$sb.AppendLine("  1. URGENT: Enable Microsoft Defender for Endpoint P2 or E5 licensing")
        [void]$sb.AppendLine("  2. Deploy Defender for Endpoint agent to monitor this device")
    }
    if (!$chkDefenderIoT.Checked -and $cmbDevType.SelectedItem -match "OT") {
        [void]$sb.AppendLine("  3. Deploy Defender for IoT sensor for OT network monitoring")
    }
    if (!$chkSegmentation.Checked) {
        [void]$sb.AppendLine("  4. Implement network segmentation to isolate IT/OT environments")
    }
    if ($criticalIssues.Count -gt 0) {
        [void]$sb.AppendLine("  5. Address all $($criticalIssues.Count) critical issues immediately")
    }
    if (!$chkSecRecommendations.Checked) {
        [void]$sb.AppendLine("  6. Review security recommendations in Defender portal")
    }
    
    [void]$sb.AppendLine("`n" + "=" * 110)
    [void]$sb.AppendLine("AUDIT METHODOLOGY: Enterprise IoT/OT Security Assessment")
    [void]$sb.AppendLine("ALIGNMENT: Microsoft Defender for IoT, IEC 62443, NIST CSF, ISO 27001")
    [void]$sb.AppendLine("COVERAGE: Defender Integration, Asset Discovery, IoT Challenges, Governance, Endpoints,")
    [void]$sb.AppendLine("          Network Security, Data Protection, Access Control, Vulnerability Management")
    [void]$sb.AppendLine("=" * 110)
    [void]$sb.AppendLine("End of Report - Generated by IoT/OT Security Auditor v3.0")
    [void]$sb.AppendLine("For Defender for IoT guidance, visit: https://learn.microsoft.com/defender-iot")
    [void]$sb.AppendLine("=" * 110)
    
    $global:auditReport = $sb.ToString()
    $txtOutput.Text = $global:auditReport
    $btnExport.Enabled = $true
    $btnExport.BackColor = "#00d9ff"
    $btnExport.ForeColor = "#000000"
})

# --- Export Logic ---
$btnExport.Add_Click({
    $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveDialog.Filter = "Text Files (*.txt)|*.txt|All Files (*.*)|*.*"
    $saveDialog.FileName = "IoT_OT_Security_Audit_$($txtDevName.Text -replace '[^a-zA-Z0-9]', '_')_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    $saveDialog.Title = "Export Enterprise IoT/OT Security Audit Report"
    
    if ($saveDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        try {
            $global:auditReport | Out-File -FilePath $saveDialog.FileName -Encoding UTF8
            [System.Windows.Forms.MessageBox]::Show(
                "Enterprise IoT/OT audit report successfully exported to:`n$($saveDialog.FileName)`n`nThis report can be shared with security teams and stakeholders for remediation planning.",
                "Export Successful",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            )
        } catch {
            [System.Windows.Forms.MessageBox]::Show(
                "Error exporting report: $($_.Exception.Message)",
                "Export Failed",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
        }
    }
})

# --- Show Form ---
[void]$form.ShowDialog()
