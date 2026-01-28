<#
.SYNOPSIS
    IoT Device Security Auditor - Professional Edition v2.0
.DESCRIPTION
    A comprehensive security assessment tool for IoT device configurations.
    Evaluates endpoint hardening, network security, encryption, compliance, and governance.
    Enhanced with IT audit best practices including asset discovery, CMDB integration,
    disaster recovery, and regulatory compliance tracking.
.NOTES
    Author: Gareth Sheldon
    Version: 2.0
    Updated: 2026-01-28
    Compliance: GDPR, HIPAA, ISO 27001, PCI-DSS
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# --- Form Setup ---
$form = New-Object System.Windows.Forms.Form
$form.Text = "IoT Security Auditor - Professional v2.0"
$form.Size = New-Object System.Drawing.Size(900, 850)
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
$pnlHeader.Size = New-Object System.Drawing.Size(900, 60)
$pnlHeader.BackColor = "#1a1a1a"
$form.Controls.Add($pnlHeader)

$lblHeader = New-Object System.Windows.Forms.Label
$lblHeader.Text = "IOT DEVICE SECURITY ASSESSMENT v2.0"
$lblHeader.Location = New-Object System.Drawing.Point(20, 18)
$lblHeader.AutoSize = $true
$lblHeader.Font = $headerFont
$lblHeader.ForeColor = "#00d9ff"
$pnlHeader.Controls.Add($lblHeader)

# --- SECTION 1: Device Information & Asset Management ---
$grpDevice = New-Object System.Windows.Forms.GroupBox
$grpDevice.Text = "Device Information & Asset Discovery"
$grpDevice.Location = New-Object System.Drawing.Point(20, 75)
$grpDevice.Size = New-Object System.Drawing.Size(850, 95)
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
$cmbDevType.Items.AddRange(@("Smart Sensor", "Gateway Device", "Camera/Surveillance", "Industrial Controller", "Smart Appliance", "Medical Device", "Other"))
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
$lblLocation.Text = "Location:"
$lblLocation.Location = New-Object System.Drawing.Point(320, 55)
$lblLocation.AutoSize = $true
$lblLocation.ForeColor = "#e0e0e0"
$grpDevice.Controls.Add($lblLocation)

$txtLocation = New-Object System.Windows.Forms.TextBox
$txtLocation.Location = New-Object System.Drawing.Point(405, 52)
$txtLocation.Width = 200
$grpDevice.Controls.Add($txtLocation)

$chkAutoDiscovery = New-Object System.Windows.Forms.CheckBox
$chkAutoDiscovery.Text = "Automated Asset Discovery Enabled"
$chkAutoDiscovery.Location = New-Object System.Drawing.Point(625, 25)
$chkAutoDiscovery.AutoSize = $true
$chkAutoDiscovery.ForeColor = "#e0e0e0"
$grpDevice.Controls.Add($chkAutoDiscovery)

# --- SECTION 2: IT Governance & Leadership ---
$grpGovernance = New-Object System.Windows.Forms.GroupBox
$grpGovernance.Text = "IT Governance & Policy Framework"
$grpGovernance.Location = New-Object System.Drawing.Point(20, 180)
$grpGovernance.Size = New-Object System.Drawing.Size(420, 105)
$grpGovernance.ForeColor = "#e0e0e0"
$form.Controls.Add($grpGovernance)

$lblFramework = New-Object System.Windows.Forms.Label
$lblFramework.Text = "Governance Framework:"
$lblFramework.Location = New-Object System.Drawing.Point(15, 25)
$lblFramework.AutoSize = $true
$lblFramework.ForeColor = "#e0e0e0"
$grpGovernance.Controls.Add($lblFramework)

$cmbFramework = New-Object System.Windows.Forms.ComboBox
$cmbFramework.Location = New-Object System.Drawing.Point(150, 22)
$cmbFramework.Width = 240
$cmbFramework.DropDownStyle = "DropDownList"
$cmbFramework.Items.AddRange(@("None", "COBIT", "ITIL", "NIST CSF", "ISO/IEC 27001", "Custom Framework"))
$cmbFramework.SelectedIndex = 0
$grpGovernance.Controls.Add($cmbFramework)

$chkPolicyDoc = New-Object System.Windows.Forms.CheckBox
$chkPolicyDoc.Text = "Security Policies Documented"
$chkPolicyDoc.Location = New-Object System.Drawing.Point(15, 50)
$chkPolicyDoc.AutoSize = $true
$chkPolicyDoc.ForeColor = "#e0e0e0"
$grpGovernance.Controls.Add($chkPolicyDoc)

$chkRolesDefined = New-Object System.Windows.Forms.CheckBox
$chkRolesDefined.Text = "IT Roles & Responsibilities Defined"
$chkRolesDefined.Location = New-Object System.Drawing.Point(15, 75)
$chkRolesDefined.AutoSize = $true
$chkRolesDefined.ForeColor = "#e0e0e0"
$grpGovernance.Controls.Add($chkRolesDefined)

# --- SECTION 3: Endpoint Hardening ---
$grpEndpoint = New-Object System.Windows.Forms.GroupBox
$grpEndpoint.Text = "Endpoint Hardening & Boot Security"
$grpEndpoint.Location = New-Object System.Drawing.Point(450, 180)
$grpEndpoint.Size = New-Object System.Drawing.Size(420, 105)
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
$chkSignedFW.Location = New-Object System.Drawing.Point(15, 50)
$chkSignedFW.AutoSize = $true
$chkSignedFW.ForeColor = "#e0e0e0"
$grpEndpoint.Controls.Add($chkSignedFW)

$chkClosedPorts = New-Object System.Windows.Forms.CheckBox
$chkClosedPorts.Text = "Unused Ports Disabled (TCP/UDP)"
$chkClosedPorts.Location = New-Object System.Drawing.Point(225, 25)
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
$chkPatchMgmt.Text = "Patch Management Process Active"
$chkPatchMgmt.Location = New-Object System.Drawing.Point(15, 75)
$chkPatchMgmt.AutoSize = $true
$chkPatchMgmt.ForeColor = "#e0e0e0"
$grpEndpoint.Controls.Add($chkPatchMgmt)

# --- SECTION 4: Network & Gateway ---
$grpNetwork = New-Object System.Windows.Forms.GroupBox
$grpNetwork.Text = "Network & Gateway Security"
$grpNetwork.Location = New-Object System.Drawing.Point(20, 295)
$grpNetwork.Size = New-Object System.Drawing.Size(420, 130)
$grpNetwork.ForeColor = "#e0e0e0"
$form.Controls.Add($grpNetwork)

$chkSWG = New-Object System.Windows.Forms.CheckBox
$chkSWG.Text = "Secure Web Gateway (SWG)"
$chkSWG.Location = New-Object System.Drawing.Point(15, 25)
$chkSWG.AutoSize = $true
$chkSWG.ForeColor = "#e0e0e0"
$grpNetwork.Controls.Add($chkSWG)

$chkSSLInspect = New-Object System.Windows.Forms.CheckBox
$chkSSLInspect.Text = "Deep HTTPS/SSL Inspection"
$chkSSLInspect.Location = New-Object System.Drawing.Point(15, 50)
$chkSSLInspect.AutoSize = $true
$chkSSLInspect.ForeColor = "#e0e0e0"
$grpNetwork.Controls.Add($chkSSLInspect)

$chkVPN = New-Object System.Windows.Forms.CheckBox
$chkVPN.Text = "VPN for Remote Access"
$chkVPN.Location = New-Object System.Drawing.Point(15, 75)
$chkVPN.AutoSize = $true
$chkVPN.ForeColor = "#e0e0e0"
$grpNetwork.Controls.Add($chkVPN)

$chkFirewall = New-Object System.Windows.Forms.CheckBox
$chkFirewall.Text = "Network Firewall Configured"
$chkFirewall.Location = New-Object System.Drawing.Point(15, 100)
$chkFirewall.AutoSize = $true
$chkFirewall.ForeColor = "#e0e0e0"
$grpNetwork.Controls.Add($chkFirewall)

$chkSegmentation = New-Object System.Windows.Forms.CheckBox
$chkSegmentation.Text = "Network Segmentation/VLANs"
$chkSegmentation.Location = New-Object System.Drawing.Point(225, 25)
$chkSegmentation.AutoSize = $true
$chkSegmentation.ForeColor = "#e0e0e0"
$grpNetwork.Controls.Add($chkSegmentation)

$chkIDS = New-Object System.Windows.Forms.CheckBox
$chkIDS.Text = "Intrusion Detection System (IDS)"
$chkIDS.Location = New-Object System.Drawing.Point(225, 50)
$chkIDS.AutoSize = $true
$chkIDS.ForeColor = "#e0e0e0"
$grpNetwork.Controls.Add($chkIDS)

# --- SECTION 5: Data Protection ---
$grpData = New-Object System.Windows.Forms.GroupBox
$grpData.Text = "Data Protection & Encryption"
$grpData.Location = New-Object System.Drawing.Point(450, 295)
$grpData.Size = New-Object System.Drawing.Size(420, 130)
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
$cmbTransport.Width = 250
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
$chkAsymmetric.Text = "Asymmetric Key Exchange (PKI)"
$chkAsymmetric.Location = New-Object System.Drawing.Point(15, 77)
$chkAsymmetric.AutoSize = $true
$chkAsymmetric.ForeColor = "#e0e0e0"
$grpData.Controls.Add($chkAsymmetric)

$chkStorageProtect = New-Object System.Windows.Forms.CheckBox
$chkStorageProtect.Text = "Secure Storage with Monitoring"
$chkStorageProtect.Location = New-Object System.Drawing.Point(15, 102)
$chkStorageProtect.AutoSize = $true
$chkStorageProtect.ForeColor = "#e0e0e0"
$grpData.Controls.Add($chkStorageProtect)

# --- SECTION 6: Access Control & Authentication ---
$grpAuth = New-Object System.Windows.Forms.GroupBox
$grpAuth.Text = "Access Control & Authentication"
$grpAuth.Location = New-Object System.Drawing.Point(20, 435)
$grpAuth.Size = New-Object System.Drawing.Size(850, 80)
$grpAuth.ForeColor = "#e0e0e0"
$form.Controls.Add($grpAuth)

$lblAPI = New-Object System.Windows.Forms.Label
$lblAPI.Text = "API Authentication:"
$lblAPI.Location = New-Object System.Drawing.Point(15, 25)
$lblAPI.AutoSize = $true
$lblAPI.ForeColor = "#e0e0e0"
$grpAuth.Controls.Add($lblAPI)

$cmbAPI = New-Object System.Windows.Forms.ComboBox
$cmbAPI.Location = New-Object System.Drawing.Point(135, 22)
$cmbAPI.Width = 180
$cmbAPI.DropDownStyle = "DropDownList"
$cmbAPI.Items.AddRange(@("None/Public", "Basic Auth", "API Keys", "OAuth 2.0/Tokens", "Certificate-Based"))
$cmbAPI.SelectedIndex = 0
$grpAuth.Controls.Add($cmbAPI)

$chkMFA = New-Object System.Windows.Forms.CheckBox
$chkMFA.Text = "Multi-Factor Authentication (MFA)"
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

# --- SECTION 7: Disaster Recovery & Business Continuity ---
$grpDR = New-Object System.Windows.Forms.GroupBox
$grpDR.Text = "Disaster Recovery & Business Continuity"
$grpDR.Location = New-Object System.Drawing.Point(20, 525)
$grpDR.Size = New-Object System.Drawing.Size(420, 105)
$grpDR.ForeColor = "#e0e0e0"
$form.Controls.Add($grpDR)

$chkBackupPlan = New-Object System.Windows.Forms.CheckBox
$chkBackupPlan.Text = "Documented Backup Plan"
$chkBackupPlan.Location = New-Object System.Drawing.Point(15, 25)
$chkBackupPlan.AutoSize = $true
$chkBackupPlan.ForeColor = "#e0e0e0"
$grpDR.Controls.Add($chkBackupPlan)

$chkOffSiteBackup = New-Object System.Windows.Forms.CheckBox
$chkOffSiteBackup.Text = "Off-Site/Cloud Backup Storage"
$chkOffSiteBackup.Location = New-Object System.Drawing.Point(15, 50)
$chkOffSiteBackup.AutoSize = $true
$chkOffSiteBackup.ForeColor = "#e0e0e0"
$grpDR.Controls.Add($chkOffSiteBackup)

$chkRecoveryTest = New-Object System.Windows.Forms.CheckBox
$chkRecoveryTest.Text = "Regular Recovery Drills Conducted"
$chkRecoveryTest.Location = New-Object System.Drawing.Point(15, 75)
$chkRecoveryTest.AutoSize = $true
$chkRecoveryTest.ForeColor = "#e0e0e0"
$grpDR.Controls.Add($chkRecoveryTest)

$chkBCP = New-Object System.Windows.Forms.CheckBox
$chkBCP.Text = "Business Continuity Plan (BCP)"
$chkBCP.Location = New-Object System.Drawing.Point(225, 25)
$chkBCP.AutoSize = $true
$chkBCP.ForeColor = "#e0e0e0"
$grpDR.Controls.Add($chkBCP)

# --- SECTION 8: Regulatory Compliance ---
$grpCompliance = New-Object System.Windows.Forms.GroupBox
$grpCompliance.Text = "Regulatory Compliance Requirements"
$grpCompliance.Location = New-Object System.Drawing.Point(450, 525)
$grpCompliance.Size = New-Object System.Drawing.Size(420, 105)
$grpCompliance.ForeColor = "#e0e0e0"
$form.Controls.Add($grpCompliance)

$chkGDPR = New-Object System.Windows.Forms.CheckBox
$chkGDPR.Text = "GDPR Compliance (Data Privacy)"
$chkGDPR.Location = New-Object System.Drawing.Point(15, 25)
$chkGDPR.AutoSize = $true
$chkGDPR.ForeColor = "#e0e0e0"
$grpCompliance.Controls.Add($chkGDPR)

$chkHIPAA = New-Object System.Windows.Forms.CheckBox
$chkHIPAA.Text = "HIPAA Compliance (Healthcare)"
$chkHIPAA.Location = New-Object System.Drawing.Point(15, 50)
$chkHIPAA.AutoSize = $true
$chkHIPAA.ForeColor = "#e0e0e0"
$grpCompliance.Controls.Add($chkHIPAA)

$chkISO27001 = New-Object System.Windows.Forms.CheckBox
$chkISO27001.Text = "ISO 27001 Security Standards"
$chkISO27001.Location = New-Object System.Drawing.Point(15, 75)
$chkISO27001.AutoSize = $true
$chkISO27001.ForeColor = "#e0e0e0"
$grpCompliance.Controls.Add($chkISO27001)

$chkPCIDSS = New-Object System.Windows.Forms.CheckBox
$chkPCIDSS.Text = "PCI-DSS (Payment Processing)"
$chkPCIDSS.Location = New-Object System.Drawing.Point(225, 25)
$chkPCIDSS.AutoSize = $true
$chkPCIDSS.ForeColor = "#e0e0e0"
$grpCompliance.Controls.Add($chkPCIDSS)

$chkNIST = New-Object System.Windows.Forms.CheckBox
$chkNIST.Text = "NIST Cybersecurity Framework"
$chkNIST.Location = New-Object System.Drawing.Point(225, 50)
$chkNIST.AutoSize = $true
$chkNIST.ForeColor = "#e0e0e0"
$grpCompliance.Controls.Add($chkNIST)

# --- Action Buttons ---
$btnAudit = New-Object System.Windows.Forms.Button
$btnAudit.Text = "RUN COMPREHENSIVE SECURITY AUDIT"
$btnAudit.Location = New-Object System.Drawing.Point(20, 640)
$btnAudit.Size = New-Object System.Drawing.Size(630, 45)
$btnAudit.BackColor = "#00d9ff"
$btnAudit.ForeColor = "#000000"
$btnAudit.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$btnAudit.FlatStyle = "Flat"
$form.Controls.Add($btnAudit)

$btnExport = New-Object System.Windows.Forms.Button
$btnExport.Text = "EXPORT REPORT"
$btnExport.Location = New-Object System.Drawing.Point(660, 640)
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
$txtOutput.Location = New-Object System.Drawing.Point(20, 695)
$txtOutput.Size = New-Object System.Drawing.Size(850, 120)
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
    [void]$sb.AppendLine("=" * 100)
    [void]$sb.AppendLine("IOT DEVICE COMPREHENSIVE SECURITY AUDIT REPORT")
    [void]$sb.AppendLine("=" * 100)
    [void]$sb.AppendLine("Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    [void]$sb.AppendLine("Device: $($txtDevName.Text)")
    [void]$sb.AppendLine("Type: $($cmbDevType.SelectedItem)")
    [void]$sb.AppendLine("Asset ID: $($txtAssetID.Text)")
    [void]$sb.AppendLine("Location: $($txtLocation.Text)")
    [void]$sb.AppendLine("Governance Framework: $($cmbFramework.SelectedItem)")
    [void]$sb.AppendLine("-" * 100)
    
    # IT Governance & Leadership (10 points)
    [void]$sb.AppendLine("`n[IT GOVERNANCE & POLICY FRAMEWORK]")
    $framework = $cmbFramework.SelectedItem
    if ($framework -ne "None") {
        $score += 4
        $passes += "Governance framework implemented: $framework"
    } else {
        $warnings += "WARNING: No formal IT governance framework in place"
    }
    
    if ($chkPolicyDoc.Checked) {
        $score += 3
        $passes += "Security policies documented and maintained"
    } else {
        $warnings += "WARNING: Security policies not documented - increases compliance risk"
    }
    
    if ($chkRolesDefined.Checked) {
        $score += 3
        $passes += "IT roles and responsibilities clearly defined"
    } else {
        $warnings += "WARNING: IT roles and responsibilities not clearly defined"
    }
    
    # Asset Management & Discovery (5 points)
    [void]$sb.AppendLine("`n[ASSET MANAGEMENT & DISCOVERY]")
    if ($chkAutoDiscovery.Checked) {
        $score += 3
        $passes += "Automated asset discovery enabled - real-time inventory tracking"
    } else {
        $warnings += "WARNING: Manual asset tracking only - risk of missing unauthorized devices"
    }
    
    if ($txtAssetID.Text -ne "") {
        $score += 2
        $passes += "Device registered in CMDB with Asset ID: $($txtAssetID.Text)"
    } else {
        $warnings += "WARNING: Device not registered in CMDB - asset lifecycle not tracked"
    }
    
    # Endpoint Hardening (15 points)
    [void]$sb.AppendLine("`n[ENDPOINT HARDENING & BOOT SECURITY]")
    if ($chkSecureBoot.Checked) {
        $score += 5
        $passes += "Secure Boot enabled - root of trust established"
    } else {
        $criticalIssues += "CRITICAL: Secure Boot disabled - vulnerable to bootkit attacks"
    }
    
    if ($chkSignedFW.Checked) {
        $score += 5
        $passes += "Firmware signature verification active"
    } else {
        $criticalIssues += "CRITICAL: Unsigned firmware accepted - backdoor injection risk"
    }
    
    if ($chkClosedPorts.Checked) {
        $score += 3
        $passes += "Unused network ports disabled"
    } else {
        $warnings += "WARNING: Open ports increase attack surface"
    }
    
    if ($chkEndpointAV.Checked) {
        $score += 2
        $passes += "Endpoint malware protection active"
    } else {
        $warnings += "WARNING: No endpoint malware protection"
    }
    
    if ($chkPatchMgmt.Checked) {
        $score += 3
        $passes += "Patch management process active - vulnerabilities addressed promptly"
    } else {
        $criticalIssues += "CRITICAL: No patch management - known vulnerabilities unaddressed"
    }
    
    # Network & Gateway (15 points)
    [void]$sb.AppendLine("`n[NETWORK & GATEWAY SECURITY]")
    if ($chkSWG.Checked) {
        $score += 3
        $passes += "Secure Web Gateway filtering traffic"
    } else {
        $warnings += "WARNING: No gateway-level traffic filtering"
    }
    
    if ($chkSSLInspect.Checked) {
        $score += 2
        $passes += "Deep SSL/TLS inspection enabled"
    } else {
        $warnings += "WARNING: Encrypted traffic not inspected - potential data exfiltration risk"
    }
    
    if ($chkVPN.Checked) {
        $score += 2
        $passes += "VPN configured for remote access"
    }
    
    if ($chkFirewall.Checked) {
        $score += 3
        $passes += "Network firewall properly configured"
    } else {
        $criticalIssues += "CRITICAL: No network firewall configured"
    }
    
    if ($chkSegmentation.Checked) {
        $score += 3
        $passes += "Network segmentation/VLANs implemented - lateral movement prevention"
    } else {
        $warnings += "WARNING: No network segmentation - flat network topology increases breach impact"
    }
    
    if ($chkIDS.Checked) {
        $score += 2
        $passes += "Intrusion Detection System monitoring network activity"
    } else {
        $warnings += "WARNING: No IDS - attacks may go undetected"
    }
    
    # Data Protection (15 points)
    [void]$sb.AppendLine("`n[DATA PROTECTION & ENCRYPTION]")
    $transport = $cmbTransport.SelectedItem
    if ($transport -match "TLS 1.3") {
        $score += 7
        $passes += "Strong transport encryption (TLS 1.3) - modern cipher suites"
    } elseif ($transport -match "TLS 1.2") {
        $score += 5
        $warnings += "WARNING: TLS 1.2 is acceptable but TLS 1.3 recommended for better security"
    } else {
        $criticalIssues += "CRITICAL: Unencrypted transport protocol - data vulnerable to interception"
    }
    
    if ($chkDataAtRest.Checked) {
        $score += 5
        $passes += "Data at rest encrypted (AES-256)"
    } else {
        $criticalIssues += "CRITICAL: Unencrypted storage - physical theft exposes data"
    }
    
    if ($chkAsymmetric.Checked) {
        $score += 2
        $passes += "Asymmetric encryption for key exchange (PKI)"
    }
    
    if ($chkStorageProtect.Checked) {
        $score += 1
        $passes += "Secure storage with active monitoring"
    }
    
    # Authentication & Access Control (20 points)
    [void]$sb.AppendLine("`n[ACCESS CONTROL & AUTHENTICATION]")
    $apiAuth = $cmbAPI.SelectedItem
    if ($apiAuth -match "Certificate|OAuth") {
        $score += 8
        $passes += "Strong API authentication implemented: $apiAuth"
    } elseif ($apiAuth -match "API Keys") {
        $score += 5
        $warnings += "WARNING: API keys acceptable but certificate-based auth recommended"
    } elseif ($apiAuth -match "Basic") {
        $score += 2
        $warnings += "WARNING: Basic authentication is weak - credentials easily compromised"
    } else {
        $criticalIssues += "CRITICAL: No API authentication - public access vulnerability"
    }
    
    if ($chkMFA.Checked) {
        $score += 5
        $passes += "Multi-factor authentication enabled"
    } else {
        $warnings += "WARNING: MFA not enabled - single point of failure in authentication"
    }
    
    if ($chkDefaultCreds.Checked) {
        $score += 3
        $passes += "Default credentials changed"
    } else {
        $criticalIssues += "CRITICAL: Default credentials active - IMMEDIATE BOTNET RISK (Mirai-style attacks)"
        $score -= 15
    }
    
    if ($chkRBAC.Checked) {
        $score += 2
        $passes += "Role-Based Access Control (RBAC) implemented - least privilege principle"
    } else {
        $warnings += "WARNING: No RBAC - excessive permissions increase insider threat risk"
    }
    
    if ($chkAccessLogs.Checked) {
        $score += 2
        $passes += "Access logs and audit trail maintained - compliance and forensics"
    } else {
        $warnings += "WARNING: No access logs - unable to investigate security incidents"
    }
    
    # Disaster Recovery & Business Continuity (10 points)
    [void]$sb.AppendLine("`n[DISASTER RECOVERY & BUSINESS CONTINUITY]")
    if ($chkBackupPlan.Checked) {
        $score += 3
        $passes += "Documented backup plan in place"
    } else {
        $criticalIssues += "CRITICAL: No documented backup plan - data loss risk"
    }
    
    if ($chkOffSiteBackup.Checked) {
        $score += 3
        $passes += "Off-site/cloud backup storage configured - protects against site disasters"
    } else {
        $warnings += "WARNING: No off-site backups - single point of failure"
    }
    
    if ($chkRecoveryTest.Checked) {
        $score += 2
        $passes += "Regular recovery drills conducted - validated RTO/RPO"
    } else {
        $warnings += "WARNING: Recovery procedures untested - may fail during actual disaster"
    }
    
    if ($chkBCP.Checked) {
        $score += 2
        $passes += "Business Continuity Plan documented and maintained"
    } else {
        $warnings += "WARNING: No BCP - business disruption during outages"
    }
    
    # Regulatory Compliance (10 points)
    [void]$sb.AppendLine("`n[REGULATORY COMPLIANCE]")
    $complianceCount = 0
    
    if ($chkGDPR.Checked) {
        $score += 2
        $complianceCount++
        $passes += "GDPR compliance controls implemented (data privacy)"
    }
    
    if ($chkHIPAA.Checked) {
        $score += 2
        $complianceCount++
        $passes += "HIPAA compliance controls implemented (healthcare data)"
    }
    
    if ($chkISO27001.Checked) {
        $score += 2
        $complianceCount++
        $passes += "ISO 27001 security standards compliance"
    }
    
    if ($chkPCIDSS.Checked) {
        $score += 2
        $complianceCount++
        $passes += "PCI-DSS compliance (payment card industry)"
    }
    
    if ($chkNIST.Checked) {
        $score += 2
        $complianceCount++
        $passes += "NIST Cybersecurity Framework alignment"
    }
    
    if ($complianceCount -eq 0) {
        $warnings += "WARNING: No regulatory compliance frameworks implemented"
    }
    
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
    
    # Calculate compliance percentages
    $score = [Math]::Max(0, $score)
    $percentage = [Math]::Round(($score / $maxScore) * 100, 1)
    
    # Final Assessment
    [void]$sb.AppendLine("`n" + "=" * 100)
    [void]$sb.AppendLine("COMPREHENSIVE SECURITY SCORE: $score / $maxScore ($percentage%)")
    [void]$sb.AppendLine("Critical Issues: $($criticalIssues.Count) | Warnings: $($warnings.Count) | Passed Controls: $($passes.Count)")
    
    if ($score -ge 85) {
        [void]$sb.AppendLine("RISK LEVEL: LOW")
        [void]$sb.AppendLine("COMPLIANCE STATUS: COMPLIANT")
        [void]$sb.AppendLine("RECOMMENDATION: Device meets enterprise security standards - approved for deployment")
        [void]$sb.AppendLine("NEXT STEPS: Continue monitoring and conduct annual recertification")
        $txtOutput.ForeColor = "#00ff00"
    } elseif ($score -ge 70) {
        [void]$sb.AppendLine("RISK LEVEL: MEDIUM")
        [void]$sb.AppendLine("COMPLIANCE STATUS: PARTIALLY COMPLIANT")
        [void]$sb.AppendLine("RECOMMENDATION: Security gaps present - remediation required before production use")
        [void]$sb.AppendLine("NEXT STEPS: Address warnings within 30 days, reaudit quarterly")
        $txtOutput.ForeColor = "#ffaa00"
    } elseif ($score -ge 50) {
        [void]$sb.AppendLine("RISK LEVEL: HIGH")
        [void]$sb.AppendLine("COMPLIANCE STATUS: NON-COMPLIANT")
        [void]$sb.AppendLine("RECOMMENDATION: Significant vulnerabilities - immediate remediation required")
        [void]$sb.AppendLine("NEXT STEPS: Address all critical issues immediately, implement missing controls")
        $txtOutput.ForeColor = "#ff6600"
    } else {
        [void]$sb.AppendLine("RISK LEVEL: CRITICAL")
        [void]$sb.AppendLine("COMPLIANCE STATUS: NON-COMPLIANT")
        [void]$sb.AppendLine("RECOMMENDATION: Device MUST NOT be deployed - severe security deficiencies")
        [void]$sb.AppendLine("NEXT STEPS: Complete security overhaul required, executive review needed")
        $txtOutput.ForeColor = "#ff0000"
    }
    
    [void]$sb.AppendLine("`nREGULATORY COMPLIANCE MAPPING:")
    [void]$sb.AppendLine("  GDPR: $(if($chkGDPR.Checked){'COMPLIANT'}else{'NOT ASSESSED'})")
    [void]$sb.AppendLine("  HIPAA: $(if($chkHIPAA.Checked){'COMPLIANT'}else{'NOT ASSESSED'})")
    [void]$sb.AppendLine("  ISO 27001: $(if($chkISO27001.Checked){'COMPLIANT'}else{'NOT ASSESSED'})")
    [void]$sb.AppendLine("  PCI-DSS: $(if($chkPCIDSS.Checked){'COMPLIANT'}else{'NOT ASSESSED'})")
    [void]$sb.AppendLine("  NIST CSF: $(if($chkNIST.Checked){'ALIGNED'}else{'NOT ASSESSED'})")
    
    [void]$sb.AppendLine("`nAUDIT METHODOLOGY:")
    [void]$sb.AppendLine("  Based on ITAM best practices and industry standards")
    [void]$sb.AppendLine("  Covers: Governance, Asset Management, Endpoint Security, Network Security,")
    [void]$sb.AppendLine("          Data Protection, Access Control, Disaster Recovery, and Compliance")
    
    [void]$sb.AppendLine("=" * 100)
    [void]$sb.AppendLine("End of Audit Report - Generated by IoT Security Auditor v2.0")
    [void]$sb.AppendLine("For questions or remediation guidance, contact your IT Security team")
    [void]$sb.AppendLine("=" * 100)
    
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
    $saveDialog.FileName = "IoT_Security_Audit_$($txtDevName.Text -replace '[^a-zA-Z0-9]', '_')_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    $saveDialog.Title = "Export Comprehensive Security Audit Report"
    
    if ($saveDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        try {
            $global:auditReport | Out-File -FilePath $saveDialog.FileName -Encoding UTF8
            [System.Windows.Forms.MessageBox]::Show(
                "Comprehensive audit report successfully exported to:`n$($saveDialog.FileName)`n`nThis report can be shared with stakeholders and compliance officers.",
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
