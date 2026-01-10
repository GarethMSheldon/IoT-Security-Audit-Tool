<#
.SYNOPSIS
    IoT Device Security Auditor - Professional Edition
.DESCRIPTION
    A comprehensive security assessment tool for IoT device configurations.
    Evaluates endpoint hardening, network security, encryption, and compliance.
.NOTES
    Author: Gareth Sheldon
    Version: 1.0
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# --- Form Setup ---
$form = New-Object System.Windows.Forms.Form
$form.Text = "IoT Security Auditor - Professional"
$form.Size = New-Object System.Drawing.Size(750, 700)
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
$pnlHeader.Size = New-Object System.Drawing.Size(750, 60)
$pnlHeader.BackColor = "#1a1a1a"
$form.Controls.Add($pnlHeader)

$lblHeader = New-Object System.Windows.Forms.Label
$lblHeader.Text = "IOT DEVICE SECURITY ASSESSMENT"
$lblHeader.Location = New-Object System.Drawing.Point(20, 18)
$lblHeader.AutoSize = $true
$lblHeader.Font = $headerFont
$lblHeader.ForeColor = "#00d9ff"
$pnlHeader.Controls.Add($lblHeader)

# --- SECTION 1: Device Information ---
$grpDevice = New-Object System.Windows.Forms.GroupBox
$grpDevice.Text = "Device Information"
$grpDevice.Location = New-Object System.Drawing.Point(20, 75)
$grpDevice.Size = New-Object System.Drawing.Size(700, 70)
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
$txtDevName.Width = 200
$grpDevice.Controls.Add($txtDevName)

$lblDevType = New-Object System.Windows.Forms.Label
$lblDevType.Text = "Device Type:"
$lblDevType.Location = New-Object System.Drawing.Point(350, 25)
$lblDevType.AutoSize = $true
$lblDevType.ForeColor = "#e0e0e0"
$grpDevice.Controls.Add($lblDevType)

$cmbDevType = New-Object System.Windows.Forms.ComboBox
$cmbDevType.Location = New-Object System.Drawing.Point(440, 22)
$cmbDevType.Width = 230
$cmbDevType.DropDownStyle = "DropDownList"
$cmbDevType.Items.AddRange(@("Smart Sensor", "Gateway Device", "Camera/Surveillance", "Industrial Controller", "Smart Appliance", "Medical Device", "Other"))
$cmbDevType.SelectedIndex = 0
$grpDevice.Controls.Add($cmbDevType)

# --- SECTION 2: Endpoint Hardening ---
$grpEndpoint = New-Object System.Windows.Forms.GroupBox
$grpEndpoint.Text = "Endpoint Hardening & Boot Security"
$grpEndpoint.Location = New-Object System.Drawing.Point(20, 155)
$grpEndpoint.Size = New-Object System.Drawing.Size(340, 130)
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
$chkClosedPorts.Location = New-Object System.Drawing.Point(15, 75)
$chkClosedPorts.AutoSize = $true
$chkClosedPorts.ForeColor = "#e0e0e0"
$grpEndpoint.Controls.Add($chkClosedPorts)

$chkEndpointAV = New-Object System.Windows.Forms.CheckBox
$chkEndpointAV.Text = "Endpoint Malware Protection"
$chkEndpointAV.Location = New-Object System.Drawing.Point(15, 100)
$chkEndpointAV.AutoSize = $true
$chkEndpointAV.ForeColor = "#e0e0e0"
$grpEndpoint.Controls.Add($chkEndpointAV)

# --- SECTION 3: Network & Gateway ---
$grpNetwork = New-Object System.Windows.Forms.GroupBox
$grpNetwork.Text = "Network & Gateway Security"
$grpNetwork.Location = New-Object System.Drawing.Point(380, 155)
$grpNetwork.Size = New-Object System.Drawing.Size(340, 130)
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

# --- SECTION 4: Data Protection ---
$grpData = New-Object System.Windows.Forms.GroupBox
$grpData.Text = "Data Protection & Encryption"
$grpData.Location = New-Object System.Drawing.Point(20, 295)
$grpData.Size = New-Object System.Drawing.Size(700, 100)
$grpData.ForeColor = "#e0e0e0"
$form.Controls.Add($grpData)

$lblTransport = New-Object System.Windows.Forms.Label
$lblTransport.Text = "Transport Protocol:"
$lblTransport.Location = New-Object System.Drawing.Point(15, 30)
$lblTransport.AutoSize = $true
$lblTransport.ForeColor = "#e0e0e0"
$grpData.Controls.Add($lblTransport)

$cmbTransport = New-Object System.Windows.Forms.ComboBox
$cmbTransport.Location = New-Object System.Drawing.Point(130, 27)
$cmbTransport.Width = 160
$cmbTransport.DropDownStyle = "DropDownList"
$cmbTransport.Items.AddRange(@("HTTP (Plaintext)", "MQTT (No TLS)", "HTTPS (TLS 1.2)", "HTTPS (TLS 1.3)", "MQTTS (TLS 1.3)"))
$cmbTransport.SelectedIndex = 0
$grpData.Controls.Add($cmbTransport)

$chkDataAtRest = New-Object System.Windows.Forms.CheckBox
$chkDataAtRest.Text = "Data at Rest Encrypted (AES-256)"
$chkDataAtRest.Location = New-Object System.Drawing.Point(15, 65)
$chkDataAtRest.AutoSize = $true
$chkDataAtRest.ForeColor = "#e0e0e0"
$grpData.Controls.Add($chkDataAtRest)

$chkAsymmetric = New-Object System.Windows.Forms.CheckBox
$chkAsymmetric.Text = "Asymmetric Key Exchange (PKI)"
$chkAsymmetric.Location = New-Object System.Drawing.Point(350, 30)
$chkAsymmetric.AutoSize = $true
$chkAsymmetric.ForeColor = "#e0e0e0"
$grpData.Controls.Add($chkAsymmetric)

$chkStorageProtect = New-Object System.Windows.Forms.CheckBox
$chkStorageProtect.Text = "Secure Storage with Monitoring"
$chkStorageProtect.Location = New-Object System.Drawing.Point(350, 65)
$chkStorageProtect.AutoSize = $true
$chkStorageProtect.ForeColor = "#e0e0e0"
$grpData.Controls.Add($chkStorageProtect)

# --- SECTION 5: Access Control & Authentication ---
$grpAuth = New-Object System.Windows.Forms.GroupBox
$grpAuth.Text = "Access Control & Authentication"
$grpAuth.Location = New-Object System.Drawing.Point(20, 405)
$grpAuth.Size = New-Object System.Drawing.Size(700, 80)
$grpAuth.ForeColor = "#e0e0e0"
$form.Controls.Add($grpAuth)

$lblAPI = New-Object System.Windows.Forms.Label
$lblAPI.Text = "API Authentication:"
$lblAPI.Location = New-Object System.Drawing.Point(15, 30)
$lblAPI.AutoSize = $true
$lblAPI.ForeColor = "#e0e0e0"
$grpAuth.Controls.Add($lblAPI)

$cmbAPI = New-Object System.Windows.Forms.ComboBox
$cmbAPI.Location = New-Object System.Drawing.Point(140, 27)
$cmbAPI.Width = 150
$cmbAPI.DropDownStyle = "DropDownList"
$cmbAPI.Items.AddRange(@("None/Public", "Basic Auth", "API Keys", "OAuth 2.0/Tokens", "Certificate-Based"))
$cmbAPI.SelectedIndex = 0
$grpAuth.Controls.Add($cmbAPI)

$chkMFA = New-Object System.Windows.Forms.CheckBox
$chkMFA.Text = "Multi-Factor Authentication (MFA)"
$chkMFA.Location = New-Object System.Drawing.Point(350, 30)
$chkMFA.AutoSize = $true
$chkMFA.ForeColor = "#e0e0e0"
$grpAuth.Controls.Add($chkMFA)

$chkDefaultCreds = New-Object System.Windows.Forms.CheckBox
$chkDefaultCreds.Text = "Default Credentials Changed"
$chkDefaultCreds.Location = New-Object System.Drawing.Point(15, 55)
$chkDefaultCreds.AutoSize = $true
$chkDefaultCreds.ForeColor = "#e0e0e0"
$grpAuth.Controls.Add($chkDefaultCreds)

# --- Action Buttons ---
$btnAudit = New-Object System.Windows.Forms.Button
$btnAudit.Text = "RUN SECURITY AUDIT"
$btnAudit.Location = New-Object System.Drawing.Point(20, 495)
$btnAudit.Size = New-Object System.Drawing.Size(520, 45)
$btnAudit.BackColor = "#00d9ff"
$btnAudit.ForeColor = "#000000"
$btnAudit.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$btnAudit.FlatStyle = "Flat"
$form.Controls.Add($btnAudit)

$btnExport = New-Object System.Windows.Forms.Button
$btnExport.Text = "EXPORT REPORT"
$btnExport.Location = New-Object System.Drawing.Point(550, 495)
$btnExport.Size = New-Object System.Drawing.Size(170, 45)
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
$txtOutput.Location = New-Object System.Drawing.Point(20, 550)
$txtOutput.Size = New-Object System.Drawing.Size(700, 100)
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
    [void]$sb.AppendLine("=" * 80)
    [void]$sb.AppendLine("IOT DEVICE SECURITY AUDIT REPORT")
    [void]$sb.AppendLine("=" * 80)
    [void]$sb.AppendLine("Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    [void]$sb.AppendLine("Device: $($txtDevName.Text)")
    [void]$sb.AppendLine("Type: $($cmbDevType.SelectedItem)")
    [void]$sb.AppendLine("-" * 80)
    
    # Endpoint Hardening (25 points)
    [void]$sb.AppendLine("`n[ENDPOINT HARDENING]")
    if ($chkSecureBoot.Checked) {
        $score += 8
        $passes += "Secure Boot enabled - Root of trust established"
    } else {
        $criticalIssues += "CRITICAL: Secure Boot disabled - vulnerable to bootkit attacks"
    }
    
    if ($chkSignedFW.Checked) {
        $score += 8
        $passes += "Firmware signature verification active"
    } else {
        $criticalIssues += "CRITICAL: Unsigned firmware accepted - backdoor injection risk"
    }
    
    if ($chkClosedPorts.Checked) {
        $score += 5
        $passes += "Unused network ports disabled"
    } else {
        $warnings += "WARNING: Open ports increase attack surface"
    }
    
    if ($chkEndpointAV.Checked) {
        $score += 4
        $passes += "Endpoint malware protection active"
    } else {
        $warnings += "WARNING: No endpoint malware protection"
    }
    
    # Network & Gateway (20 points)
    [void]$sb.AppendLine("`n[NETWORK & GATEWAY SECURITY]")
    if ($chkSWG.Checked) {
        $score += 7
        $passes += "Secure Web Gateway filtering traffic"
    } else {
        $warnings += "WARNING: No gateway-level traffic filtering"
    }
    
    if ($chkSSLInspect.Checked) {
        $score += 5
        $passes += "Deep SSL/TLS inspection enabled"
    } else {
        $warnings += "WARNING: Encrypted traffic not inspected"
    }
    
    if ($chkVPN.Checked) {
        $score += 4
        $passes += "VPN configured for remote access"
    }
    
    if ($chkFirewall.Checked) {
        $score += 4
        $passes += "Network firewall properly configured"
    } else {
        $criticalIssues += "CRITICAL: No network firewall configured"
    }
    
    # Data Protection (25 points)
    [void]$sb.AppendLine("`n[DATA PROTECTION & ENCRYPTION]")
    $transport = $cmbTransport.SelectedItem
    if ($transport -match "TLS 1.3") {
        $score += 10
        $passes += "Strong transport encryption (TLS 1.3)"
    } elseif ($transport -match "TLS 1.2") {
        $score += 7
        $warnings += "WARNING: TLS 1.2 is acceptable but TLS 1.3 recommended"
    } else {
        $criticalIssues += "CRITICAL: Unencrypted transport protocol - data vulnerable to interception"
    }
    
    if ($chkDataAtRest.Checked) {
        $score += 8
        $passes += "Data at rest encrypted (AES-256)"
    } else {
        $criticalIssues += "CRITICAL: Unencrypted storage - physical theft exposes data"
    }
    
    if ($chkAsymmetric.Checked) {
        $score += 4
        $passes += "Asymmetric encryption for key exchange"
    }
    
    if ($chkStorageProtect.Checked) {
        $score += 3
        $passes += "Secure storage with active monitoring"
    }
    
    # Authentication & Access (30 points)
    [void]$sb.AppendLine("`n[ACCESS CONTROL & AUTHENTICATION]")
    $apiAuth = $cmbAPI.SelectedItem
    if ($apiAuth -match "Certificate|OAuth") {
        $score += 15
        $passes += "Strong API authentication ($apiAuth)"
    } elseif ($apiAuth -match "API Keys") {
        $score += 10
        $warnings += "WARNING: API keys acceptable but certificate-based auth recommended"
    } elseif ($apiAuth -match "Basic") {
        $score += 3
        $warnings += "WARNING: Basic authentication is weak"
    } else {
        $criticalIssues += "CRITICAL: No API authentication - public access vulnerability"
    }
    
    if ($chkMFA.Checked) {
        $score += 10
        $passes += "Multi-factor authentication enabled"
    } else {
        $warnings += "WARNING: MFA not enabled - single point of failure"
    }
    
    if ($chkDefaultCreds.Checked) {
        $score += 5
        $passes += "Default credentials changed"
    } else {
        $criticalIssues += "CRITICAL: Default credentials active - IMMEDIATE BOTNET RISK"
        $score -= 20
    }
    
    # Generate Report Sections
    if ($criticalIssues.Count -gt 0) {
        [void]$sb.AppendLine("`n[CRITICAL ISSUES]")
        foreach ($issue in $criticalIssues) {
            [void]$sb.AppendLine("  [X] $issue")
        }
    }
    
    if ($warnings.Count -gt 0) {
        [void]$sb.AppendLine("`n[WARNINGS]")
        foreach ($warn in $warnings) {
            [void]$sb.AppendLine("  [!] $warn")
        }
    }
    
    if ($passes.Count -gt 0) {
        [void]$sb.AppendLine("`n[PASSED CONTROLS]")
        foreach ($pass in $passes) {
            [void]$sb.AppendLine("  [+] $pass")
        }
    }
    
    # Final Assessment
    $score = [Math]::Max(0, $score)
    [void]$sb.AppendLine("`n" + "=" * 80)
    [void]$sb.AppendLine("SECURITY SCORE: $score / $maxScore")
    
    if ($score -ge 85) {
        [void]$sb.AppendLine("RISK LEVEL: LOW")
        [void]$sb.AppendLine("STATUS: Device meets enterprise security standards")
        $txtOutput.ForeColor = "#00ff00"
    } elseif ($score -ge 65) {
        [void]$sb.AppendLine("RISK LEVEL: MEDIUM")
        [void]$sb.AppendLine("STATUS: Security gaps present - remediation recommended")
        $txtOutput.ForeColor = "#ffaa00"
    } elseif ($score -ge 40) {
        [void]$sb.AppendLine("RISK LEVEL: HIGH")
        [void]$sb.AppendLine("STATUS: Significant vulnerabilities - immediate action required")
        $txtOutput.ForeColor = "#ff6600"
    } else {
        [void]$sb.AppendLine("RISK LEVEL: CRITICAL")
        [void]$sb.AppendLine("STATUS: Device should NOT be deployed - severe security deficiencies")
        $txtOutput.ForeColor = "#ff0000"
    }
    
    [void]$sb.AppendLine("=" * 80)
    
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
    $saveDialog.FileName = "IoT_Security_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    $saveDialog.Title = "Export Security Audit Report"
    
    if ($saveDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        try {
            $global:auditReport | Out-File -FilePath $saveDialog.FileName -Encoding UTF8
            [System.Windows.Forms.MessageBox]::Show(
                "Audit report successfully exported to:`n$($saveDialog.FileName)",
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
