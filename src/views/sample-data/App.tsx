/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useState, useEffect, useRef, useCallback, useMemo } from "react";
import { App as McpApp } from "@modelcontextprotocol/ext-apps";
import { applyTheme } from "../../shared/theme";
import { extractCallResult } from "../../shared/extract-tool-text";
import "./styles.css";

interface AlertInfo {
  rule: string;
  severity: "critical" | "high" | "medium";
}

interface HuntQuery {
  label: string;
  query: string;
}

interface Scenario {
  id: string;
  name: string;
  desc: string;
  icon: string;
  tags: string[];
  severity: "critical" | "high" | "medium";
  eventSources: { index: string; label: string }[];
  alerts: AlertInfo[];
  hunts: HuntQuery[];
  outcome: string;
}

const SCENARIOS: Scenario[] = [
  {
    id: "ransomware-kill-chain",
    name: "Ransomware Kill Chain",
    desc: "Full kill chain — phishing, C2 beaconing, lateral movement, credential dump, mass encryption across 4 hosts",
    icon: "\u{1F480}",
    tags: ["T1566.001 Spearphishing", "T1486 Encryption", "T1490 Inhibit Recovery"],
    severity: "critical",
    eventSources: [
      { index: "logs-endpoint.events.process-*", label: "Endpoint process events (macro exec, discovery, cred dump)" },
      { index: "logs-endpoint.events.network-*", label: "C2 beacon connections to external IPs" },
      { index: "logs-endpoint.events.file-*", label: "Mass file encryption (.locked extension)" },
    ],
    alerts: [
      { rule: "Suspicious Macro-Enabled Document Execution", severity: "medium" },
      { rule: "Cobalt Strike Beacon - Periodic C2 Communication", severity: "high" },
      { rule: "Enumeration of Domain Admin Group", severity: "medium" },
      { rule: "Credential Dumping - LSASS Access on Domain Controller", severity: "critical" },
      { rule: "Ransomware - Mass File Extension Modification", severity: "critical" },
      { rule: "Ransomware - Volume Shadow Copy Deletion", severity: "critical" },
      { rule: "Lateral Movement via PsExec to Multiple Hosts", severity: "high" },
    ],
    hunts: [
      { label: "Encoded PowerShell", query: 'FROM logs-endpoint.events.process-* | WHERE process.name == "powershell.exe" AND process.args LIKE "*-enc*" | STATS count=COUNT() BY host.name' },
      { label: "File encryption", query: 'FROM logs-endpoint.events.file-* | WHERE file.extension == "locked" | STATS count=COUNT() BY host.name, process.name' },
      { label: "C2 beaconing", query: 'FROM logs-endpoint.events.network-* | WHERE destination.port IN (443, 8443) | STATS count=COUNT() BY destination.ip, process.name' },
    ],
    outcome: "View in Security > Alerts for the full kill chain. Host WKSTN-RECV01 shows initial access, SRV-DC01 shows credential theft, SRV-FILE01 and SRV-SQL01 show encryption. Timeline view shows the progression from phishing to ransomware deployment.",
  },
  {
    id: "windows-credential-theft",
    name: "Windows Credential Theft",
    desc: "Mimikatz, procdump LSASS dump, NTDS extraction on DC, SAM hive export, SMB lateral movement",
    icon: "\u{1F511}",
    tags: ["T1003 Credential Dumping", "T1021.002 SMB"],
    severity: "critical",
    eventSources: [
      { index: "logs-endpoint.events.process-*", label: "Process events (mimikatz, procdump, ntdsutil, reg.exe)" },
      { index: "logs-endpoint.events.network-*", label: "SMB connections to domain controller" },
    ],
    alerts: [
      { rule: "Credential Dumping via Mimikatz", severity: "critical" },
      { rule: "LSASS Memory Dump via Procdump", severity: "high" },
      { rule: "NTDS.dit Extraction Attempt", severity: "critical" },
      { rule: "SAM Registry Hive Export", severity: "high" },
      { rule: "Lateral Movement - SMB to Domain Controller", severity: "high" },
    ],
    hunts: [
      { label: "Credential tools", query: 'FROM logs-endpoint.events.process-* | WHERE process.name IN ("mimikatz.exe", "procdump.exe", "ntdsutil.exe") | STATS count=COUNT() BY process.name, host.name' },
      { label: "SMB lateral movement", query: 'FROM logs-endpoint.events.network-* | WHERE destination.port == 445 | STATS count=COUNT() BY source.ip, destination.ip' },
    ],
    outcome: "Check Security > Alerts grouped by host. WIN-ANALYST01 and WIN-DEV03 show credential theft tools, DC-CORP01 shows NTDS extraction. Risk score is 95 for the Mimikatz alert. Use the investigation graph to trace lateral movement from workstation to DC.",
  },
  {
    id: "linux-persistence",
    name: "Linux Persistence",
    desc: "Backdoor via cron, SSH authorized_keys, systemd service, and kernel rootkit on production Linux servers",
    icon: "\u{1F427}",
    tags: ["T1053.003 Cron", "T1098.004 SSH Keys", "T1014 Rootkit"],
    severity: "critical",
    eventSources: [
      { index: "logs-auditd.log-*", label: "Auditd events (SYSCALL, EXECVE, PATH records)" },
    ],
    alerts: [
      { rule: "Suspicious Download via Curl to Hidden File", severity: "medium" },
      { rule: "Crontab Persistence - Root Cron Modified", severity: "high" },
      { rule: "SSH Authorized Keys Modified", severity: "high" },
      { rule: "Systemd Service Created for Persistence", severity: "high" },
      { rule: "Kernel Module Loaded - Potential Rootkit", severity: "critical" },
      { rule: "SSHD Config Modified to Allow Root Login", severity: "high" },
    ],
    hunts: [
      { label: "Persistence mechanisms", query: 'FROM logs-auditd.log-* | WHERE process.name IN ("crontab", "systemctl", "insmod") OR process.args LIKE "*authorized_keys*" | STATS count=COUNT() BY process.name, host.name' },
      { label: "Hidden file downloads", query: 'FROM logs-auditd.log-* | WHERE process.name == "curl" AND process.args LIKE "*/tmp/*" | STATS count=COUNT() BY host.name' },
    ],
    outcome: "Hosts web-prod-01 and db-prod-02 show persistence mechanisms. The rootkit alert (risk score 95) is the highest priority. Check the auditd process tree to see the full attack — from initial curl download through cron/SSH/systemd persistence to kernel rootkit.",
  },
  {
    id: "network-ids-threats",
    name: "Network IDS Threats",
    desc: "Suricata IDS detections — DNS tunneling, Cobalt Strike beacons, JA3 fingerprinting, port scanning",
    icon: "\u{1F6E1}\u{FE0F}",
    tags: ["T1071.001 C2 Web", "T1048 DNS Exfil", "T1046 Port Scan"],
    severity: "high",
    eventSources: [
      { index: "logs-suricata.eve-*", label: "DNS queries (including tunneling subdomains)" },
      { index: "logs-suricata.eve-*", label: "TLS connections with JA3 fingerprints" },
      { index: "logs-suricata.eve-*", label: "HTTP POST beacon requests" },
      { index: "logs-suricata.eve-*", label: "IDS signature alerts (ET rules)" },
      { index: "logs-suricata.eve-*", label: "Port scan flows across 8 ports" },
    ],
    alerts: [
      { rule: "DNS Tunneling - High Volume Subdomain Queries", severity: "high" },
      { rule: "Suricata IDS - Cobalt Strike Beacon Detected", severity: "critical" },
      { rule: "Suspicious TLS JA3 Fingerprint - Known C2 Framework", severity: "high" },
      { rule: "Network Port Scan Detected", severity: "medium" },
      { rule: "HTTP C2 Beacon - Periodic POST Requests", severity: "high" },
    ],
    hunts: [
      { label: "DNS tunneling", query: 'FROM logs-suricata.eve-* | WHERE dns.question.name LIKE "*evil-cdn*" | STATS count=COUNT() BY dns.question.name, source.ip' },
      { label: "IDS alerts by signature", query: 'FROM logs-suricata.eve-* | WHERE suricata.eve.event_type == "alert" | STATS count=COUNT() BY suricata.eve.alert.signature' },
      { label: "Suspicious TLS", query: 'FROM logs-suricata.eve-* | WHERE tls.client.ja3 IS NOT NULL | STATS count=COUNT() BY tls.client.ja3, destination.ip' },
    ],
    outcome: "Internal host 10.0.5.22 is the compromised endpoint. DNS tunneling exfils data via long subdomain queries to data.x7k2.evil-cdn.com. TLS JA3 hash matches known Cobalt Strike fingerprint. Port scan comes from a separate external IP. Correlate the IDS alerts with endpoint data for full picture.",
  },
  {
    id: "aws-privilege-escalation",
    name: "AWS Privilege Escalation",
    desc: "IAM key creation, admin policy, role assumption, Secrets Manager theft, S3 exfil, CloudTrail disabled",
    icon: "\u{2601}\u{FE0F}",
    tags: ["T1078.004 Cloud Accounts", "T1562.008 Disable Logs"],
    severity: "high",
    eventSources: [
      { index: "logs-aws.cloudtrail-*", label: "IAM API calls (CreateAccessKey, AttachUserPolicy, AssumeRole)" },
      { index: "logs-aws.cloudtrail-*", label: "Resource access (GetSecretValue, GetObject, RunInstances)" },
      { index: "logs-aws.cloudtrail-*", label: "Anti-forensics (DeleteTrail, StopLogging)" },
    ],
    alerts: [
      { rule: "AWS IAM Access Key Created for Another User", severity: "high" },
      { rule: "AWS IAM Privilege Escalation via Policy Attachment", severity: "critical" },
      { rule: "AWS Secrets Manager - Unauthorized Access", severity: "high" },
      { rule: "AWS S3 Bulk Data Download", severity: "high" },
      { rule: "AWS CloudTrail Logging Disabled", severity: "critical" },
    ],
    hunts: [
      { label: "Privilege escalation", query: 'FROM logs-aws.cloudtrail-* | WHERE event.action IN ("AttachUserPolicy", "PutRolePolicy", "CreateRole") | STATS count=COUNT() BY event.action, user.name, source.ip' },
      { label: "Anti-forensics", query: 'FROM logs-aws.cloudtrail-* | WHERE event.action IN ("DeleteTrail", "StopLogging") | STATS count=COUNT() BY event.action, user.name' },
    ],
    outcome: "Two source IPs appear — the original (dev-user) and a second IP (escalated-role). The attack progresses from IAM enumeration through privilege escalation to data exfiltration and anti-forensics. CloudTrail logging disabled is the highest-severity indicator.",
  },
  {
    id: "okta-identity-takeover",
    name: "Okta Identity Takeover",
    desc: "Suspicious geo login, MFA reset, admin role grant, API token creation across 3 compromised accounts",
    icon: "\u{1FAAA}",
    tags: ["T1556 Auth Modification", "T1098 Account Manipulation"],
    severity: "high",
    eventSources: [
      { index: "logs-okta.system-*", label: "Authentication events (login, MFA challenge)" },
      { index: "logs-okta.system-*", label: "IAM changes (password reset, MFA deactivation/activation)" },
      { index: "logs-okta.system-*", label: "Privilege changes (admin grant, API token creation)" },
    ],
    alerts: [
      { rule: "Okta Login from New Geographic Location", severity: "medium" },
      { rule: "Okta MFA Factor Reset After Authentication", severity: "high" },
      { rule: "Okta Admin Role Assigned to User", severity: "critical" },
      { rule: "Okta API Token Created by New Admin", severity: "critical" },
      { rule: "Multiple Okta Accounts Compromised from Same IP", severity: "critical" },
    ],
    hunts: [
      { label: "MFA changes", query: 'FROM logs-okta.system-* | WHERE event.action IN ("user.mfa.factor.deactivate", "user.mfa.factor.activate") | STATS count=COUNT() BY event.action, user.name' },
      { label: "Admin role grants", query: 'FROM logs-okta.system-* | WHERE event.action == "user.account.privilege.grant" | STATS count=COUNT() BY user.name, source.ip' },
    ],
    outcome: "3 victims (cfo@, it-admin@, devops@) are compromised from the same attacker IP in Moscow. The attacker resets MFA, grants admin to it-admin@, creates an API token for persistence. The multi-account alert correlates all 3 compromises by source IP.",
  },
  {
    id: "entra-id-compromise",
    name: "Entra ID Compromise",
    desc: "Impossible travel sign-in, conditional access bypass, Global Admin escalation, OAuth consent phishing",
    icon: "\u{1F310}",
    tags: ["T1078.004 Cloud Accounts", "T1098.003 Cloud Roles", "T1566.002 Phishing"],
    severity: "critical",
    eventSources: [
      { index: "logs-azure.signinlogs-*", label: "Sign-in events with risk levels, conditional access, geo data" },
      { index: "logs-azure.auditlogs-*", label: "Role assignments, app registrations, OAuth consent grants" },
    ],
    alerts: [
      { rule: "Impossible Travel - Azure AD Sign-In", severity: "high" },
      { rule: "Azure AD Risky Sign-In - High Risk", severity: "high" },
      { rule: "Azure AD Global Administrator Role Assigned", severity: "critical" },
      { rule: "OAuth App Consent Phishing - Excessive Permissions", severity: "critical" },
      { rule: "Azure AD MFA Disabled for User", severity: "high" },
    ],
    hunts: [
      { label: "Risky sign-ins", query: 'FROM logs-azure.signinlogs-* | WHERE azure.signinlogs.properties.risk_level_aggregated != "none" | STATS count=COUNT() BY user.name, source.ip, azure.signinlogs.properties.risk_level_aggregated' },
      { label: "OAuth app grants", query: 'FROM logs-azure.auditlogs-* | WHERE event.action == "Add OAuth2PermissionGrant" OR event.action == "Consent to application" | STATS count=COUNT() BY event.action, user.name' },
    ],
    outcome: "sarah.chen@contoso.com signs in from San Francisco then Lagos within minutes (impossible travel). Attacker escalates to Global Admin, registers a malicious OAuth app 'ShadowApp-Exfil' with Mail.Read + Files.ReadWrite.All. mike.dev@ consents to it. MFA is then disabled for global.admin@.",
  },
  {
    id: "gworkspace-exfiltration",
    name: "Google Workspace Exfil",
    desc: "Compromised CEO grants admin to contractor, bulk download of financial docs, sharing to personal email",
    icon: "\u{1F4E7}",
    tags: ["T1530 Cloud Storage", "T1567.002 Exfil to Cloud"],
    severity: "critical",
    eventSources: [
      { index: "logs-google_workspace.login-*", label: "Login events with MFA status and suspicious flags" },
      { index: "logs-google_workspace.admin-*", label: "Admin privilege grants, security settings changes" },
      { index: "logs-google_workspace.drive-*", label: "Bulk file downloads, external sharing to personal email" },
    ],
    alerts: [
      { rule: "Google Workspace - Suspicious Login Without MFA", severity: "medium" },
      { rule: "Google Workspace - Super Admin Granted to External Contractor", severity: "critical" },
      { rule: "Google Workspace - External Drive Sharing Enabled Org-Wide", severity: "high" },
      { rule: "Google Workspace - Bulk File Download by External User", severity: "high" },
      { rule: "Google Drive - Sensitive Files Shared to Personal Email", severity: "critical" },
      { rule: "Google Workspace - 2FA Disabled for Finance User", severity: "high" },
    ],
    hunts: [
      { label: "External sharing", query: 'FROM logs-google_workspace.drive-* | WHERE event.action == "change_user_access" AND google_workspace.drive.visibility == "shared_externally" | STATS count=COUNT() BY file.name, user.email' },
      { label: "Bulk downloads", query: 'FROM logs-google_workspace.drive-* | WHERE event.action == "download" | STATS count=COUNT() BY user.email, file.name' },
      { label: "Admin changes", query: 'FROM logs-google_workspace.admin-* | WHERE event.action == "GRANT_ADMIN_PRIVILEGE" | STATS count=COUNT() BY event.action, user.email' },
    ],
    outcome: "CEO account (ceo@acmecorp.com) is compromised. Attacker grants Super Admin to ext.contractor@, enables org-wide external sharing, downloads 9 sensitive files (revenue forecasts, M&A analysis, compensation data), and shares them to personal-gmail@gmail.com. 2FA is disabled for the finance lead.",
  },
  {
    id: "crowdstrike-edr-attack",
    name: "CrowdStrike EDR Attack",
    desc: "Third-party EDR: drive-by HTA download, encoded PowerShell, certutil beacon download, process masquerading, WMI lateral movement",
    icon: "\u{1F985}",
    tags: ["T1218.005 Mshta", "T1036.005 Masquerading", "T1047 WMI"],
    severity: "critical",
    eventSources: [
      { index: "logs-crowdstrike.fdr-*", label: "CrowdStrike FDR process events (ProcessRollup2) with full process tree" },
      { index: "logs-crowdstrike.fdr-*", label: "CrowdStrike FDR network events (NetworkConnectIP4) for C2 connections" },
    ],
    alerts: [
      { rule: "CrowdStrike - MSHTA Spawned by Browser", severity: "high" },
      { rule: "CrowdStrike - Encoded PowerShell Execution", severity: "high" },
      { rule: "CrowdStrike - Certutil Used for File Download", severity: "high" },
      { rule: "CrowdStrike - Masqueraded Process Name", severity: "critical" },
      { rule: "CrowdStrike - WMI Remote Process Execution", severity: "high" },
    ],
    hunts: [
      { label: "Process tree", query: 'FROM logs-crowdstrike.fdr-* | WHERE event.action == "ProcessRollup2" | STATS count=COUNT() BY process.name, process.parent.name, host.name' },
      { label: "C2 connections", query: 'FROM logs-crowdstrike.fdr-* | WHERE event.action == "NetworkConnectIP4" AND destination.port == 443 | STATS count=COUNT() BY process.name, destination.ip' },
    ],
    outcome: "LAPTOP-SALES04 shows a complete attack chain in the event analyzer: explorer.exe → chrome.exe → mshta.exe → powershell.exe → (certutil.exe download + rundll32.exe C2 + discovery commands + svchost.exe beacon → wmic.exe lateral movement). CrowdStrike FDR events use proper process.entity_id for tree visualization.",
  },
  {
    id: "cdr-cross-domain",
    name: "CDR: Cross-Domain Compromise",
    desc: "Flagship demo: CrowdStrike endpoint compromise + Okta identity takeover for the SAME user. Phishing → data exfil on endpoint while MFA reset + admin escalation in Okta. Includes a Higher-Order correlation rule.",
    icon: "\u{1F310}\u{1F511}",
    tags: ["Cross-Domain", "CDR", "Higher-Order Rule", "T1078 Valid Accounts"],
    severity: "critical",
    eventSources: [
      { index: "logs-crowdstrike.fdr-*", label: "CrowdStrike FDR process tree: chrome → mshta → powershell → 7z/curl/schtasks" },
      { index: "logs-crowdstrike.fdr-*", label: "CrowdStrike FDR network events for data exfiltration" },
      { index: "logs-okta.system-*", label: "Okta auth events: impossible travel login from attacker IP" },
      { index: "logs-okta.system-*", label: "Okta IAM events: MFA deactivate, password change, admin group, API token" },
    ],
    alerts: [
      { rule: "CDR - MSHTA Spawned by Browser", severity: "high" },
      { rule: "CDR - Encoded PowerShell from Phishing Chain", severity: "high" },
      { rule: "CDR - Data Staging via Archive Tool", severity: "high" },
      { rule: "CDR - Data Exfiltration via Curl", severity: "critical" },
      { rule: "CDR - Scheduled Task Persistence", severity: "high" },
      { rule: "CDR - Impossible Travel Login", severity: "medium" },
      { rule: "CDR - MFA Deactivated After Suspicious Login", severity: "high" },
      { rule: "CDR - Password Changed from Suspicious IP", severity: "high" },
      { rule: "CDR - User Added to Admin Group", severity: "critical" },
      { rule: "CDR - API Token Created by Compromised Account", severity: "critical" },
      { rule: "CDR - Cross-Domain Compromise (Higher-Order Rule)", severity: "critical" },
    ],
    hunts: [
      { label: "Cross-domain user activity", query: 'FROM logs-crowdstrike.fdr-*, logs-okta.system-* | WHERE user.email == "alex.chen@acmecorp.com" | STATS count=COUNT() BY event.dataset, event.action' },
      { label: "Attacker IP across sources", query: 'FROM logs-crowdstrike.fdr-*, logs-okta.system-* | WHERE related.ip IS NOT NULL | STATS count=COUNT() BY event.dataset, source.ip' },
      { label: "Okta identity changes", query: 'FROM logs-okta.system-* | WHERE event.action IN ("user.mfa.factor.deactivate", "user.account.update_password", "app.user_membership.add", "system.api_token.create") | STATS count=COUNT() BY event.action, user.email' },
      { label: "CS endpoint process tree", query: 'FROM logs-crowdstrike.fdr-* | WHERE event.action == "ProcessRollup2" AND user.email == "alex.chen@acmecorp.com" | STATS count=COUNT() BY process.name, process.parent.name' },
    ],
    outcome: "This is the three-layer correlation demo. Layer 1 (Manual): Open any CS alert, see user.email alex.chen@acmecorp.com, open Timeline, filter by that email — see BOTH CS endpoint events and Okta identity events on the same timeline. Layer 2 (Automated): The Higher-Order ES|QL rule fires automatically when 4+ alerts from multiple sources share the same user.email. Layer 3 (AI): Run Attack Discovery to get a full narrative of the cross-domain attack. Pitch: in CrowdStrike SIEM, these live in separate consoles. In Elastic, one timeline, one click, one response.",
  },
  {
    id: "mac-endpoint-activity",
    name: "macOS Unified Log",
    desc: "Apple Event credential phishing (display dialog), volume mute stealer indicator, clipboard theft, TCC privacy bypass, LaunchAgent persistence",
    icon: "\u{1F34E}",
    tags: ["T1059.002 AppleScript", "T1562.001 TCC Bypass", "T1543.001 LaunchAgent"],
    severity: "critical",
    eventSources: [
      { index: "logs-unifiedlogs.log-*", label: "Apple Events (syso,dlog credential dialog, aevt,stvl mute, Jons,gClp clipboard)" },
      { index: "logs-unifiedlogs.log-*", label: "TCC access requests and grants (com.apple.TCC subsystem)" },
      { index: "logs-unifiedlogs.log-*", label: "LaunchAgent autolaunch (com.apple.loginwindow.logging)" },
    ],
    alerts: [
      { rule: "macOS - Apple Event Display Dialog (Credential Phishing)", severity: "high" },
      { rule: "macOS - Volume Mute via Apple Event (Stealer Indicator)", severity: "critical" },
      { rule: "macOS - Apple Event Get Clipboard", severity: "high" },
      { rule: "macOS - TCC Access Denied Then Granted", severity: "critical" },
      { rule: "macOS - LaunchAgent Autolaunch Registered", severity: "high" },
    ],
    hunts: [
      { label: "Apple Event types", query: 'FROM logs-unifiedlogs.log-* | WHERE apple_event.type_code IS NOT NULL | STATS count=COUNT() BY apple_event.type_code, process.name' },
      { label: "TCC access changes", query: 'FROM logs-unifiedlogs.log-* | WHERE unified_log.subsystem == "com.apple.TCC" | STATS count=COUNT() BY message' },
      { label: "LaunchAgent activity", query: 'FROM logs-unifiedlogs.log-* | WHERE unified_log.subsystem == "com.apple.loginwindow.logging" AND message LIKE "*performAutolaunch*" | STATS count=COUNT() BY message' },
    ],
    outcome: "MACBOOK-DEV07 shows a macOS stealer attack via Unified Log telemetry. osascript displays a fake password dialog (syso,dlog), mutes volume (aevt,stvl — known stealer pre-indicator), reads clipboard. TCC shows Accessibility access granted to osascript. A LaunchAgent is registered for persistence. All events use the Elastic unifiedlogs integration fields.",
  },
  {
    id: "gcp-cloud-audit",
    name: "GCP Cloud Audit",
    desc: "Service account key theft, IAM over-permissioning, firewall opened to 0.0.0.0/0, logging sink deleted, storage bucket made public",
    icon: "\u{2601}\u{FE0F}",
    tags: ["T1098.001 Cloud Credentials", "T1562.008 Disable Logs", "T1537 Cloud Exfil"],
    severity: "critical",
    eventSources: [
      { index: "logs-gcp.audit-*", label: "GCP audit logs (IAM, Compute, Storage, Logging API calls)" },
    ],
    alerts: [
      { rule: "GCP - Service Account Key Created", severity: "high" },
      { rule: "GCP - IAM Policy Modified to Allow All Users", severity: "critical" },
      { rule: "GCP - Firewall Rule Allows Inbound SSH from Any", severity: "high" },
      { rule: "GCP - Cloud Logging Sink Deleted", severity: "critical" },
      { rule: "GCP - Cloud Storage Bucket Made Public", severity: "critical" },
    ],
    hunts: [
      { label: "IAM changes", query: 'FROM logs-gcp.audit-* | WHERE gcp.audit.method_name LIKE "*iam*" OR gcp.audit.method_name LIKE "*SetIamPolicy*" | STATS count=COUNT() BY gcp.audit.method_name, user.email' },
      { label: "Firewall changes", query: 'FROM logs-gcp.audit-* | WHERE gcp.audit.method_name LIKE "*firewall*" | STATS count=COUNT() BY gcp.audit.method_name, source.ip' },
      { label: "Anti-forensics", query: 'FROM logs-gcp.audit-* | WHERE gcp.audit.method_name LIKE "*DeleteSink*" OR gcp.audit.method_name LIKE "*StopLogging*" | STATS count=COUNT() BY gcp.audit.method_name, user.email' },
    ],
    outcome: "Project acme-prod-293847 shows a compromised service account. Initial SA key created by a legitimate user, then attacker IP takes over — modifies IAM to allow allUsers, opens SSH firewall, deletes audit log sink, makes customer data bucket public. Two distinct source IPs visible in the audit trail.",
  },
  {
    id: "cloudflare-waf-threats",
    name: "Cloudflare WAF & Security",
    desc: "SQL injection, XSS, credential stuffing, path traversal, L7 DDoS, bot traffic — all blocked/challenged by WAF",
    icon: "\u{1F525}",
    tags: ["T1190 Exploit Public App", "T1110.004 Credential Stuffing", "T1498 DDoS"],
    severity: "high",
    eventSources: [
      { index: "logs-cloudflare.logpush-*", label: "WAF block/challenge/drop events with rule IDs" },
      { index: "logs-cloudflare.logpush-*", label: "Bot score analysis (score 0-100)" },
      { index: "logs-cloudflare.logpush-*", label: "Rate limiting and DDoS mitigation events" },
    ],
    alerts: [
      { rule: "Cloudflare - SQL Injection Blocked", severity: "high" },
      { rule: "Cloudflare - Credential Stuffing Attack", severity: "high" },
      { rule: "Cloudflare - DDoS Attack Mitigated", severity: "high" },
      { rule: "Cloudflare - Path Traversal Attempt", severity: "high" },
    ],
    hunts: [
      { label: "WAF blocks by rule", query: 'FROM logs-cloudflare.logpush-* | WHERE cloudflare.action == "block" | STATS count=COUNT() BY cloudflare.rule_message, source.ip' },
      { label: "Bot traffic", query: 'FROM logs-cloudflare.logpush-* | WHERE cloudflare.bot.score < 10 | STATS count=COUNT() BY cloudflare.bot.score, source.ip, url.path' },
      { label: "Credential stuffing", query: 'FROM logs-cloudflare.logpush-* | WHERE url.path LIKE "*/login*" AND cloudflare.action != "allow" | STATS count=COUNT() BY source.ip, cloudflare.action' },
    ],
    outcome: "app.acmecorp.com under active attack from 3 IPs. SQLi and path traversal blocked, credential stuffing challenged, DDoS traffic dropped. Bot scores near 0 for all attack traffic. Legitimate traffic (score 95) from US IP passes through. Cloudflare ray IDs link each event to the edge log.",
  },
  {
    id: "github-audit-events",
    name: "GitHub Audit Events",
    desc: "Compromised contractor: repo made public, deploy key added, admin invite, secret alert dismissed, fork workflow dispatch",
    icon: "\u{1F419}",
    tags: ["T1567 Exfil via Web", "T1098.001 Cloud Creds", "T1195.002 Supply Chain"],
    severity: "critical",
    eventSources: [
      { index: "logs-github.audit-*", label: "Repository visibility changes, deploy keys, branch protection overrides" },
      { index: "logs-github.audit-*", label: "Organization membership and role changes" },
      { index: "logs-github.audit-*", label: "Secret scanning alerts, workflow dispatches, PAT creation" },
    ],
    alerts: [
      { rule: "GitHub - Repository Visibility Changed to Public", severity: "critical" },
      { rule: "GitHub - Deploy Key Added to Repository", severity: "high" },
      { rule: "GitHub - Organization Member Invited with Admin Role", severity: "high" },
      { rule: "GitHub - Secrets Scanning Alert Dismissed", severity: "high" },
      { rule: "GitHub - Workflow Dispatch from Fork", severity: "high" },
    ],
    hunts: [
      { label: "Visibility changes", query: 'FROM logs-github.audit-* | WHERE event.action == "repo.access" | STATS count=COUNT() BY github.repo, github.actor, github.visibility' },
      { label: "Suspicious actor activity", query: 'FROM logs-github.audit-* | WHERE github.actor == "dev-contractor-42" | STATS count=COUNT() BY event.action, github.repo' },
      { label: "Supply chain risks", query: 'FROM logs-github.audit-* | WHERE event.action LIKE "*workflow*" OR event.action LIKE "*deploy_key*" | STATS count=COUNT() BY event.action, github.actor' },
    ],
    outcome: "dev-contractor-42 compromised in acmecorp org. Payment-service repo made public (source code leak), deploy key with write access added, external user invited as admin. Secret scanning alert dismissed to hide exposed credentials. Fork-triggered CI workflow indicates potential supply chain attack vector.",
  },
  {
    id: "docker-container-events",
    name: "Docker Container Events",
    desc: "Privileged container with host mount, container escape via nsenter, untrusted registry pull, host network mode",
    icon: "\u{1F40B}",
    tags: ["T1611 Escape to Host", "T1195.002 Supply Chain", "T1059 Execution"],
    severity: "critical",
    eventSources: [
      { index: "logs-docker.events-*", label: "Container lifecycle events (create, start, die, exec)" },
      { index: "logs-docker.events-*", label: "Image pull events from registries" },
      { index: "logs-docker.events-*", label: "Network mode and volume mount configurations" },
    ],
    alerts: [
      { rule: "Docker - Image Pulled from Untrusted Registry", severity: "high" },
      { rule: "Docker - Privileged Container Started", severity: "critical" },
      { rule: "Docker - Container Escape via Mount", severity: "critical" },
      { rule: "Docker - Container Running as Root", severity: "high" },
      { rule: "Docker - Network Mode Host Detected", severity: "high" },
    ],
    hunts: [
      { label: "Privileged containers", query: 'FROM logs-docker.events-* | WHERE docker.attrs.privileged == "true" | STATS count=COUNT() BY container.name, container.image.name' },
      { label: "Host mounts", query: 'FROM logs-docker.events-* | WHERE docker.attrs.binds LIKE "*/host*" | STATS count=COUNT() BY container.name, docker.attrs.binds' },
      { label: "Untrusted images", query: 'FROM logs-docker.events-* | WHERE event.action == "pull" AND NOT docker.attrs.name LIKE "*docker.io*" | STATS count=COUNT() BY docker.attrs.name' },
    ],
    outcome: "docker-host-prod-01 shows a crypto-mining attack. evil-registry.io/crypto-miner pulled, started as privileged with /:/host:rw mount (full host filesystem access). Root exec runs nsenter to escape container into host namespace. Host network mode gives unrestricted network access. Legitimate nginx container was killed (exit 137).",
  },
  {
    id: "kubernetes-audit",
    name: "Kubernetes Audit",
    desc: "Secrets theft, hostPID pod escape, cluster-admin binding, kube-system ConfigMap tampering, pod exec",
    icon: "\u{2638}\u{FE0F}",
    tags: ["T1552.007 Container API", "T1611 Escape to Host", "T1609 Container Admin"],
    severity: "critical",
    eventSources: [
      { index: "logs-kubernetes.audit-*", label: "K8s API audit events (secrets, pods, clusterrolebindings, configmaps)" },
    ],
    alerts: [
      { rule: "K8s - Secrets Accessed by Service Account", severity: "high" },
      { rule: "K8s - Pod Created with hostPID", severity: "critical" },
      { rule: "K8s - ClusterRoleBinding to cluster-admin", severity: "critical" },
      { rule: "K8s - ConfigMap Modified in kube-system", severity: "high" },
      { rule: "K8s - Exec into Running Pod", severity: "medium" },
    ],
    hunts: [
      { label: "Secrets access", query: 'FROM logs-kubernetes.audit-* | WHERE kubernetes.audit.objectRef.resource == "secrets" | STATS count=COUNT() BY user.name, kubernetes.audit.objectRef.namespace, kubernetes.audit.objectRef.name' },
      { label: "Privilege escalation", query: 'FROM logs-kubernetes.audit-* | WHERE kubernetes.audit.objectRef.resource IN ("clusterrolebindings", "clusterroles") | STATS count=COUNT() BY kubernetes.audit.verb, user.name' },
      { label: "Container exec", query: 'FROM logs-kubernetes.audit-* | WHERE kubernetes.audit.objectRef.subresource == "exec" | STATS count=COUNT() BY user.name, kubernetes.audit.objectRef.namespace' },
    ],
    outcome: "Cluster prod-us-east-1 compromised via service account default:compromised-sa. Attacker reads production secrets, creates hostPID pod for host escape, binds to cluster-admin for full privileges, patches CoreDNS for DNS manipulation, creates backdoor SA in kube-system, and deletes events to cover tracks.",
  },
  {
    id: "messy-custom-log",
    name: "Messy Custom Log",
    desc: "Intentionally inconsistent real-world logs: mixed formats (syslog, JSON, plaintext), inconsistent fields, NullPointerExceptions, OOMKills, iptables drops",
    icon: "\u{1F4DC}",
    tags: ["Custom Ingestion", "Mixed Formats", "Real-World Noise"],
    severity: "medium",
    eventSources: [
      { index: "logs-custom.messy-*", label: "Mixed-format logs: syslog, JSON, key=value, plaintext from 4 hosts" },
    ],
    alerts: [
      { rule: "Custom Log - High Error Rate Burst", severity: "high" },
      { rule: "Custom Log - Anomalous Field Pattern", severity: "medium" },
    ],
    hunts: [
      { label: "Error patterns", query: 'FROM logs-custom.messy-* | WHERE log.level IN ("error", "ERROR", "CRITICAL", "fatal") | STATS count=COUNT() BY log.level, host.name' },
      { label: "Log sources", query: 'FROM logs-custom.messy-* | STATS count=COUNT() BY log.logger, host.name | SORT count DESC' },
      { label: "Network drops", query: 'FROM logs-custom.messy-* | WHERE message LIKE "*DROP*" OR message LIKE "*firewall*" | STATS count=COUNT() BY host.name' },
    ],
    outcome: "Tests parser robustness and log normalization. Events come from 4 hosts with inconsistent naming (legacy-app-srv, BILLING_SYS_02, monitor.internal, app-node-east-3). Mix of syslog, structured JSON, key=value, and raw plaintext. Includes Java stack traces, OOMKilled container events, iptables drops, SSL cert warnings, and database exports. Some fields are flat, some nested, some both.",
  },
];

interface GenerateResult {
  indexed: number;
  scenario: string;
  indices: string[];
}

type Phase = "select" | "generating" | "done" | "error";
type SeverityFilter = "all" | "critical" | "high" | "medium";

const SEVERITY_LABEL: Record<"critical" | "high" | "medium" | "low", string> = {
  critical: "Critical", high: "High", medium: "Medium", low: "Low",
};

const SEVERITY_FILTERS: { key: SeverityFilter; label: string }[] = [
  { key: "all", label: "All" },
  { key: "critical", label: "Critical" },
  { key: "high", label: "High" },
  { key: "medium", label: "Medium" },
];

const AppGlyph = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
    <path d="M23.9506 12.4984C23.9527 11.5265 23.6542 10.5777 23.0961 9.78204C22.538 8.98635 21.7475 8.38267 20.8329 8.05369C20.9165 7.62975 20.9586 7.19872 20.9588 6.76664C20.9593 5.33599 20.5061 3.94206 19.6645 2.78515C18.8228 1.62826 17.6361 0.767973 16.2748 0.327936C14.9135 -0.112099 13.4478 -0.109226 12.0882 0.336144C10.7287 0.781513 9.54534 1.64645 8.70826 2.80664C8.09097 2.32848 7.33466 2.06452 6.55389 2.05472C5.77314 2.04491 5.01045 2.2898 4.38134 2.75229C3.75222 3.21479 3.29095 3.86969 3.0674 4.61782C2.84384 5.36595 2.87015 6.16656 3.14238 6.8984C2.22542 7.23206 1.43269 7.83861 0.870884 8.63641C0.309073 9.43422 0.00515049 10.385 2.34805e-05 11.3608C-0.00305405 12.3366 0.296461 13.2893 0.857326 14.0879C1.41819 14.8864 2.21282 15.4914 3.13179 15.8195C3.05214 16.2435 3.01275 16.6741 3.01414 17.1054C3.01158 18.5358 3.46368 19.9298 4.30518 21.0864C5.14666 22.2429 6.33397 23.1021 7.69564 23.5398C9.05729 23.9775 10.5228 23.9711 11.8806 23.5214C13.2384 23.0718 14.4181 22.2022 15.2494 21.0384C15.8649 21.5186 16.6204 21.7849 17.4009 21.7969C18.1815 21.8089 18.9447 21.566 19.5747 21.1049C20.2047 20.6438 20.6669 19.9898 20.8915 19.242C21.1161 18.4944 21.0906 17.6938 20.8188 16.9619C21.734 16.6265 22.5246 16.0189 23.0845 15.2211C23.6442 14.4232 23.9465 13.4731 23.9506 12.4984ZM9.27296 3.52899C10.0442 2.40726 11.1788 1.586 12.4853 1.20381C13.7919 0.821635 15.1902 0.901957 16.4444 1.43121C17.6986 1.96048 18.7316 2.90626 19.3694 4.10891C20.0071 5.31156 20.2104 6.69741 19.9447 8.03252L14.6576 12.6631L9.41649 10.2749L8.39297 8.09017L9.27296 3.52899ZM6.62238 2.94075C7.24393 2.94062 7.84828 3.14484 8.34238 3.52193L7.54943 7.60311L3.95885 6.75487C3.80314 6.32609 3.75287 5.86614 3.81229 5.41386C3.87172 4.96158 4.03908 4.53022 4.30026 4.15621C4.56145 3.78221 4.90878 3.47653 5.31293 3.26499C5.71708 3.05344 6.1662 2.94224 6.62238 2.94075ZM0.925906 11.3713C0.931192 10.5387 1.19621 9.72838 1.68401 9.05351C2.17182 8.37865 2.85807 7.87284 3.64708 7.60664L7.58826 8.53722L8.51296 10.5149L3.47414 15.0725C2.72441 14.7865 2.07928 14.2793 1.62421 13.6184C1.16915 12.9574 0.925627 12.1738 0.925906 11.3713ZM14.7012 20.3348C13.9892 21.3831 12.9599 22.1753 11.7643 22.5953C10.5688 23.0152 9.27013 23.0407 8.05905 22.668C6.84795 22.2953 5.78828 21.5441 5.03568 20.5247C4.28307 19.5053 3.8772 18.2714 3.87767 17.0042C3.87822 16.6092 3.91764 16.2152 3.99532 15.8278L9.14826 11.1643L14.4094 13.5619L15.5741 15.7878L14.7012 20.3348ZM17.3341 20.9231C16.7144 20.9209 16.1126 20.7142 15.6224 20.3348L16.4035 16.2666L19.9918 17.1054C20.1479 17.5339 20.1986 17.9934 20.1396 18.4455C20.0808 18.8976 19.914 19.3289 19.6534 19.7031C19.3928 20.0772 19.0461 20.3831 18.6425 20.5951C18.2388 20.8069 17.79 20.9187 17.3341 20.9207V20.9231ZM20.3035 16.2513L16.3529 15.3278L15.3035 13.3278L20.4706 8.80075C21.2209 9.08447 21.8672 9.58986 22.3234 10.2497C22.7796 10.9096 23.0242 11.6926 23.0247 12.4948C23.0173 13.3258 22.7512 14.1336 22.2635 14.8065C21.7759 15.4792 21.0908 15.9834 20.3035 16.2489V16.2513Z" fill="currentColor"/>
  </svg>
);

function SeverityChip({ severity }: { severity: "critical" | "high" | "medium" | "low" }) {
  return (
    <span className={`sev-chip sev-chip-${severity}`}>
      <span className="sev-chip-dot" />
      <span className="sev-chip-label">{SEVERITY_LABEL[severity]}</span>
    </span>
  );
}

export function App() {
  const appRef = useRef<McpApp | null>(null);
  const [connected, setConnected] = useState(false);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [expanded, setExpanded] = useState<string | null>(null);
  const [count, setCount] = useState(50);
  const [createRulesEnabled, setCreateRulesEnabled] = useState(true);
  const [phase, setPhase] = useState<Phase>("select");
  const [results, setResults] = useState<GenerateResult[]>([]);
  const [currentScenario, setCurrentScenario] = useState<string | null>(null);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [cleanupCount, setCleanupCount] = useState<number | null>(null);
  const [rulesCreated, setRulesCreated] = useState(0);
  const [existingData, setExistingData] = useState<{ totalDocs: number; totalAlerts: number; existingRules: number; byScenario: Record<string, { events: number; alerts: number }> } | null>(null);
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("all");
  const [searchInput, setSearchInput] = useState("");

  const loadExistingData = useCallback(async (app: McpApp) => {
    try {
      const toolResult = await app.callServerTool({ name: "check-existing-sample-data", arguments: {} });
      const text = extractCallResult(toolResult);
      if (text) setExistingData(JSON.parse(text));
    } catch { /* cluster might not be reachable */ }
  }, []);

  useEffect(() => {
    const app = new McpApp({ name: "sample-data", version: "1.0.0" });
    appRef.current = app;
    applyTheme(app);

    app.ontoolresult = (toolResult) => {
      try {
        const text = extractCallResult(toolResult);
        if (text) {
          const data = JSON.parse(text);
          if (data.indexed !== undefined) {
            setResults((prev) => [...prev, data]);
          }
        }
      } catch { /* ignore */ }
    };

    app.connect().then(() => {
      setConnected(true);
      loadExistingData(app);
    });
    return () => { app.close(); };
  }, [loadExistingData]);

  const toggleScenario = useCallback((id: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  const filteredScenarios = useMemo(() => {
    const q = searchInput.trim().toLowerCase();
    return SCENARIOS.filter((s) => {
      if (severityFilter !== "all" && s.severity !== severityFilter) return false;
      if (q) {
        const hay = `${s.name} ${s.desc} ${s.tags.join(" ")}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [severityFilter, searchInput]);

  const selectAll = useCallback(() => {
    if (selected.size === filteredScenarios.length) setSelected(new Set());
    else setSelected(new Set(filteredScenarios.map((s) => s.id)));
  }, [selected.size, filteredScenarios]);

  const generate = async () => {
    if (!appRef.current || selected.size === 0) return;
    setPhase("generating");
    setResults([]);
    setErrorMsg(null);
    setRulesCreated(0);
    setStatusMessage(null);

    const scenarios = [...selected];

    try {
      if (createRulesEnabled) {
        let ruleTotal = 0;
        for (const scenario of scenarios) {
          setStatusMessage(`Creating rules for ${SCENARIOS.find((s) => s.id === scenario)?.name || scenario}...`);
          try {
            const toolResult = await appRef.current.callServerTool({
              name: "create-rules-for-scenario",
              arguments: { scenario },
            });
            const text = extractCallResult(toolResult);
            if (text) {
              const data = JSON.parse(text);
              ruleTotal += data.created || 0;
            }
          } catch { /* some scenarios may not have rules */ }
        }
        setRulesCreated(ruleTotal);
      }

      for (const scenario of scenarios) {
        setCurrentScenario(scenario);
        setStatusMessage(null);
        const toolResult = await appRef.current.callServerTool({
          name: "generate-scenario",
          arguments: { scenario, count },
        });
        const text = extractCallResult(toolResult);
        if (text) {
          setResults((prev) => [...prev, JSON.parse(text)]);
        }
      }
      setPhase("done");
      if (appRef.current) loadExistingData(appRef.current);
    } catch (e) {
      setErrorMsg(e instanceof Error ? e.message : String(e));
      setPhase("error");
    }
    setCurrentScenario(null);
    setStatusMessage(null);
  };

  const cleanup = async () => {
    if (!appRef.current) return;
    setPhase("generating");
    setCurrentScenario("cleanup");
    setCleanupCount(null);
    try {
      const toolResult = await appRef.current.callServerTool({
        name: "cleanup-sample-data",
        arguments: {},
      });
      const text = extractCallResult(toolResult);
      if (text) {
        const data = JSON.parse(text);
        setCleanupCount(data.deleted ?? 0);
      }
      setPhase("done");
      if (appRef.current) loadExistingData(appRef.current);
    } catch (e) {
      setErrorMsg(e instanceof Error ? e.message : String(e));
      setPhase("error");
    }
    setCurrentScenario(null);
  };

  const runAttackDiscovery = async () => {
    if (!appRef.current) return;
    await appRef.current.sendMessage({
      role: "user",
      content: [{ type: "text", text: "Run attack discovery on the alerts that were just generated. Use the triage-attack-discoveries tool." }],
    });
  };

  const reset = () => {
    setPhase("select");
    setResults([]);
    setErrorMsg(null);
    setCleanupCount(null);
    setRulesCreated(0);
    setStatusMessage(null);
  };

  if (!connected) {
    return (
      <div className="loading-state">
        <div className="loading-spinner" />
        <span>Connecting to server...</span>
      </div>
    );
  }

  const totalIndexed = results.reduce((sum, r) => sum + r.indexed, 0);

  return (
    <div className="sample-app">
      <header className="sample-header">
        <div className="sample-header-left">
          <div className="sample-header-brand">
            <span className="sample-header-glyph" aria-hidden="true"><AppGlyph /></span>
            <h1 className="sample-header-title">Sample Data Generator</h1>
          </div>
        </div>
      </header>

      {phase === "select" && (
        <div className="sample-body">
          {existingData && existingData.totalDocs > 0 && (
            <div className="existing-banner">
              <span className="existing-banner-dot" />
              <span className="existing-banner-text">
                <strong>{existingData.totalDocs.toLocaleString()}</strong> existing sample docs · {existingData.totalAlerts} alerts · {existingData.existingRules} rules from a previous generation
              </span>
              <button className="btn btn-sm btn-ghost" onClick={cleanup}>Cleanup</button>
            </div>
          )}

          <div className="sample-toolbar">
            <div className="sample-severity-tabs" role="tablist">
              {SEVERITY_FILTERS.map((f) => {
                const count = f.key === "all"
                  ? SCENARIOS.length
                  : SCENARIOS.filter((s) => s.severity === f.key).length;
                return (
                  <button
                    key={f.key}
                    role="tab"
                    aria-selected={severityFilter === f.key}
                    className={`sample-severity-tab${severityFilter === f.key ? " active" : ""}`}
                    onClick={() => setSeverityFilter(f.key)}
                  >
                    <span>{f.label}</span>
                    <span className="sample-severity-tab-count">{count}</span>
                  </button>
                );
              })}
            </div>
            <div className="sample-toolbar-search">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><circle cx="11" cy="11" r="7" /><path d="m21 21-4.35-4.35" /></svg>
              <input
                type="text"
                placeholder="Filter scenarios..."
                value={searchInput}
                onChange={(e) => setSearchInput(e.target.value)}
              />
            </div>
            <button className="btn btn-sm btn-ghost" onClick={selectAll}>
              {selected.size === filteredScenarios.length && filteredScenarios.length > 0 ? "Deselect all" : "Select all"}
            </button>
          </div>

          <div className="scenario-grid">
            {filteredScenarios.map((s) => (
              <div key={s.id} className="scenario-cell">
                <button
                  className={`scenario-card sev-${s.severity}${selected.has(s.id) ? " selected" : ""}`}
                  onClick={() => toggleScenario(s.id)}
                >
                  <div className="scenario-card-head">
                    <div className={`scenario-card-check${selected.has(s.id) ? " checked" : ""}`}>
                      {selected.has(s.id) && <span>✓</span>}
                    </div>
                    <span className="scenario-card-icon">{s.icon}</span>
                    <SeverityChip severity={s.severity} />
                  </div>
                  <div className="scenario-card-name">{s.name}</div>
                  <div className="scenario-card-desc">{s.desc}</div>
                  <div className="scenario-card-tags">
                    {s.tags.map((t) => <span key={t} className="scenario-mitre-pill">{t}</span>)}
                  </div>
                  <div className="scenario-card-footer">
                    <div className="scenario-card-meta">
                      {existingData?.byScenario[s.id] ? (
                        <span className="scenario-card-meta-item existing">
                          <span className="dot" />
                          {existingData.byScenario[s.id].events} docs exist
                        </span>
                      ) : (
                        <>
                          <span className="scenario-card-meta-item">{s.eventSources.length} sources</span>
                          <span className="scenario-card-meta-item">{s.alerts.length} alerts</span>
                        </>
                      )}
                    </div>
                    <button
                      type="button"
                      className="scenario-card-details-btn"
                      onClick={(e) => { e.stopPropagation(); setExpanded(expanded === s.id ? null : s.id); }}
                    >
                      {expanded === s.id ? "Hide" : "Details"}
                    </button>
                  </div>
                </button>

                {expanded === s.id && (
                  <div className="scenario-detail-panel">
                    <div className="scenario-detail-section">
                      <div className="scenario-detail-section-title">Events Generated</div>
                      <div className="scenario-detail-list">
                        {s.eventSources.map((es, i) => (
                          <div key={i} className="scenario-detail-row">
                            <span className="scenario-detail-index">{es.index}</span>
                            <span className="scenario-detail-label">{es.label}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                    <div className="scenario-detail-section">
                      <div className="scenario-detail-section-title">Alerts ({s.alerts.length})</div>
                      <div className="scenario-detail-list">
                        {s.alerts.map((a, i) => (
                          <div key={i} className="scenario-detail-row">
                            <SeverityChip severity={a.severity} />
                            <span className="scenario-detail-label">{a.rule}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                    <div className="scenario-detail-section">
                      <div className="scenario-detail-section-title">Expected Outcome</div>
                      <p className="scenario-detail-outcome">{s.outcome}</p>
                    </div>
                  </div>
                )}
              </div>
            ))}
            {filteredScenarios.length === 0 && (
              <div className="empty-state" style={{ gridColumn: "1 / -1" }}>
                <div style={{ fontSize: 28, marginBottom: 8 }}>🔍</div>
                <div>No scenarios match your filters</div>
              </div>
            )}
          </div>

          {/* Floating action bar: inline event-count stepper + detection-rule
              toggle + the primary Generate CTA. The "Cleanup existing" ghost
              button was removed from here — the same action still lives in the
              top-of-body banner when previous sample docs are detected. */}
          <div className="sample-action-bar">
            <div className="action-bar-setting">
              <span className="action-bar-label">Events</span>
              <div className="action-bar-stepper">
                <button className="stepper-btn" onClick={() => setCount((c) => Math.max(10, c - 10))} aria-label="Decrement">−</button>
                <input
                  type="number"
                  value={count}
                  onChange={(e) => setCount(Math.max(10, Math.min(1000, parseInt(e.target.value) || 50)))}
                  min={10}
                  max={1000}
                  aria-label="Events per scenario"
                />
                <button className="stepper-btn" onClick={() => setCount((c) => Math.min(1000, c + 10))} aria-label="Increment">+</button>
              </div>
            </div>

            <div className="action-bar-divider" aria-hidden="true" />

            <div className="action-bar-setting">
              <span className="action-bar-label">Rules</span>
              <button
                type="button"
                role="switch"
                aria-checked={createRulesEnabled}
                aria-label="Create detection rules"
                className={`toggle-switch${createRulesEnabled ? " on" : ""}`}
                onClick={() => setCreateRulesEnabled((v) => !v)}
              >
                <span className="toggle-switch-thumb" />
              </button>
            </div>

            <div className="action-bar-divider" aria-hidden="true" />

            <button
              className="btn btn-sm btn-primary"
              onClick={generate}
              disabled={selected.size === 0}
            >
              Generate {selected.size === filteredScenarios.length && filteredScenarios.length === SCENARIOS.length ? "all" : selected.size} scenario{selected.size !== 1 ? "s" : ""}
              <span className="btn-detail">≈ {(selected.size * count).toLocaleString()} events{createRulesEnabled ? " + rules" : ""}</span>
            </button>
          </div>
        </div>
      )}

      {phase === "generating" && (
        <div className="sample-body">
          <div className="progress-panel">
            <div className="progress-header">
              <div className="loading-spinner" />
              <span>{currentScenario === "cleanup" ? "Cleaning up sample data..." : statusMessage || "Generating security events..."}</span>
            </div>
            {currentScenario && currentScenario !== "cleanup" && (
              <div className="progress-current">
                <span style={{ fontSize: 18 }}>{SCENARIOS.find((s) => s.id === currentScenario)?.icon || "⚙️"}</span>
                <span>{SCENARIOS.find((s) => s.id === currentScenario)?.name || currentScenario}</span>
              </div>
            )}
            {rulesCreated > 0 && results.length === 0 && (
              <div className="progress-result-row">
                <span className="progress-check">✓</span>
                <span>Created {rulesCreated} detection rules</span>
              </div>
            )}
            {results.length > 0 && (
              <div className="progress-results">
                {results.map((r, i) => (
                  <div key={i} className="progress-result-row">
                    <span className="progress-check">✓</span>
                    <span className="progress-result-name">{SCENARIOS.find((s) => s.id === r.scenario)?.name || r.scenario}</span>
                    <span className="progress-count">{r.indexed} docs</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {phase === "done" && (
        <div className="sample-body">
          <div className="done-panel">
            {cleanupCount !== null ? (
              <>
                <div className="done-header-row">
                  <span className="done-header-icon done-header-icon-cleanup">🗑</span>
                  <div>
                    <div className="done-title">Cleanup Complete</div>
                    <div className="done-subtitle">{cleanupCount.toLocaleString()} documents removed</div>
                  </div>
                </div>
                <div className="done-footer">
                  <button className="btn btn-sm btn-primary" onClick={reset}>Back</button>
                </div>
              </>
            ) : (
              <>
                <div className="done-header-row">
                  <span className="done-header-icon">✓</span>
                  <div>
                    <div className="done-title">{totalIndexed.toLocaleString()} documents across {results.length} scenarios</div>
                    {rulesCreated > 0 && (
                      <div className="done-subtitle">{rulesCreated} detection rules created (disabled)</div>
                    )}
                  </div>
                </div>

                <div className="done-scenarios">
                  {results.map((r, i) => {
                    const s = SCENARIOS.find((sc) => sc.id === r.scenario);
                    return (
                      <div key={i} className="done-scenario-card">
                        <div className="done-scenario-header">
                          <span style={{ fontSize: 16 }}>{s?.icon || "📊"}</span>
                          <span className="done-scenario-name">{s?.name || r.scenario}</span>
                          <span className="done-scenario-count">{r.indexed}</span>
                        </div>
                        {s && s.hunts.length > 0 && (
                          <div className="done-hunts">
                            {s.hunts.map((h, j) => (
                              <button
                                key={j}
                                className="hunt-btn"
                                onClick={async () => {
                                  if (!appRef.current) return;
                                  await appRef.current.sendMessage({
                                    role: "user",
                                    content: [{ type: "text", text: `Run this threat hunt query using the threat-hunt tool:\n\n${h.query}` }],
                                  });
                                }}
                              >
                                <span className="hunt-btn-icon">🔍</span> {h.label}
                              </button>
                            ))}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>

                <div className="done-next-steps">
                  <div className="done-next-title">Next Steps</div>
                  <div className="done-next-actions">
                    <button className="btn btn-sm btn-primary" onClick={runAttackDiscovery}>
                      Run Attack Discovery
                    </button>
                    <button className="btn btn-sm btn-ghost" onClick={async () => {
                      if (!appRef.current) return;
                      await appRef.current.sendMessage({
                        role: "user",
                        content: [{ type: "text", text: "Show me the security alerts that were just generated. Use the triage-alerts tool." }],
                      });
                    }}>
                      Triage Alerts
                    </button>
                  </div>
                </div>

                <div className="done-footer">
                  <button className="btn btn-sm btn-ghost" onClick={reset}>Generate more</button>
                  <button className="btn btn-sm btn-ghost" onClick={cleanup}>Cleanup all</button>
                </div>
              </>
            )}
          </div>
        </div>
      )}

      {phase === "error" && (
        <div className="sample-body">
          <div className="error-panel">
            <div className="error-icon">⚠</div>
            <div className="error-title">Generation Failed</div>
            <div className="error-message">{errorMsg}</div>
            {results.length > 0 && (
              <div className="error-partial">
                Partial results: {totalIndexed} documents indexed from {results.length} scenario(s)
              </div>
            )}
            <button className="btn btn-sm btn-primary" onClick={reset}>Try Again</button>
          </div>
        </div>
      )}
    </div>
  );
}
