use serde::{Serialize, Deserialize};
use std::sync::LazyLock;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Technique {
    pub id: String,
    pub name: String,
    pub description: String,
    pub tactics: Vec<String>,
    pub platforms: Vec<String>,
    pub data_sources: Vec<String>,
    pub mitigation: Option<String>,
    pub detection: String,
    pub sub_techniques: Vec<Technique>,
}

fn t(
    id: &str, name: &str, desc: &str,
    tactics: &[&str], platforms: &[&str],
    data_sources: &[&str], mitigation: Option<&str>,
    detection: &str,
) -> Technique {
    Technique {
        id: id.to_string(),
        name: name.to_string(),
        description: desc.to_string(),
        tactics: tactics.iter().map(|s| s.to_string()).collect(),
        platforms: platforms.iter().map(|s| s.to_string()).collect(),
        data_sources: data_sources.iter().map(|s| s.to_string()).collect(),
        mitigation: mitigation.map(|s| s.to_string()),
        detection: detection.to_string(),
        sub_techniques: vec![],
    }
}

static TECHNIQUE_DB: LazyLock<Vec<Technique>> = LazyLock::new(|| vec![
    // =========================================================================
    // TA0043 Reconnaissance
    // =========================================================================
    t("T1595", "Active Scanning", "Adversaries may execute active scans of victim infrastructure to gather information",
        &["TA0043"], &["PRE"], &["Network Traffic", "Scan Logs"], None,
        "Monitor for port scans, vulnerability scans, and directory brute-force activity"),
    t("T1592", "Gather Victim Host Information", "Adversaries may gather information about the hosts of compromised systems",
        &["TA0043"], &["PRE"], &["Third-Party Intelligence"], None,
        "Harden externally facing services; limit information disclosure"),
    t("T1589", "Gather Victim Identity Information", "Adversaries may gather information about the identities of victims",
        &["TA0043"], &["PRE"], &["Third-Party Intelligence"], None,
        "Monitor for unauthorized data harvesting of employee information"),
    t("T1590", "Gather Victim Network Information", "Adversaries may gather information about the victim networks",
        &["TA0043"], &["PRE"], &["Third-Party Intelligence"], None,
        "Restrict public exposure of network topology details"),
    t("T1591", "Gather Victim Org Information", "Adversaries may gather information about the victim organization",
        &["TA0043"], &["PRE"], &["Third-Party Intelligence"], None,
        "Limit public disclosure of organizational structure and relationships"),
    t("T1598", "Phishing for Information", "Adversaries may send phishing messages to elicit sensitive information",
        &["TA0043"], &["PRE"], &["Email Gateway", "User Reports"], None,
        "Train users to recognize phishing attempts; implement email filtering"),
    t("T1597", "Search Closed Sources", "Adversaries may search closed sources for target information",
        &["TA0043"], &["PRE"], &["Third-Party Intelligence"], None,
        "Monitor for data exposure on dark web and paste sites"),
    t("T1596", "Search Open Technical Databases", "Adversaries may search freely available technical databases",
        &["TA0043"], &["PRE"], &["Third-Party Intelligence"], None,
        "Limit exposure of data in public databases and registries"),
    t("T1593", "Search Open Websites/Domains", "Adversaries may search open websites for information about victims",
        &["TA0043"], &["PRE"], &["Third-Party Intelligence"], None,
        "Monitor for unauthorized data scraping from public web properties"),
    t("T1594", "Search Victim-Owned Websites", "Adversaries may search websites owned by the victim for information",
        &["TA0043"], &["PRE"], &["Third-Party Intelligence"], None,
        "Review web properties for unintended information disclosure"),
    // =========================================================================
    // TA0042 Resource Development
    // =========================================================================
    t("T1583", "Acquire Infrastructure", "Adversaries may buy, lease, or rent infrastructure to support operations",
        &["TA0042"], &["PRE"], &["Threat Intelligence"], None,
        "Monitor for newly registered domains and infrastructure"),
    t("T1584", "Compromise Infrastructure", "Adversaries may compromise third-party infrastructure for operations",
        &["TA0042"], &["PRE"], &["Threat Intelligence"], None,
        "Monitor for abuse of trusted third-party services"),
    t("T1585", "Establish Accounts", "Adversaries may create and cultivate accounts for operations",
        &["TA0042"], &["PRE"], &["Threat Intelligence"], None,
        "Monitor for creation of fake social media and email accounts"),
    t("T1586", "Compromise Accounts", "Adversaries may compromise accounts to support operations",
        &["TA0042"], &["PRE"], &["Threat Intelligence"], None,
        "Monitor for compromised credential usage from unusual locations"),
    t("T1587", "Develop Capabilities", "Adversaries may build capabilities to support operations",
        &["TA0042"], &["PRE"], &["Threat Intelligence"], None,
        "Monitor for development and distribution of malware artifacts"),
    t("T1588", "Obtain Capabilities", "Adversaries may buy or steal capabilities to support operations",
        &["TA0042"], &["PRE"], &["Threat Intelligence"], None,
        "Monitor for purchases of offensive tools and exploits"),
    // =========================================================================
    // TA0001 Initial Access
    // =========================================================================
    t("T1189", "Drive-by Compromise", "Adversaries may gain initial access through drive-by compromises",
        &["TA0001"], &["Windows", "macOS", "Linux"], &["Network Traffic", "Web Proxy Logs"],
        Some("M1048 - Application Isolation and Sandboxing"),
        "Monitor web proxy and IDS logs for drive-by download activity"),
    t("T1190", "Exploit Public-Facing App", "Adversaries may exploit weaknesses in Internet-facing apps to gain access",
        &["TA0001"], &["Windows", "Linux"], &["Application Logs", "Network Traffic"],
        Some("M1048 - Application Isolation and Sandboxing"),
        "Monitor application logs for exploitation attempts and anomalies"),
    t("T1133", "External Remote Services", "Adversaries may leverage external remote services for initial access",
        &["TA0001"], &["Windows", "Linux", "Network"], &["Authentication Logs", "VPN Logs"],
        Some("M1035 - Limit Access to Resource Over Network"),
        "Monitor VPN and remote access logs for unusual authentication patterns"),
    t("T1200", "Hardware Additions", "Adversaries may introduce hardware components to gain initial access",
        &["TA0001"], &["Windows", "macOS"], &["Device Monitoring"],
        Some("M1034 - Limit Hardware Installation"),
        "Monitor for unauthorized USB and peripheral device connections"),
    t("T1566", "Phishing", "Adversaries may send phishing messages to gain access to victim systems",
        &["TA0001"], &["Windows", "macOS", "Linux"], &["Email Gateway", "User Reports"],
        Some("M1049 - Antivirus/Antimalware"),
        "Monitor email gateway for suspicious attachments and links"),
    t("T1195", "Supply Chain Compromise", "Adversaries may manipulate products prior to receipt by final consumer",
        &["TA0001"], &["Windows", "macOS", "Linux"], &["Code Signing", "Vendor Notifications"],
        Some("M1051 - Update Software"),
        "Monitor for unauthorized changes to software supply chain"),
    t("T1199", "Trusted Relationship", "Adversaries may breach trusted external parties to gain access",
        &["TA0001"], &["Windows", "macOS", "Linux"], &["Third-Party Logs", "Authentication Logs"],
        Some("M1030 - Network Segmentation"),
        "Segment network by third-party access; monitor cross-tenant activity"),
    t("T1078", "Valid Accounts", "Adversaries may obtain and abuse credentials of existing accounts",
        &["TA0001", "TA0004", "TA0005"], &["Windows", "macOS", "Linux", "Cloud"],
        &["Authentication Logs", "Access Logs"],
        Some("M1032 - Multi-factor Authentication"),
        "Monitor for unusual login patterns and impossible travel; enforce MFA"),
    t("T1137", "Office Application Startup", "Adversaries may abuse Microsoft Office for persistence and execution",
        &["TA0001", "TA0003"], &["Windows", "macOS"],
        &["Office Registry Keys", "Office Template Modifications"],
        Some("M1042 - Disable or Remove Feature or Program"),
        "Monitor Office startup folders, registry keys, and template modifications"),
    // =========================================================================
    // TA0002 Execution
    // =========================================================================
    t("T1059", "Command and Scripting Interpreter", "Adversaries may abuse command and script interpreters to execute",
        &["TA0002"], &["Windows", "macOS", "Linux"], &["Process Creation", "Command-Line Logging"],
        Some("M1049 - Antivirus/Antimalware"),
        "Monitor process creation and command-line arguments for suspicious interpreters"),
    t("T1047", "Windows Management Instrumentation", "Adversaries may abuse WMI to execute commands and payloads",
        &["TA0002"], &["Windows"], &["WMI Logs", "Process Creation"],
        Some("M1026 - Privileged Account Management"),
        "Monitor WMI event subscriptions and wmic.exe command-line usage"),
    t("T1203", "Exploitation for Client Execution", "Adversaries may exploit vulnerabilities in client apps to execute code",
        &["TA0002"], &["Windows", "macOS", "Linux"], &["Application Logs", "Crash Dumps"],
        Some("M1048 - Application Isolation and Sandboxing"),
        "Monitor application crashes and exploit prevention telemetry"),
    t("T1204", "User Execution", "Adversaries may rely on user actions like clicking links or opening files",
        &["TA0002"], &["Windows", "macOS", "Linux"], &["Process Creation", "User Behavior"],
        Some("M1031 - Network Intrusion Prevention"),
        "Implement application whitelisting and user awareness training"),
    t("T1053", "Scheduled Task/Job", "Adversaries may abuse task scheduling to facilitate execution",
        &["TA0002", "TA0003"], &["Windows", "macOS", "Linux"],
        &["Scheduled Task Logs", "Process Creation"],
        Some("M1026 - Privileged Account Management"),
        "Monitor creation and modification of scheduled tasks and cron jobs"),
    t("T1072", "Software Deployment Tools", "Adversaries may use third-party software suites for execution",
        &["TA0002", "TA0008"], &["Windows", "Linux", "Network"], &["SCCM Logs", "PDQ Logs"],
        Some("M1040 - Behavior Prevention on Endpoint"),
        "Monitor software deployment tool activity and access patterns"),
    t("T1569", "System Services", "Adversaries may abuse system services or daemons to execute commands",
        &["TA0002"], &["Windows", "Linux"], &["Service Creation Logs", "Process Creation"],
        Some("M1022 - Restrict File and Directory Permissions"),
        "Monitor service installation and service execution events"),
    // =========================================================================
    // TA0003 Persistence
    // =========================================================================
    t("T1098", "Account Manipulation", "Adversaries may manipulate accounts to maintain or elevate access",
        &["TA0003", "TA0004"], &["Windows", "Linux", "Cloud"],
        &["Authentication Logs", "AD Logs"],
        Some("M1032 - Multi-factor Authentication"),
        "Monitor for unauthorized changes to account permissions and group membership"),
    t("T1547", "Boot or Logon Autostart Execution", "Adversaries may configure settings to auto-execute during boot",
        &["TA0003", "TA0004"], &["Windows", "macOS", "Linux"],
        &["Registry Keys", "Startup Folder", "Login Items"],
        Some("M1024 - Restrict Registry Permissions"),
        "Monitor registry run keys, startup folders, and login item modifications"),
    t("T1136", "Create Account", "Adversaries may create an account to maintain access to victim systems",
        &["TA0003"], &["Windows", "Linux", "Cloud"],
        &["Account Creation Logs", "Authentication Logs"],
        Some("M1032 - Multi-factor Authentication"),
        "Monitor for new account creation especially with administrative privileges"),
    t("T1543", "Create or Modify System Process", "Adversaries may create or modify system processes to execute payloads",
        &["TA0003", "TA0004"], &["Windows", "Linux"],
        &["Service Creation Logs", "System Logs"],
        Some("M1022 - Restrict File and Directory Permissions"),
        "Monitor service and daemon creation and modification"),
    t("T1546", "Event Triggered Execution", "Adversaries may establish persistence via system mechanisms triggered by events",
        &["TA0003", "TA0004"], &["Windows", "macOS", "Linux"],
        &["WMI Logs", "Registry Keys"],
        Some("M1022 - Restrict File and Directory Permissions"),
        "Monitor for WMI event subscription, AppInit DLLs, and other event triggers"),
    t("T1176", "Browser Extensions", "Adversaries may abuse browser extensions for persistence and code execution",
        &["TA0003"], &["Windows", "macOS", "Linux"], &["Browser Extension Logs"],
        Some("M1042 - Disable or Remove Feature or Program"),
        "Monitor browser extension installations and permissions"),
    t("T1574", "Hijack Execution Flow", "Adversaries may abuse dynamic linker hijacking to redirect execution",
        &["TA0003", "TA0004", "TA0005"], &["Windows", "macOS", "Linux"],
        &["DLL Loads", "Library Preloads"],
        Some("M1013 - Application Developer Guidance"),
        "Monitor DLL search order hijacking and library preload modifications"),
    t("T1505", "Server Software Component", "Adversaries may abuse extensible features to persist on network components",
        &["TA0003"], &["Windows", "Linux", "Network"], &["IIS Logs", "Apache Logs"],
        Some("M1047 - Audit"),
        "Monitor for unauthorized web shells and server-side extensions"),
    t("T1542", "Pre-OS Boot", "Adversaries may abuse boot execution flow to execute payloads during boot",
        &["TA0003", "TA0005"], &["Windows"], &["Boot Logs", "BIOS/UEFI Logs"],
        Some("M1046 - Boot Integrity"),
        "Monitor for unauthorized boot configuration changes and rootkit installation"),
    t("T1548", "Abuse Elevation Control Mechanism", "Adversaries may circumvent mechanisms designed to control elevated privileges",
        &["TA0003", "TA0004", "TA0005"], &["Windows", "macOS", "Linux"],
        &["Process Creation", "UAC Logs"],
        Some("M1028 - Operating System Configuration"),
        "Monitor for UAC bypass attempts and sudo escalation patterns"),
    // =========================================================================
    // TA0004 Privilege Escalation
    // =========================================================================
    t("T1134", "Access Token Manipulation", "Adversaries may modify access tokens to hijack another session identity",
        &["TA0004", "TA0005"], &["Windows"],
        &["Token Manipulation Logs", "Process Creation"],
        Some("M1018 - User Account Management"),
        "Monitor for token theft and impersonation events via API monitoring"),
    t("T1068", "Exploitation for Privilege Escalation", "Adversaries may exploit software vulnerabilities to elevate privileges",
        &["TA0004"], &["Windows", "macOS", "Linux"],
        &["Crash Dumps", "Security Logs"],
        Some("M1048 - Application Isolation and Sandboxing"),
        "Monitor for unexpected privilege changes and exploit prevention alerts"),
    t("T1055", "Process Injection", "Adversaries may inject code into processes to evade defenses and elevate privileges",
        &["TA0004", "TA0005"], &["Windows", "macOS", "Linux"],
        &["Process Access Logs", "Memory Protection"],
        Some("M1040 - Behavior Prevention on Endpoint"),
        "Monitor for cross-process injection, DLL injection, and process hollowing"),
    t("T1484", "Domain Policy Modification", "Adversaries may modify domain configuration to compromise domain-wide policy",
        &["TA0004", "TA0005"], &["Windows", "Linux", "Cloud"],
        &["Group Policy Logs", "Domain Controller Logs"],
        Some("M1047 - Audit"),
        "Monitor GPO modifications and domain policy changes"),
    // =========================================================================
    // TA0005 Defense Evasion
    // =========================================================================
    t("T1562", "Impair Defenses", "Adversaries may modify victim environment to hinder defensive mechanisms",
        &["TA0005"], &["Windows", "macOS", "Linux"],
        &["Service State Logs", "Process Creation"],
        Some("M1022 - Restrict File and Directory Permissions"),
        "Monitor for disabling of security tools, firewall mods, and AMSI bypass"),
    t("T1140", "Deobfuscate/Decode Files", "Adversaries may use obfuscated files to hide intrusion artifacts",
        &["TA0005"], &["Windows", "macOS", "Linux"],
        &["Process Creation", "File Creation"], None,
        "Monitor for tools and commands that decode or deobfuscate files"),
    t("T1070", "Indicator Removal on Host", "Adversaries may delete or modify artifacts to remove evidence of presence",
        &["TA0005"], &["Windows", "macOS", "Linux"],
        &["File Deletion Logs", "Log Gaps"],
        Some("M1029 - Remote Data Storage"),
        "Implement remote logging and monitor for log clearing events"),
    t("T1027", "Obfuscated Files or Info", "Adversaries may make files difficult to analyze by encrypting or encoding them",
        &["TA0005"], &["Windows", "macOS", "Linux"],
        &["File Analysis", "Static Analysis"], None,
        "Monitor for Base64-encoded content and other obfuscation patterns"),
    t("T1218", "System Binary Proxy Execution", "Adversaries may proxy execution with a signed binary to bypass defenses",
        &["TA0005"], &["Windows"], &["Process Creation", "Module Loads"],
        Some("M1042 - Disable or Remove Feature or Program"),
        "Monitor for LOLBin abuse including mshta, regsvr32, and rundll32"),
    t("T1222", "File/Dir Permissions Modification", "Adversaries may modify file permissions to bypass access controls",
        &["TA0005"], &["Windows", "Linux"],
        &["File Permission Changes", "ACL Modifications"],
        Some("M1026 - Privileged Account Management"),
        "Monitor for changes to file and directory permissions and ACLs"),
    t("T1216", "System Script Proxy Execution", "Adversaries may bypass script defenses by proxying through signed binaries",
        &["TA0005"], &["Windows"], &["Script Block Logging", "Process Creation"], None,
        "Monitor for signed script host abuse like cscript/wscript execution"),
    t("T1553", "Subvert Trust Controls", "Adversaries may modify mechanisms that validate digital certificates",
        &["TA0005"], &["Windows", "macOS"],
        &["Certificate Store Logs", "Code Signing"],
        Some("M1042 - Disable or Remove Feature or Program"),
        "Monitor certificate store modifications and unsigned code execution"),
    t("T1036", "Masquerading", "Adversaries may manipulate artifact features to appear legitimate",
        &["TA0005"], &["Windows", "macOS", "Linux"],
        &["File Metadata", "Process Creation"],
        Some("M1022 - Restrict File and Directory Permissions"),
        "Monitor for files with mismatched names, extensions, and icon changes"),
    t("T1497", "Virtualization/Sandbox Evasion", "Adversaries may employ means to detect and avoid virtualization environments",
        &["TA0005", "TA0007"], &["Windows", "macOS", "Linux"],
        &["Process Creation", "API Calls"], None,
        "Monitor for fingerprinting behavior and anti-analysis checks"),
    t("T1480", "Execution Guardrails", "Adversaries may execute payloads with constraints to target specific environments",
        &["TA0005"], &["Windows", "macOS", "Linux"], &["Process Creation"], None,
        "Monitor for conditional execution patterns and environment checks"),
    // =========================================================================
    // TA0006 Credential Access
    // =========================================================================
    t("T1003", "OS Credential Dumping", "Adversaries may attempt to dump credentials from operating system storage",
        &["TA0006"], &["Windows", "macOS", "Linux"],
        &["Process Creation", "Sysmon Logs"],
        Some("M1043 - Credential Access Protection"),
        "Monitor for LSASS access, /etc/shadow reads, and credential dump tools"),
    t("T1110", "Brute Force", "Adversaries may use brute force techniques to gain access to accounts",
        &["TA0006"], &["Windows", "macOS", "Linux", "Cloud"],
        &["Authentication Logs"],
        Some("M1036 - Account Use Policies"),
        "Monitor for multiple failed authentication attempts and account lockouts"),
    t("T1557", "Adversary-in-the-Middle", "Adversaries may abuse AIAM attacks to intercept credentials and data",
        &["TA0006", "TA0009"], &["Windows", "macOS", "Linux"],
        &["Network Traffic", "ARP Cache"],
        Some("M1041 - Encrypt Sensitive Information"),
        "Monitor for ARP spoofing, LLMNR/NBT-NS poisoning, andDHCP spoofing"),
    t("T1555", "Credentials from Password Stores", "Adversaries may search for common password storage locations",
        &["TA0006"], &["Windows", "macOS", "Linux"],
        &["Process Creation", "API Calls"],
        Some("M1027 - Password Policies"),
        "Monitor access to password managers, credential vaults, and browsers"),
    t("T1528", "Steal Application Access Token", "Adversaries may steal OAuth tokens to gain access to cloud resources",
        &["TA0006"], &["Windows", "macOS", "Linux", "Cloud"],
        &["Authentication Logs", "Cloud Logs"],
        Some("M1027 - Password Policies"),
        "Monitor for unauthorized OAuth token usage and consent grants"),
    t("T1558", "Steal/Forge Kerberos Tickets", "Adversaries may steal or forge Kerberos tickets for lateral movement",
        &["TA0006"], &["Windows"], &["Kerberos Logs", "Authentication Logs"],
        Some("M1027 - Password Policies"),
        "Monitor for Kerberoasting, Golden Ticket, and Silver Ticket attacks"),
    t("T1552", "Unsecured Credentials", "Adversaries may search for credentials stored insecurely on systems",
        &["TA0006"], &["Windows", "macOS", "Linux"],
        &["File Access Logs", "Process Creation"], None,
        "Monitor for access to files containing credentials and configuration keys"),
    // =========================================================================
    // TA0007 Discovery
    // =========================================================================
    t("T1087", "Account Discovery", "Adversaries may attempt to get a listing of accounts on a system",
        &["TA0007"], &["Windows", "macOS", "Linux"],
        &["Process Creation", "Command-Line Logging"], None,
        "Monitor for commands that enumerate local and domain accounts"),
    t("T1082", "System Information Discovery", "Adversaries may attempt to get detailed information about the system",
        &["TA0007"], &["Windows", "macOS", "Linux"],
        &["Process Creation", "Command-Line Logging"], None,
        "Monitor for systeminfo, uname, and other system enumeration commands"),
    t("T1016", "System Network Config Discovery", "Adversaries may look for details of the network configuration",
        &["TA0007"], &["Windows", "macOS", "Linux"],
        &["Process Creation", "Command-Line Logging"], None,
        "Monitor for ipconfig, ifconfig, and network enumeration commands"),
    t("T1049", "System Network Connections", "Adversaries may attempt to get network connections from a system",
        &["TA0007"], &["Windows", "macOS", "Linux"],
        &["Process Creation", "Network Logs"], None,
        "Monitor for netstat, ss, and other network connection listing commands"),
    t("T1057", "Process Discovery", "Adversaries may attempt to get information about running processes",
        &["TA0007"], &["Windows", "macOS", "Linux"],
        &["Process Creation", "Command-Line Logging"], None,
        "Monitor for tasklist, ps, and other process enumeration commands"),
    t("T1069", "Permission Groups Discovery", "Adversaries may attempt to enumerate permission groups on a system",
        &["TA0007"], &["Windows", "macOS", "Linux"],
        &["Process Creation", "Command-Line Logging"], None,
        "Monitor for net group, getent, and domain group enumeration commands"),
    t("T1018", "Remote System Discovery", "Adversaries may attempt to get a listing of remote computers on a network",
        &["TA0007"], &["Windows", "macOS", "Linux"],
        &["Process Creation", "Network Traffic"], None,
        "Monitor for ping sweeps, net view, and network scanning activity"),
    t("T1033", "System Owner/User Discovery", "Adversaries may attempt to identify the primary user of the system",
        &["TA0007"], &["Windows", "macOS", "Linux"],
        &["Process Creation", "Command-Line Logging"], None,
        "Monitor for whoami, id, and other user identity enumeration commands"),
    t("T1083", "File and Directory Discovery", "Adversaries may enumerate files and directories for sensitive information",
        &["TA0007"], &["Windows", "macOS", "Linux"],
        &["File Access Logs", "Process Creation"], None,
        "Monitor for ls, dir, tree, and other file system enumeration commands"),
    t("T1005", "Data from Local System", "Adversaries may search local system sources for valuable data",
        &["TA0007", "TA0009"], &["Windows", "macOS", "Linux"],
        &["File Access Logs"], None,
        "Monitor for mass file access and data staging on local systems"),
    // =========================================================================
    // TA0008 Lateral Movement
    // =========================================================================
    t("T1021", "Remote Services", "Adversaries may use remote services to move laterally in a network",
        &["TA0008"], &["Windows", "macOS", "Linux", "Network"],
        &["Authentication Logs", "Network Traffic"],
        Some("M1042 - Disable or Remove Feature or Program"),
        "Monitor for RDP, SSH, SMB, and other remote service connections"),
    t("T1570", "Lateral Tool Transfer", "Adversaries may transfer tools between compromised systems",
        &["TA0008"], &["Windows", "macOS", "Linux"],
        &["Network Traffic", "File Transfer Logs"],
        Some("M1031 - Network Intrusion Prevention"),
        "Monitor for file transfers between internal systems via SMB, SCP, or FTP"),
    t("T1550", "Use Alternate Auth Material", "Adversaries may use alternate authentication material for lateral movement",
        &["TA0008"], &["Windows", "macOS", "Linux", "Cloud"],
        &["Authentication Logs", "Kerberos Logs"],
        Some("M1026 - Privileged Account Management"),
        "Monitor for pass-the-hash, pass-the-ticket, and forged token usage"),
    t("T1563", "Remote Service Session Hijacking", "Adversaries may hijack sessions of remote services for lateral movement",
        &["TA0008"], &["Windows", "Linux"],
        &["Authentication Logs", "Session Logs"],
        Some("M1026 - Privileged Account Management"),
        "Monitor for RDP session hijacking and SSH session manipulation"),
    t("T1080", "Taint Shared Content", "Adversaries may contaminate shared content to compromise other systems",
        &["TA0008"], &["Windows", "macOS", "Linux"],
        &["File Modification Logs"],
        Some("M1022 - Restrict File and Directory Permissions"),
        "Monitor for modifications to shared drives, folders, and network resources"),
    // =========================================================================
    // TA0009 Collection
    // =========================================================================
    t("T1560", "Archive Collected Data", "Adversaries may archive collected data before exfiltration",
        &["TA0009"], &["Windows", "macOS", "Linux"],
        &["File Creation Logs", "Process Creation"],
        Some("M1029 - Remote Data Storage"),
        "Monitor for creation of archive files (zip, rar, 7z) in staging directories"),
    t("T1123", "Audio Capture", "Adversaries may attempt to capture audio to collect sensitive information",
        &["TA0009"], &["Windows", "macOS"],
        &["Process Creation", "API Calls"], None,
        "Monitor for microphone access and audio recording software execution"),
    t("T1119", "Automated Collection", "Adversaries may use automated tools to collect data from the system",
        &["TA0009"], &["Windows", "macOS", "Linux"],
        &["File Access Logs", "Process Creation"], None,
        "Monitor for scripts and tools performing mass file collection"),
    t("T1039", "Data from Network Shared Drive", "Adversaries may search network shares for files of interest",
        &["TA0009"], &["Windows", "macOS", "Linux"],
        &["File Access Logs", "Network Traffic"], None,
        "Monitor for mass file access on network shares and shared drives"),
    t("T1025", "Data from Removable Media", "Adversaries may collect data from removable media connected to the system",
        &["TA0009"], &["Windows", "macOS", "Linux"],
        &["File Access Logs", "Device Monitoring"], None,
        "Monitor for data access and copying from USB drives and removable media"),
    t("T1074", "Data Staged", "Adversaries may stage collected data in a central location before exfiltration",
        &["TA0009"], &["Windows", "macOS", "Linux"],
        &["File Creation Logs", "Directory Monitoring"],
        Some("M1029 - Remote Data Storage"),
        "Monitor for data staging in temporary directories and hidden folders"),
    t("T1530", "Data from Cloud Storage", "Adversaries may collect data from cloud storage services",
        &["TA0009"], &["Windows", "macOS", "Linux", "Cloud"],
        &["Cloud Logs", "API Calls"],
        Some("M1027 - Password Policies"),
        "Monitor cloud storage access patterns and bulk data downloads"),
    t("T1114", "Email Collection", "Adversaries may collect email addresses and messages from victim systems",
        &["TA0009"], &["Windows", "macOS", "Linux"],
        &["Email Logs", "API Calls"],
        Some("M1032 - Multi-factor Authentication"),
        "Monitor for unauthorized email access and forwarding rules"),
    // =========================================================================
    // TA0011 Command and Control
    // =========================================================================
    t("T1071", "Application Layer Protocol", "Adversaries may communicate using application layer protocols for C2",
        &["TA0011"], &["Windows", "macOS", "Linux"],
        &["Network Traffic", "Web Proxy Logs"],
        Some("M1031 - Network Intrusion Prevention"),
        "Monitor for HTTP, HTTPS, DNS, and other application layer C2 traffic"),
    t("T1092", "Comm Through Removable Media", "Adversaries may communicate through removable media to transfer C2 data",
        &["TA0011"], &["Windows", "macOS", "Linux"],
        &["File Access Logs", "Device Monitoring"], None,
        "Monitor for C2 data transfer via USB and removable media devices"),
    t("T1090", "Proxy", "Adversaries may use a proxy to communicate with C2 infrastructure",
        &["TA0011"], &["Windows", "macOS", "Linux"],
        &["Network Traffic", "Web Proxy Logs"],
        Some("M1031 - Network Intrusion Prevention"),
        "Monitor for connections to known proxy services and multi-hop chains"),
    t("T1104", "Multi-Stage Channels", "Adversaries may use multiple stages for C2 communications",
        &["TA0011"], &["Windows", "macOS", "Linux"],
        &["Network Traffic"],
        Some("M1031 - Network Intrusion Prevention"),
        "Monitor for staged C2 infrastructure and initial callback patterns"),
    t("T1105", "Ingress Tool Transfer", "Adversaries may transfer tools or files from external systems into the network",
        &["TA0011"], &["Windows", "macOS", "Linux"],
        &["Network Traffic", "File Creation Logs"],
        Some("M1031 - Network Intrusion Prevention"),
        "Monitor for downloads from external hosts and tool staging activity"),
    t("T1095", "Non-Application Layer Protocol", "Adversaries may communicate using non-application layer protocols for C2",
        &["TA0011"], &["Windows", "macOS", "Linux"],
        &["Network Traffic", "Packet Capture"],
        Some("M1031 - Network Intrusion Prevention"),
        "Monitor for C2 over raw TCP, UDP, and other non-standard protocols"),
    t("T1572", "Protocol Tunneling", "Adversaries may tunnel network protocols to encapsulate C2 traffic",
        &["TA0011"], &["Windows", "macOS", "Linux"],
        &["Network Traffic", "Packet Capture"],
        Some("M1031 - Network Intrusion Prevention"),
        "Monitor for DNS tunneling, ICMP tunneling, and other encapsulation"),
    t("T1573", "Encrypted Channel", "Adversaries may use encryption to conceal C2 communications",
        &["TA0011"], &["Windows", "macOS", "Linux"],
        &["Network Traffic", "SSL/TLS Logs"],
        Some("M1031 - Network Intrusion Prevention"),
        "Monitor for encrypted C2 channels and certificate anomalies"),
    t("T1132", "Data Encoding", "Adversaries may encode data to conceal command and control information",
        &["TA0011"], &["Windows", "macOS", "Linux"],
        &["Network Traffic", "Process Creation"], None,
        "Monitor for Base64, hex, and other encoding in network communications"),
    t("T1008", "Fallback Channels", "Adversaries may use fallback channels for C2 when primary channels fail",
        &["TA0011"], &["Windows", "macOS", "Linux"],
        &["Network Traffic"],
        Some("M1031 - Network Intrusion Prevention"),
        "Monitor for connections to multiple C2 domains and IP addresses"),
    t("T1001", "Data Obfuscation", "Adversaries may obfuscate C2 traffic to avoid detection",
        &["TA0011"], &["Windows", "macOS", "Linux"],
        &["Network Traffic", "DNS Logs"],
        Some("M1031 - Network Intrusion Prevention"),
        "Monitor for domain fronting, junk data, and Steganography in C2"),
    // =========================================================================
    // TA0010 Exfiltration
    // =========================================================================
    t("T1020", "Automated Exfiltration", "Adversaries may automate data exfiltration using scripts or tools",
        &["TA0010"], &["Windows", "macOS", "Linux"],
        &["Network Traffic", "Process Creation"],
        Some("M1029 - Remote Data Storage"),
        "Monitor for automated data transfer scripts and scheduled exfiltration"),
    t("T1030", "Data Transfer Size Limits", "Adversaries may split data into small chunks to avoid detection",
        &["TA0010"], &["Windows", "macOS", "Linux"],
        &["Network Traffic"],
        Some("M1029 - Remote Data Storage"),
        "Monitor for small but frequent data transfers to external endpoints"),
    t("T1041", "Exfiltration Over C2 Channel", "Adversaries may steal data using the existing C2 channel",
        &["TA0010"], &["Windows", "macOS", "Linux"],
        &["Network Traffic"],
        Some("M1029 - Remote Data Storage"),
        "Monitor for data uploads within established C2 connections"),
    t("T1048", "Exfiltration Over Alternative Protocol", "Adversaries may exfiltrate data over non-C2 protocols",
        &["TA0010"], &["Windows", "macOS", "Linux"],
        &["Network Traffic", "DNS Logs"],
        Some("M1029 - Remote Data Storage"),
        "Monitor for data transfers over DNS, ICMP, or other non-standard protocols"),
    t("T1011", "Exfiltration Over Other Network Medium", "Adversaries may exfiltrate over alternative network mediums",
        &["TA0010"], &["Windows", "macOS", "Linux"],
        &["Network Traffic", "Device Monitoring"],
        Some("M1029 - Remote Data Storage"),
        "Monitor for data exfiltration over Bluetooth, Wi-Fi, or cellular connections"),
    t("T1567", "Exfiltration Over Web Service", "Adversaries may exfiltrate data by using legitimate web services",
        &["TA0010"], &["Windows", "macOS", "Linux"],
        &["Network Traffic", "Cloud Logs"],
        Some("M1021 - Restrict Web-Based Content"),
        "Monitor for uploads to cloud storage, paste sites, and social media"),
    // =========================================================================
    // TA0040 Impact
    // =========================================================================
    t("T1485", "Data Destruction", "Adversaries may destroy data and files on systems to impact availability",
        &["TA0040"], &["Windows", "macOS", "Linux"],
        &["File Deletion Logs", "Process Creation"],
        Some("M1053 - Data Backup"),
        "Monitor for mass file deletion and disk wipe utilities"),
    t("T1486", "Data Encrypted for Impact", "Adversaries may encrypt data on systems to impact availability for extortion",
        &["TA0040"], &["Windows", "macOS", "Linux"],
        &["File Modification Logs", "Process Creation"],
        Some("M1053 - Data Backup"),
        "Monitor for bulk file encryption and ransomware indicators"),
    t("T1489", "Service Stop", "Adversaries may stop or disable services to impact system availability",
        &["TA0040"], &["Windows", "Linux"],
        &["Service State Logs", "Process Creation"],
        Some("M1030 - Network Segmentation"),
        "Monitor for service stop commands and critical service disruptions"),
    t("T1490", "Inhibit System Recovery", "Adversaries may delete or disable system recovery to prevent restoration",
        &["TA0040", "TA0046"], &["Windows", "Linux"],
        &["Process Creation", "System Logs"],
        Some("M1053 - Data Backup"),
        "Monitor for deletion of shadow copies, boot configuration, and recovery data"),
    t("T1491", "Defacement", "Adversaries may modify visual appearance of systems to impact reputation",
        &["TA0040"], &["Windows", "Linux", "Network"],
        &["File Modification Logs", "Web Logs"],
        Some("M1053 - Data Backup"),
        "Monitor for unauthorized changes to web pages and desktop backgrounds"),
    t("T1498", "Network Denial of Service", "Adversaries may perform DDoS attacks to degrade network service availability",
        &["TA0040"], &["Windows", "macOS", "Linux", "Network"],
        &["Network Traffic", "Flow Data"],
        Some("M1037 - Filter Network Traffic"),
        "Monitor for traffic volume anomalies and volumetric DDoS patterns"),
    t("T1499", "Endpoint Denial of Service", "Adversaries may perform DoS attacks to degrade service on targeted endpoints",
        &["TA0040"], &["Windows", "macOS", "Linux"],
        &["Application Logs", "Process Creation"],
        Some("M1037 - Filter Network Traffic"),
        "Monitor for resource exhaustion attacks and application-layer flooding"),
    // =========================================================================
    // TA0045 Impair Process Control
    // =========================================================================
    t("T1565", "Data Manipulation", "Adversaries may insert, delete, or manipulate data in industrial control systems",
        &["TA0045"], &["Windows", "Linux", "Network"],
        &["ICS Network Traffic", "Process Monitoring"],
        Some("M1049 - Antivirus/Antimalware"),
        "Monitor for unauthorized modifications to ICS data flows and parameters"),
]);

pub struct TechniqueDatabase {
    pub techniques: Vec<Technique>,
    by_id: HashMap<String, usize>,
    by_tactic: HashMap<String, Vec<usize>>,
}

impl TechniqueDatabase {
    pub fn new() -> Self {
        let techniques = TECHNIQUE_DB.clone();
        let mut by_id = HashMap::new();
        let mut by_tactic: HashMap<String, Vec<usize>> = HashMap::new();

        for (i, tech) in techniques.iter().enumerate() {
            by_id.insert(tech.id.clone(), i);
            for tactic in &tech.tactics {
                by_tactic.entry(tactic.clone()).or_default().push(i);
            }
        }

        Self {
            techniques,
            by_id,
            by_tactic,
        }
    }

    pub fn get_technique(&self, id: &str) -> Option<&Technique> {
        self.by_id.get(id).map(|&i| &self.techniques[i])
    }

    pub fn get_techniques_by_tactic(&self, tactic: &str) -> Vec<&Technique> {
        self.by_tactic
            .get(tactic)
            .map(|indices| indices.iter().map(|&i| &self.techniques[i]).collect())
            .unwrap_or_default()
    }

    pub fn search_techniques(&self, query: &str) -> Vec<&Technique> {
        let q = query.to_lowercase();
        self.techniques
            .iter()
            .filter(|tech| {
                tech.id.to_lowercase().contains(&q)
                    || tech.name.to_lowercase().contains(&q)
                    || tech.description.to_lowercase().contains(&q)
            })
            .collect()
    }

    pub fn get_all_techniques(&self) -> &[Technique] {
        &self.techniques
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_database_creation() {
        let db = TechniqueDatabase::new();
        assert!(db.get_all_techniques().len() >= 100);
    }

    #[test]
    fn test_get_technique() {
        let db = TechniqueDatabase::new();
        let tech = db.get_technique("T1566");
        assert!(tech.is_some());
        let tech = tech.unwrap();
        assert_eq!(tech.name, "Phishing");
        assert!(tech.tactics.contains(&"TA0001".to_string()));
    }

    #[test]
    fn test_get_techniques_by_tactic() {
        let db = TechniqueDatabase::new();
        let recon = db.get_techniques_by_tactic("TA0043");
        assert_eq!(recon.len(), 10);
        let execution = db.get_techniques_by_tactic("TA0002");
        assert!(execution.len() >= 7);
    }

    #[test]
    fn test_search_techniques() {
        let db = TechniqueDatabase::new();
        let results = db.search_techniques("phishing");
        assert!(!results.is_empty());
        assert!(results.iter().any(|t| t.name == "Phishing"));
    }

    #[test]
    fn test_search_by_id() {
        let db = TechniqueDatabase::new();
        let results = db.search_techniques("T1059");
        assert!(!results.is_empty());
        assert!(results.iter().any(|t| t.id == "T1059"));
    }

    #[test]
    fn test_get_nonexistent_technique() {
        let db = TechniqueDatabase::new();
        assert!(db.get_technique("T9999").is_none());
    }

    #[test]
    fn test_get_nonexistent_tactic() {
        let db = TechniqueDatabase::new();
        let results = db.get_techniques_by_tactic("TA9999");
        assert!(results.is_empty());
    }

    #[test]
    fn test_all_tactics_present() {
        let db = TechniqueDatabase::new();
        let tactics = [
            "TA0043", "TA0042", "TA0001", "TA0002", "TA0003",
            "TA0004", "TA0005", "TA0006", "TA0007", "TA0008",
            "TA0009", "TA0011", "TA0010", "TA0040", "TA0045", "TA0046",
        ];
        for tactic in tactics {
            let techs = db.get_techniques_by_tactic(tactic);
            assert!(
                !techs.is_empty(),
                "No techniques found for tactic {}",
                tactic
            );
        }
    }

    #[test]
    fn test_technique_fields_not_empty() {
        let db = TechniqueDatabase::new();
        for tech in db.get_all_techniques() {
            assert!(!tech.id.is_empty(), "Empty id for technique");
            assert!(!tech.name.is_empty(), "Empty name for technique");
            assert!(!tech.description.is_empty(), "Empty description for technique");
            assert!(!tech.tactics.is_empty(), "Empty tactics for technique {}", tech.id);
            assert!(!tech.detection.is_empty(), "Empty detection for technique {}", tech.id);
        }
    }

    #[test]
    fn test_multi_tactic_techniques() {
        let db = TechniqueDatabase::new();
        let t1078 = db.get_technique("T1078").unwrap();
        assert!(t1078.tactics.len() >= 3);
        assert!(t1078.tactics.contains(&"TA0001".to_string()));
        assert!(t1078.tactics.contains(&"TA0004".to_string()));
        assert!(t1078.tactics.contains(&"TA0005".to_string()));
    }
}
