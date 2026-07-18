use serde::{Serialize, Deserialize};
use strum_macros::{EnumIter, EnumString, IntoStaticStr, Display};
use crate::types::EventType;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Display, EnumIter, EnumString, IntoStaticStr)]
pub enum Tactic {
    #[strum(serialize = "TA0043")]
    Reconnaissance,
    #[strum(serialize = "TA0042")]
    ResourceDevelopment,
    #[strum(serialize = "TA0001")]
    InitialAccess,
    #[strum(serialize = "TA0002")]
    Execution,
    #[strum(serialize = "TA0003")]
    Persistence,
    #[strum(serialize = "TA0004")]
    PrivilegeEscalation,
    #[strum(serialize = "TA0005")]
    DefenseEvasion,
    #[strum(serialize = "TA0006")]
    CredentialAccess,
    #[strum(serialize = "TA0007")]
    Discovery,
    #[strum(serialize = "TA0008")]
    LateralMovement,
    #[strum(serialize = "TA0009")]
    Collection,
    #[strum(serialize = "TA0010")]
    Exfiltration,
    #[strum(serialize = "TA0011")]
    CommandAndControl,
    #[strum(serialize = "TA0040")]
    Impact,
}

#[derive(Debug, Clone, Copy)]
pub struct Technique {
    pub id: &'static str,
    pub name: &'static str,
    pub tactic: Tactic,
    pub description: &'static str,
}

pub const TECHNIQUES: &[Technique] = &[
    Technique { id: "T1059.001", name: "PowerShell", tactic: Tactic::Execution, description: "Adversaries may abuse PowerShell commands and scripts for execution." },
    Technique { id: "T1059.003", name: "Windows Command Shell", tactic: Tactic::Execution, description: "Adversaries may abuse the Windows command shell for execution." },
    Technique { id: "T1059.005", name: "Visual Basic", tactic: Tactic::Execution, description: "Adversaries may abuse Visual Basic (VB) for execution." },
    Technique { id: "T1059.006", name: "Python", tactic: Tactic::Execution, description: "Adversaries may abuse Python commands and scripts for execution." },
    Technique { id: "T1059.007", name: "JavaScript", tactic: Tactic::Execution, description: "Adversaries may abuse JavaScript for execution." },
    Technique { id: "T1053.005", name: "Scheduled Task", tactic: Tactic::Persistence, description: "Adversaries may abuse the Windows Task Scheduler to perform initial or recurring execution of malicious code." },
    Technique { id: "T1053.003", name: "Cron", tactic: Tactic::Persistence, description: "Adversaries may abuse the cron utility to perform initial or recurring execution of malicious code." },
    Technique { id: "T1547.001", name: "Registry Run Keys / Startup Folder", tactic: Tactic::Persistence, description: "Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key." },
    Technique { id: "T1543.003", name: "Windows Service", tactic: Tactic::Persistence, description: "Adversaries may create or modify Windows services to repeatedly execute malicious payloads as part of persistence." },
    Technique { id: "T1546.003", name: "WMI Event Subscription", tactic: Tactic::Persistence, description: "Adversaries may abuse WMI event subscriptions to establish persistence." },
    Technique { id: "T1136.001", name: "Local Account", tactic: Tactic::Persistence, description: "Adversaries may create a local account to maintain persistence." },
    Technique { id: "T1547.009", name: "Shortcut Modification", tactic: Tactic::Persistence, description: "Adversaries may create or modify shortcuts to run a program during system boot or user login." },
    Technique { id: "T1003", name: "OS Credential Dumping", tactic: Tactic::CredentialAccess, description: "Adversaries may attempt to dump credentials to obtain account login and credential material." },
    Technique { id: "T1003.001", name: "LSASS Memory", tactic: Tactic::CredentialAccess, description: "Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS)." },
    Technique { id: "T1003.002", name: "Security Account Manager", tactic: Tactic::CredentialAccess, description: "Adversaries may attempt to extract credential material from the Security Account Manager (SAM) database." },
    Technique { id: "T1110", name: "Brute Force", tactic: Tactic::CredentialAccess, description: "Adversaries may use brute force techniques to gain access to accounts." },
    Technique { id: "T1558.001", name: "Golden Ticket", tactic: Tactic::CredentialAccess, description: "Adversaries may forge Kerberos TGT tickets (Golden Ticket) to bypass kerberos authentication." },
    Technique { id: "T1055", name: "Process Injection", tactic: Tactic::DefenseEvasion, description: "Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges." },
    Technique { id: "T1027", name: "Obfuscated Files or Information", tactic: Tactic::DefenseEvasion, description: "Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents." },
    Technique { id: "T1070", name: "Indicator Removal", tactic: Tactic::DefenseEvasion, description: "Adversaries may delete or modify artifacts generated within systems to remove evidence of their presence." },
    Technique { id: "T1562.001", name: "Disable or Modify Tools", tactic: Tactic::DefenseEvasion, description: "Adversaries may disable and/or modify security tools to avoid possible detection." },
    Technique { id: "T1140", name: "Deobfuscate/Decode Files or Information", tactic: Tactic::DefenseEvasion, description: "Adversaries may use obfuscated files or information to hide artifacts of an intrusion." },
    Technique { id: "T1497", name: "Virtualization/Sandbox Evasion", tactic: Tactic::DefenseEvasion, description: "Adversaries may employ means to detect and avoid virtualization and analysis environments." },
    Technique { id: "T1036", name: "Masquerading", tactic: Tactic::DefenseEvasion, description: "Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate or benign." },
    Technique { id: "T1082", name: "System Information Discovery", tactic: Tactic::Discovery, description: "An adversary may attempt to get detailed information about the operating system and hardware." },
    Technique { id: "T1083", name: "File and Directory Discovery", tactic: Tactic::Discovery, description: "Adversaries may enumerate files and directories or may search in specific locations of a host or network share." },
    Technique { id: "T1057", name: "Process Discovery", tactic: Tactic::Discovery, description: "Adversaries may attempt to get information about running processes on a system." },
    Technique { id: "T1049", name: "System Network Connections Discovery", tactic: Tactic::Discovery, description: "Adversaries may attempt to get a listing of network connections to or from the compromised system." },
    Technique { id: "T1018", name: "Remote System Discovery", tactic: Tactic::Discovery, description: "Adversaries may attempt to get a listing of other systems by IP address, hostname, or other logical identifier." },
    Technique { id: "T1087", name: "Account Discovery", tactic: Tactic::Discovery, description: "Adversaries may attempt to get a listing of accounts on a system." },
    Technique { id: "T1012", name: "Query Registry", tactic: Tactic::Discovery, description: "Adversaries may interact with the Windows Registry to gather information about the system." },
    Technique { id: "T1078", name: "Valid Accounts", tactic: Tactic::InitialAccess, description: "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access." },
    Technique { id: "T1190", name: "Exploit Public-Facing Application", tactic: Tactic::InitialAccess, description: "Adversaries may attempt to take advantage of a weakness in an Internet-facing computer or program." },
    Technique { id: "T1566", name: "Phishing", tactic: Tactic::InitialAccess, description: "Adversaries may send phishing messages to gain access to victim systems." },
    Technique { id: "T1133", name: "External Remote Services", tactic: Tactic::InitialAccess, description: "Adversaries may leverage external-facing remote services to initially access and/or persist within a network." },
    Technique { id: "T1071", name: "Application Layer Protocol", tactic: Tactic::CommandAndControl, description: "Adversaries may communicate using OSI application layer protocols to avoid detection/network filtering." },
    Technique { id: "T1071.001", name: "Web Protocols", tactic: Tactic::CommandAndControl, description: "Adversaries may communicate using application layer protocols associated with web traffic to avoid detection." },
    Technique { id: "T1573", name: "Encrypted Channel", tactic: Tactic::CommandAndControl, description: "Adversaries may employ a known encryption algorithm to conceal command and control traffic." },
    Technique { id: "T1572", name: "Protocol Tunneling", tactic: Tactic::CommandAndControl, description: "Adversaries may tunnel network communications to and from a victim system within a separate protocol." },
    Technique { id: "T1105", name: "Ingress Tool Transfer", tactic: Tactic::CommandAndControl, description: "Adversaries may transfer tools or other files from an external system into a compromised environment." },
    Technique { id: "T1486", name: "Data Encrypted for Impact", tactic: Tactic::Impact, description: "Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability to system and network resources." },
    Technique { id: "T1485", name: "Data Destruction", tactic: Tactic::Impact, description: "Adversaries may destroy data and files on specific systems or in large numbers on a network to interrupt availability to systems, services, and network resources." },
    Technique { id: "T1489", name: "Service Stop", tactic: Tactic::Impact, description: "Adversaries may stop or disable services on a system to render those services unavailable to legitimate users." },
    Technique { id: "T1490", name: "Inhibit System Recovery", tactic: Tactic::Impact, description: "Adversaries may delete or remove built-in data and turn off services designed to aid in the recovery of a corrupted system." },
    Technique { id: "T1498", name: "Network Denial of Service", tactic: Tactic::Impact, description: "Adversaries may perform Network Denial of Service (DoS) attacks to degrade or block the availability of targeted resources." },
    Technique { id: "T1048", name: "Exfiltration Over Alternative Protocol", tactic: Tactic::Exfiltration, description: "Adversaries may steal data by exfiltrating it over a different protocol than that of the existing command and control channel." },
    Technique { id: "T1041", name: "Exfiltration Over C2 Channel", tactic: Tactic::Exfiltration, description: "Adversaries may steal data by exfiltrating it over an existing command and control channel." },
    Technique { id: "T1567", name: "Exfiltration Over Web Service", tactic: Tactic::Exfiltration, description: "Adversaries may use an existing, legitimate external Web service to exfiltrate data rather than their primary command and control channel." },
    Technique { id: "T1005", name: "Data from Local System", tactic: Tactic::Collection, description: "Adversaries may search local system sources, such as file systems and configuration files, to find files of interest." },
    Technique { id: "T1039", name: "Data from Network Shared Drive", tactic: Tactic::Collection, description: "Adversaries may search network shares on computers they have compromised to find files of interest." },
    Technique { id: "T1114", name: "Email Collection", tactic: Tactic::Collection, description: "Adversaries may target user email to collect sensitive information." },
    Technique { id: "T1056.001", name: "Keylogging", tactic: Tactic::Collection, description: "Adversaries may log user keystrokes to capture information about victims during compromise." },
    Technique { id: "T1113", name: "Screen Capture", tactic: Tactic::Collection, description: "Adversaries may attempt to take screen captures of the desktop to gather information over the course of an operation." },
    Technique { id: "T1047", name: "Windows Management Instrumentation", tactic: Tactic::Execution, description: "Adversaries may abuse Windows Management Instrumentation (WMI) to execute malicious commands and payloads." },
    Technique { id: "T1204.002", name: "Malicious File", tactic: Tactic::Execution, description: "An adversary may rely upon a user opening a malicious file to gain execution." },
    Technique { id: "T1203", name: "Exploitation for Client Execution", tactic: Tactic::Execution, description: "Adversaries may exploit software vulnerabilities in client applications to execute code." },
    Technique { id: "T1569.002", name: "Service Execution", tactic: Tactic::Execution, description: "Adversaries may abuse the Windows service control manager to execute malicious commands or payloads." },
    Technique { id: "T1021", name: "Remote Services", tactic: Tactic::LateralMovement, description: "Adversaries may use Valid Accounts to log into a service specifically designed to accept remote connections." },
    Technique { id: "T1021.002", name: "SMB/Windows Admin Shares", tactic: Tactic::LateralMovement, description: "Adversaries may use SMB to interact with admin shares for lateral movement." },
    Technique { id: "T1021.006", name: "Windows Remote Management", tactic: Tactic::LateralMovement, description: "Adversaries may use Windows Remote Management to execute commands on remote systems." },
    Technique { id: "T1550", name: "Use Alternate Authentication Material", tactic: Tactic::LateralMovement, description: "Adversaries may use alternate authentication material, such as password hashes, Kerberos tickets, and application access tokens." },
];

pub fn get_techniques_for_tactic(tactic: Tactic) -> Vec<&'static Technique> {
    TECHNIQUES.iter().filter(|t| t.tactic == tactic).collect()
}

pub fn classify_event_to_technique(event_type: &EventType) -> Vec<&'static Technique> {
    match event_type {
        EventType::ProcessCreated => {
            vec![&TECHNIQUES[0], &TECHNIQUES[2], &TECHNIQUES[43], &TECHNIQUES[45]]
        }
        EventType::ProcessTerminated => {
            vec![]
        }
        EventType::ProcessInjected => {
            vec![&TECHNIQUES[17]]
        }
        EventType::FileCreated | EventType::FileModified => {
            vec![&TECHNIQUES[8], &TECHNIQUES[18], &TECHNIQUES[11], &TECHNIQUES[44]]
        }
        EventType::FileDeleted => {
            vec![&TECHNIQUES[20], &TECHNIQUES[36], &TECHNIQUES[38]]
        }
        EventType::FileRenamed => {
            vec![&TECHNIQUES[22]]
        }
        EventType::RegistryCreated | EventType::RegistryModified => {
            vec![&TECHNIQUES[8], &TECHNIQUES[14], &TECHNIQUES[30]]
        }
        EventType::RegistryDeleted => {
            vec![&TECHNIQUES[20]]
        }
        EventType::NetworkConnection => {
            vec![&TECHNIQUES[32], &TECHNIQUES[33], &TECHNIQUES[34], &TECHNIQUES[35]]
        }
        EventType::NetworkListen => {
            vec![&TECHNIQUES[32]]
        }
        EventType::DnsQuery | EventType::DnsResponse => {
            vec![&TECHNIQUES[32], &TECHNIQUES[33]]
        }
        EventType::AuthSuccess => {
            vec![&TECHNIQUES[31]]
        }
        EventType::AuthFailure => {
            vec![&TECHNIQUES[15], &TECHNIQUES[16]]
        }
        EventType::PrivilegeEscalation => {
            vec![&TECHNIQUES[21], &TECHNIQUES[28], &TECHNIQUES[17]]
        }
        EventType::ServiceCreated | EventType::ServiceStarted => {
            vec![&TECHNIQUES[9], &TECHNIQUES[46]]
        }
        EventType::ServiceStopped => {
            vec![&TECHNIQUES[37]]
        }
        EventType::ScheduledTaskCreated | EventType::ScheduledTaskModified => {
            vec![&TECHNIQUES[6], &TECHNIQUES[7]]
        }
        EventType::WmiEvent => {
            vec![&TECHNIQUES[10], &TECHNIQUES[43]]
        }
        EventType::MemoryAllocation | EventType::MemoryProtection => {
            vec![&TECHNIQUES[17], &TECHNIQUES[21]]
        }
        EventType::ThreadCreated | EventType::ThreadRemote => {
            vec![&TECHNIQUES[17]]
        }
        EventType::ModuleLoaded => {
            vec![&TECHNIQUES[17], &TECHNIQUES[19]]
        }
        EventType::ThreatDetected => {
            vec![&TECHNIQUES[35]]
        }
        _ => vec![],
    }
}
