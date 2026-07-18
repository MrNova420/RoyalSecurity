/*
   RoyalSecurity - Attack Technique Detection Rules
   Author: RoyalSecurity Contributors
   Date: 2025-01-01
   License: AGPL-3.0-or-later
   Description: YARA rules for detecting common attack techniques
*/

rule Process_Injection_CreateRemoteThread {
    meta:
        description = "Detects CreateRemoteThread API usage for process injection"
        author = "RoyalSecurity"
        date = "2025-01-01"
        severity = "high"
        mitre = "T1055.003"
        tags = "injection,process_injection"
    strings:
         = "CreateRemoteThread" ascii
         = "VirtualAllocEx" ascii
         = "WriteProcessMemory" ascii
         = "NtCreateThreadEx" ascii
    condition:
        2 of (*)
}

rule Process_Hollowing {
    meta:
        description = "Detects process hollowing indicators"
        author = "RoyalSecurity"
        date = "2025-01-01"
        severity = "high"
        mitre = "T1055.012"
        tags = "injection,process_hollowing"
    strings:
         = "NtUnmapViewOfSection" ascii
         = "ZwUnmapViewOfSection" ascii
         = "SetThreadContext" ascii
         = "ResumeThread" ascii
    condition:
        2 of (*)
}

rule APC_Queue_Injection {
    meta:
        description = "Detects APC injection via QueueUserAPC"
        author = "RoyalSecurity"
        date = "2025-01-01"
        severity = "high"
        mitre = "T1055.004"
        tags = "injection,apc"
    strings:
         = "QueueUserAPC" ascii
         = "NtQueueApcThread" ascii
         = "NtQueueApcThreadEx" ascii
    condition:
        1 of (*)
}

rule Credential_Dumping_LSASS {
    meta:
        description = "Detects LSASS memory dump for credential extraction"
        author = "RoyalSecurity"
        date = "2025-01-01"
        severity = "critical"
        mitre = "T1003.001"
        tags = "credentials,lsass,credential_dumping"
    strings:
         = "lsass.exe" ascii
         = "MiniDumpWriteDump" ascii
         = "procdump" ascii
         = "comsvcs.dll" ascii
         = "MiniDumpWriteDumpA" ascii
    condition:
        2 of (*)
}

rule Persistence_Scheduled_Task {
    meta:
        description = "Detects suspicious scheduled task creation"
        author = "RoyalSecurity"
        date = "2025-01-01"
        severity = "medium"
        mitre = "T1053.005"
        tags = "persistence,scheduled_task"
    strings:
         = "schtasks /create" ascii nocase
         = "ScheduledTask" ascii
         = "Register-ScheduledTask" ascii
         = "New-ScheduledTask" ascii
    condition:
        1 of (*)
}

rule Persistence_Service_Creation {
    meta:
        description = "Detects suspicious Windows service installation"
        author = "RoyalSecurity"
        date = "2025-01-01"
        severity = "medium"
        mitre = "T1543.003"
        tags = "persistence,service"
    strings:
         = "sc create" ascii nocase
         = "New-Service" ascii
         = "Win32_Service" ascii
         = "CreateServiceA" ascii
    condition:
        1 of (*)
}

rule Defense_Evasion_AMSI_Bypass {
    meta:
        description = "Detects AMSI bypass techniques"
        author = "RoyalSecurity"
        date = "2025-01-01"
        severity = "high"
        mitre = "T1562.001"
        tags = "evasion,amsi"
    strings:
         = "AmsiScanBuffer" ascii
         = "amsi.dll" ascii
         = "amsiInitFailed" ascii
         = "SetProcessMitigationPolicy" ascii
         = "AmsiOpenSession" ascii
    condition:
        2 of (*)
}

rule Defense_Evasion_ETW_Patch {
    meta:
        description = "Detects ETW patching to evade logging"
        author = "RoyalSecurity"
        date = "2025-01-01"
        severity = "high"
        mitre = "T1562.006"
        tags = "evasion,etw"
    strings:
         = "EtwEventWrite" ascii
         = "NtTraceControl" ascii
         = "EtwEventRegister" ascii
         = "NtSetInformationThread" ascii
    condition:
        2 of (*)
}

rule Script_Abuse_PowerShell_Obfuscation {
    meta:
        description = "Detects obfuscated PowerShell commands"
        author = "RoyalSecurity"
        date = "2025-01-01"
        severity = "high"
        mitre = "T1059.001"
        tags = "script,powershell,obfuscation"
    strings:
         = "powershell -enc" ascii nocase
         = "powershell -nop" ascii nocase
         = "DownloadString" ascii
         = "IEX(" ascii
         = "Invoke-Expression" ascii
         = "FromBase64String" ascii
    condition:
        2 of (*)
}

rule Script_Abuse_Office_Macro {
    meta:
        description = "Detects malicious Office macro patterns"
        author = "RoyalSecurity"
        date = "2025-01-01"
        severity = "high"
        mitre = "T1059.005"
        tags = "script,macro,office"
    strings:
         = "Auto_Open" ascii
         = "Document_Open" ascii
         = "Shell(" ascii
         = "WScript.Shell" ascii
         = "CreateObject" ascii
    condition:
        2 of (*)
}
