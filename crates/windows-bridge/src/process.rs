use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ProcessStatus {
    Running,
    Suspended,
    Terminated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub exe_path: String,
    pub command_line: String,
    pub parent_pid: u32,
    pub user: String,
    pub cpu_usage: f64,
    pub memory_mb: u64,
    pub status: ProcessStatus,
}

#[cfg(windows)]
pub fn list_processes() -> Vec<ProcessInfo> {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
        PROCESSENTRY32W,
    };
    use std::mem::zeroed;

    let mut processes = Vec::new();
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            .unwrap_or_default();
        let mut entry: PROCESSENTRY32W = zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let name = String::from_utf16_lossy(&entry.szExeFile)
                    .trim_end_matches('\0')
                    .to_string();
                processes.push(ProcessInfo {
                    pid: entry.th32ProcessID,
                    name,
                    exe_path: String::new(),
                    command_line: String::new(),
                    parent_pid: entry.th32ParentProcessID,
                    user: String::new(),
                    cpu_usage: 0.0,
                    memory_mb: 0,
                    status: ProcessStatus::Running,
                });
                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = windows::Win32::Foundation::CloseHandle(snapshot);
    }
    processes
}

#[cfg(not(windows))]
pub fn list_processes() -> Vec<ProcessInfo> {
    vec![
        ProcessInfo {
            pid: 1,
            name: "system".to_string(),
            exe_path: "/System".to_string(),
            command_line: String::new(),
            parent_pid: 0,
            user: "SYSTEM".to_string(),
            cpu_usage: 0.5,
            memory_mb: 128,
            status: ProcessStatus::Running,
        },
        ProcessInfo {
            pid: 100,
            name: "svchost.exe".to_string(),
            exe_path: "C:\\Windows\\System32\\svchost.exe".to_string(),
            command_line: "svchost.exe -k netsvcs".to_string(),
            parent_pid: 1,
            user: "LOCAL SERVICE".to_string(),
            cpu_usage: 2.1,
            memory_mb: 64,
            status: ProcessStatus::Running,
        },
        ProcessInfo {
            pid: 200,
            name: "suspended_process.exe".to_string(),
            exe_path: "C:\\temp\\suspended_process.exe".to_string(),
            command_line: "suspended_process.exe --inject".to_string(),
            parent_pid: 100,
            user: "Administrator".to_string(),
            cpu_usage: 0.0,
            memory_mb: 32,
            status: ProcessStatus::Suspended,
        },
        ProcessInfo {
            pid: 300,
            name: "cmd.exe".to_string(),
            exe_path: "C:\\Windows\\System32\\cmd.exe".to_string(),
            command_line: "cmd.exe /c whoami".to_string(),
            parent_pid: 100,
            user: "Administrator".to_string(),
            cpu_usage: 0.2,
            memory_mb: 8,
            status: ProcessStatus::Running,
        },
        ProcessInfo {
            pid: 400,
            name: "powershell.exe".to_string(),
            exe_path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe".to_string(),
            command_line: "powershell.exe -enc SQBmACgAJAB0AGUAcwB0ACkA".to_string(),
            parent_pid: 300,
            user: "Administrator".to_string(),
            cpu_usage: 5.0,
            memory_mb: 120,
            status: ProcessStatus::Running,
        },
        ProcessInfo {
            pid: 500,
            name: "mimikatz.exe".to_string(),
            exe_path: "C:\\temp\\mimikatz.exe".to_string(),
            command_line: "mimikatz.exe privilege::debug".to_string(),
            parent_pid: 300,
            user: "SYSTEM".to_string(),
            cpu_usage: 8.0,
            memory_mb: 45,
            status: ProcessStatus::Running,
        },
        ProcessInfo {
            pid: 600,
            name: "calc.exe".to_string(),
            exe_path: "C:\\Windows\\System32\\calc.exe".to_string(),
            command_line: "calc.exe".to_string(),
            parent_pid: 1,
            user: "User".to_string(),
            cpu_usage: 0.1,
            memory_mb: 16,
            status: ProcessStatus::Running,
        },
        ProcessInfo {
            pid: 700,
            name: "old_process.exe".to_string(),
            exe_path: "C:\\temp\\old_process.exe".to_string(),
            command_line: String::new(),
            parent_pid: 1,
            user: "User".to_string(),
            cpu_usage: 0.0,
            memory_mb: 0,
            status: ProcessStatus::Terminated,
        },
    ]
}

#[cfg(windows)]
pub fn get_process_by_pid(pid: u32) -> Option<ProcessInfo> {
    list_processes().into_iter().find(|p| p.pid == pid)
}

#[cfg(not(windows))]
pub fn get_process_by_pid(pid: u32) -> Option<ProcessInfo> {
    list_processes().into_iter().find(|p| p.pid == pid)
}

pub fn is_suspicious_process(info: &ProcessInfo) -> bool {
    let suspicious_names = [
        "mimikatz.exe",
        "procdump.exe",
        "psexec.exe",
        "nc.exe",
        "netcat.exe",
        "meterpreter.exe",
        "cobaltstrike.exe",
        "beacon.exe",
        "inject.exe",
    ];
    let lower_name = info.name.to_lowercase();
    for pattern in &suspicious_names {
        if lower_name.contains(pattern) {
            return true;
        }
    }
    if lower_name.contains("powershell") && info.command_line.contains("-enc") {
        return true;
    }
    if lower_name.contains("cmd.exe") && info.command_line.contains("/c") {
        let cmd_line = info.command_line.to_lowercase();
        if cmd_line.contains("whoami") || cmd_line.contains("net user") || cmd_line.contains("net group") {
            return true;
        }
    }
    if info.status == ProcessStatus::Suspended {
        return true;
    }
    if info.exe_path.to_lowercase().contains("\\temp\\") && !info.exe_path.is_empty() {
        return true;
    }
    false
}

#[cfg(windows)]
pub fn get_process_count() -> usize {
    list_processes().len()
}

#[cfg(not(windows))]
pub fn get_process_count() -> usize {
    list_processes().len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_processes_returns_data() {
        let processes = list_processes();
        assert!(!processes.is_empty());
    }

    #[test]
    fn test_get_process_by_pid_system() {
        let proc = get_process_by_pid(4);
        assert!(proc.is_some());
    }

    #[test]
    fn test_get_process_by_pid_not_found() {
        let proc = get_process_by_pid(99999999);
        assert!(proc.is_none());
    }

    #[test]
    fn test_is_suspicious_mimikatz() {
        let proc = ProcessInfo {
            pid: 999,
            name: "mimikatz.exe".to_string(),
            exe_path: "C:\\temp\\mimikatz.exe".to_string(),
            command_line: "mimikatz.exe".to_string(),
            parent_pid: 100,
            user: "SYSTEM".to_string(),
            cpu_usage: 5.0,
            memory_mb: 40,
            status: ProcessStatus::Running,
        };
        assert!(is_suspicious_process(&proc));
    }

    #[test]
    fn test_is_suspicious_encoded_ps() {
        let proc = ProcessInfo {
            pid: 998,
            name: "powershell.exe".to_string(),
            exe_path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe".to_string(),
            command_line: "powershell.exe -enc SQBmACgAJAB0AGUAcwB0ACkA".to_string(),
            parent_pid: 300,
            user: "Administrator".to_string(),
            cpu_usage: 2.0,
            memory_mb: 80,
            status: ProcessStatus::Running,
        };
        assert!(is_suspicious_process(&proc));
    }

    #[test]
    fn test_is_not_suspicious_normal() {
        let proc = ProcessInfo {
            pid: 600,
            name: "calc.exe".to_string(),
            exe_path: "C:\\Windows\\System32\\calc.exe".to_string(),
            command_line: "calc.exe".to_string(),
            parent_pid: 1,
            user: "User".to_string(),
            cpu_usage: 0.1,
            memory_mb: 16,
            status: ProcessStatus::Running,
        };
        assert!(!is_suspicious_process(&proc));
    }

    #[test]
    fn test_get_process_count() {
        let count = get_process_count();
        assert!(count >= 1);
    }

    #[test]
    fn test_process_status_variants() {
        assert_ne!(ProcessStatus::Running, ProcessStatus::Suspended);
        assert_ne!(ProcessStatus::Running, ProcessStatus::Terminated);
        assert_ne!(ProcessStatus::Suspended, ProcessStatus::Terminated);
    }
}
