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
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
        PROCESSENTRY32W,
    };
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    let mut processes = Vec::new();
    unsafe {
        let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(s) => s,
            Err(_) => return processes,
        };
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let name = String::from_utf16_lossy(&entry.szExeFile)
                    .trim_end_matches('\0')
                    .to_string();
                let pid = entry.th32ProcessID;
                let parent_pid = entry.th32ParentProcessID;

                let (exe_path, memory_mb, user) = if pid > 0 {
                    if let Ok(handle) =
                        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
                    {
                        let exe = get_process_exe_path(handle);
                        let mem = get_process_memory_mb(handle);
                        let usr = get_process_user(handle);
                        let _ = CloseHandle(handle);
                        (exe, mem, usr)
                    } else {
                        (String::new(), 0u64, String::new())
                    }
                } else {
                    (String::new(), 0u64, String::new())
                };

                processes.push(ProcessInfo {
                    pid,
                    name,
                    exe_path,
                    command_line: String::new(),
                    parent_pid,
                    user,
                    cpu_usage: 0.0,
                    memory_mb,
                    status: ProcessStatus::Running,
                });
                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snapshot);
    }
    processes
}

#[cfg(windows)]
fn get_process_exe_path(handle: windows::Win32::Foundation::HANDLE) -> String {
    use windows::Win32::System::Threading::{QueryFullProcessImageNameW, PROCESS_NAME_FORMAT};

    unsafe {
        let mut buf = [0u16; 260];
        let mut size = buf.len() as u32;
        if QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_FORMAT(0),
            windows::core::PWSTR(buf.as_mut_ptr()),
            &mut size,
        )
        .is_ok()
        {
            String::from_utf16_lossy(&buf[..size as usize]).to_string()
        } else {
            String::new()
        }
    }
}

#[cfg(windows)]
fn get_process_memory_mb(handle: windows::Win32::Foundation::HANDLE) -> u64 {
    use windows::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};

    unsafe {
        let mut counters: PROCESS_MEMORY_COUNTERS = std::mem::zeroed();
        counters.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
        if GetProcessMemoryInfo(handle, &mut counters, counters.cb).is_ok() {
            (counters.WorkingSetSize / (1024 * 1024)) as u64
        } else {
            0
        }
    }
}

#[cfg(windows)]
fn get_process_user(handle: windows::Win32::Foundation::HANDLE) -> String {
    use windows::Win32::Foundation::{CloseHandle, LocalFree, HLOCAL};
    use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows::Win32::System::Threading::OpenProcessToken;
    use windows::core::PWSTR;

    unsafe {
        let mut token_handle = windows::Win32::Foundation::HANDLE::default();
        if OpenProcessToken(handle, TOKEN_QUERY, &mut token_handle).is_err() {
            return String::new();
        }

        let mut required_size = 0u32;
        let _ = GetTokenInformation(
            token_handle,
            TokenUser,
            None,
            0,
            &mut required_size,
        );

        if required_size == 0 {
            let _ = CloseHandle(token_handle);
            return String::new();
        }

        let mut buf: Vec<u8> = vec![0u8; required_size as usize];
        let result = GetTokenInformation(
            token_handle,
            TokenUser,
            Some(buf.as_mut_ptr() as *mut _),
            required_size,
            &mut required_size,
        );
        let _ = CloseHandle(token_handle);

        if result.is_err() {
            return String::new();
        }

        let token_user = &*(buf.as_ptr() as *const TOKEN_USER);
        let sid = token_user.User.Sid;
        let mut sid_str = PWSTR(std::ptr::null_mut());
        if ConvertSidToStringSidW(sid, &mut sid_str).is_ok() && !sid_str.is_null() {
            let ptr = sid_str.0;
            let mut len = 0usize;
            let mut p = ptr;
            while *p != 0 {
                len += 1;
                p = p.add(1);
            }
            let result = String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len));
            let _ = LocalFree(HLOCAL(ptr as *mut _));
            result
        } else {
            if !sid_str.is_null() {
                let _ = LocalFree(HLOCAL(sid_str.0 as *mut _));
            }
            String::new()
        }
    }
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
