use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    pub hostname: String,
    pub os_version: String,
    pub architecture: String,
    pub uptime_secs: u64,
    pub total_memory_mb: u64,
    pub available_memory_mb: u64,
    pub cpu_count: u32,
    pub cpu_usage_percent: f64,
}

#[cfg(windows)]
pub fn get_system_info() -> SystemInfo {
    use windows::Win32::System::SystemInformation::{GetSystemInfo, GlobalMemoryStatusEx};

    let mut sys_info = Default::default();
    unsafe { GetSystemInfo(&mut sys_info) };

    let mut mem_status = windows::Win32::System::SystemInformation::MEMORYSTATUSEX {
        dwLength: std::mem::size_of::<
            windows::Win32::System::SystemInformation::MEMORYSTATUSEX,
        >() as u32,
        ..Default::default()
    };
    unsafe { GlobalMemoryStatusEx(&mut mem_status).ok() };

    let hostname = std::env::var("COMPUTERNAME")
        .unwrap_or_else(|_| "unknown".to_string());

    let arch = unsafe { sys_info.Anonymous.Anonymous.wProcessorArchitecture.0 };
    let arch_str = match arch {
        0 => "x86".to_string(),
        9 => "x86_64".to_string(),
        12 => "ARM64".to_string(),
        _ => format!("Unknown({})", arch),
    };

    SystemInfo {
        hostname,
        os_version: "Windows".to_string(),
        architecture: arch_str,
        uptime_secs: get_uptime_secs(),
        total_memory_mb: (mem_status.ullTotalPhys / 1024 / 1024) as u64,
        available_memory_mb: (mem_status.ullAvailPhys / 1024 / 1024) as u64,
        cpu_count: sys_info.dwNumberOfProcessors,
        cpu_usage_percent: get_cpu_usage(),
    }
}

#[cfg(not(windows))]
pub fn get_system_info() -> SystemInfo {
    SystemInfo {
        hostname: "DESKTOP-TEST".to_string(),
        os_version: "Windows 11 Pro 22H2".to_string(),
        architecture: "x86_64".to_string(),
        uptime_secs: 3600 * 24 + 7200,
        total_memory_mb: 16384,
        available_memory_mb: 8192,
        cpu_count: 8,
        cpu_usage_percent: 12.5,
    }
}

#[cfg(windows)]
pub fn get_uptime_secs() -> u64 {
    use windows::Win32::System::SystemInformation::GetTickCount64;
    unsafe { GetTickCount64() / 1000 }
}

#[cfg(not(windows))]
pub fn get_uptime_secs() -> u64 {
    3600 * 24 + 7200
}

#[cfg(windows)]
pub fn get_memory_usage() -> (u64, u64) {
    use windows::Win32::System::SystemInformation::GlobalMemoryStatusEx;

    let mut mem_status = windows::Win32::System::SystemInformation::MEMORYSTATUSEX {
        dwLength: std::mem::size_of::<
            windows::Win32::System::SystemInformation::MEMORYSTATUSEX,
        >() as u32,
        ..Default::default()
    };
    unsafe { GlobalMemoryStatusEx(&mut mem_status).ok() };

    let total = (mem_status.ullTotalPhys / 1024 / 1024) as u64;
    let available = (mem_status.ullAvailPhys / 1024 / 1024) as u64;
    (total - available, total)
}

#[cfg(not(windows))]
pub fn get_memory_usage() -> (u64, u64) {
    (8192, 16384)
}

#[cfg(windows)]
pub fn get_cpu_usage() -> f64 {
    use windows::Win32::System::Performance::{
        PdhAddEnglishCounterW, PdhCollectQueryData, PdhGetFormattedCounterValue, PdhOpenQueryW,
        PDH_FMT_DOUBLE,
    };

    unsafe {
        let mut query = Default::default();
        if PdhOpenQueryW(None, 0, &mut query) != 0 {
            return 0.0;
        }

        let counter_path = windows::core::PCWSTR::from_raw(
            windows::core::w!("\\Processor(_Total)\\% Processor Time").as_ptr(),
        );
        let mut counter = Default::default();
        if PdhAddEnglishCounterW(query, counter_path, 0, &mut counter) != 0 {
            return 0.0;
        }

        let _ = PdhCollectQueryData(query);
        let mut value = Default::default();
        let status = PdhGetFormattedCounterValue(counter, PDH_FMT_DOUBLE, None, &mut value);
        if status == 0 {
            value.Anonymous.doubleValue
        } else {
            0.0
        }
    }
}

#[cfg(not(windows))]
pub fn get_cpu_usage() -> f64 {
    12.5
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_system_info() {
        let info = get_system_info();
        assert!(!info.hostname.is_empty());
        assert!(!info.os_version.is_empty());
        assert!(info.cpu_count > 0);
    }

    #[test]
    fn test_get_uptime_secs() {
        let uptime = get_uptime_secs();
        assert!(uptime > 0);
    }

    #[test]
    fn test_get_memory_usage() {
        let (used, total) = get_memory_usage();
        assert!(total > 0);
        assert!(used <= total);
    }

    #[test]
    fn test_get_cpu_usage() {
        let cpu = get_cpu_usage();
        assert!(cpu >= 0.0 && cpu <= 100.0);
    }
}
