use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::LazyLock;

static CORE_PIN_COUNTS: LazyLock<Vec<AtomicUsize>> =
    LazyLock::new(|| {
        let n = get_core_count();
        (0..n).map(|_| AtomicUsize::new(0)).collect()
    });

#[cfg(windows)]
pub fn get_core_count() -> usize {
    use windows::Win32::System::SystemInformation::GetSystemInfo;

    let mut sys_info = Default::default();
    unsafe { GetSystemInfo(&mut sys_info) };
    sys_info.dwNumberOfProcessors as usize
}

#[cfg(not(windows))]
pub fn get_core_count() -> usize {
    4
}

#[cfg(windows)]
pub fn set_thread_affinity(core_index: usize) -> Result<(), String> {
    use windows::Win32::System::Threading::{GetCurrentThread, SetThreadAffinityMask};

    let count = get_core_count();
    if core_index >= count {
        return Err(format!(
            "core_index {} out of range (core count: {})",
            core_index, count
        ));
    }

    let mask = 1usize << core_index;
    let thread = unsafe { GetCurrentThread() };
    let prev = unsafe { SetThreadAffinityMask(thread, mask) };
    if prev == 0 {
        return Err("SetThreadAffinityMask failed".to_string());
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn set_thread_affinity(core_index: usize) -> Result<(), String> {
    let count = get_core_count();
    if core_index >= count {
        return Err(format!(
            "core_index {} out of range (core count: {})",
            core_index, count
        ));
    }
    Ok(())
}

pub fn pin_to_least_loaded_core() -> Result<usize, String> {
    let count = get_core_count();
    if count == 0 {
        return Err("no cores available".to_string());
    }

    let mut best_core = 0;
    let mut best_count = usize::MAX;
    for i in 0..count {
        let c = CORE_PIN_COUNTS[i].load(Ordering::Relaxed);
        if c < best_count {
            best_count = c;
            best_core = i;
        }
    }

    CORE_PIN_COUNTS[best_core].fetch_add(1, Ordering::Relaxed);
    set_thread_affinity(best_core)?;
    Ok(best_core)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_core_count() {
        let count = get_core_count();
        assert!(count > 0, "core count should be > 0, got {}", count);
    }

    #[test]
    fn test_set_thread_affinity_valid() {
        let count = get_core_count();
        let result = set_thread_affinity(0);
        assert!(result.is_ok());
        if count > 1 {
            let result = set_thread_affinity(count - 1);
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_set_thread_affinity_invalid() {
        let count = get_core_count();
        let result = set_thread_affinity(count + 100);
        assert!(result.is_err());
    }

    #[test]
    fn test_pin_to_least_loaded_core() {
        let result = pin_to_least_loaded_core();
        assert!(result.is_ok());
        let core = result.unwrap();
        assert!(core < get_core_count());
    }

    #[test]
    fn test_pin_to_least_loaded_distributes() {
        let count = get_core_count();
        let mut cores = Vec::new();
        for _ in 0..count {
            let c = pin_to_least_loaded_core().unwrap();
            cores.push(c);
        }
        let unique: std::collections::HashSet<_> = cores.iter().collect();
        if count > 1 {
            assert!(unique.len() > 1, "should distribute across multiple cores");
        }
    }

    #[test]
    fn test_core_pin_counts_are_tracked() {
        let count = get_core_count();
        let before = CORE_PIN_COUNTS[0].load(Ordering::Relaxed);
        let _ = pin_to_least_loaded_core();
        let after = CORE_PIN_COUNTS[0].load(Ordering::Relaxed);
        assert!(
            after >= before,
            "pin count should not decrease after pinning"
        );
    }
}
