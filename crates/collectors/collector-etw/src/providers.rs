pub const GUID_KERNEL_PROCESS: &str = "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716";
pub const GUID_KERNEL_FILEIO: &str = "bed7cf1b-0c93-4be4-b4a7-5b0b0c84e6a8";
pub const GUID_KERNEL_NETWORK: &str = "7dd42a49-5329-4832-8dfd-1e22f7e3b6ae";
pub const GUID_KERNEL_REGISTRY: &str = "76577757-7206-4fa2-8069-80ecbc02c22f";
pub const GUID_SECURITY_AUDITING: &str = "54849625-5478-4994-a5ba-3e3b0328c30d";
pub const GUID_POWERSHELL: &str = "a0c1853b-5c40-4b15-8766-3cf1c58f985a";
pub const GUID_WMI_ACTIVITY: &str = "1418ef04-b0b4-4623-84f0-0f3be4d0de86";
pub const GUID_AMSI: &str = "2e5e8c86-85dc-47dc-84cf-9a567241aeb5";
pub const GUID_THREAT_INTEL: &str = "0ea14858-018a-4401-b4be-f3d0bfb90303";
pub const GUID_DNS_CLIENT: &str = "1c95122e-7180-4591-9bb3-f44be68d2e25";

#[derive(Debug, Clone)]
pub struct ProviderInfo {
    pub name: &'static str,
    pub guid: &'static str,
    pub description: &'static str,
    pub events: Vec<EventInfo>,
}

#[derive(Debug, Clone)]
pub struct EventInfo {
    pub id: u16,
    pub name: &'static str,
    pub description: &'static str,
}

pub fn kernel_process_events() -> Vec<EventInfo> {
    vec![
        EventInfo { id: 1, name: "ProcessStart", description: "A new process has been created" },
        EventInfo { id: 2, name: "ProcessStop", description: "A process has exited" },
        EventInfo { id: 3, name: "ProcessDCStart", description: "Process start during DC start" },
        EventInfo { id: 4, name: "ProcessDCStop", description: "Process stop during DC stop" },
    ]
}

pub fn kernel_fileio_events() -> Vec<EventInfo> {
    vec![
        EventInfo { id: 10, name: "FileIORead", description: "File read operation" },
        EventInfo { id: 11, name: "FileIOWrite", description: "File write operation" },
        EventInfo { id: 12, name: "FileIOCreate", description: "File create operation" },
        EventInfo { id: 13, name: "FileIODelete", description: "File delete operation" },
        EventInfo { id: 14, name: "FileIORename", description: "File rename operation" },
    ]
}

pub fn kernel_network_events() -> Vec<EventInfo> {
    vec![
        EventInfo { id: 10, name: "TCPConnect", description: "TCP connection initiated" },
        EventInfo { id: 11, name: "TCPClose", description: "TCP connection closed" },
        EventInfo { id: 12, name: "TCPRecv", description: "TCP data received" },
        EventInfo { id: 13, name: "TCPSend", description: "TCP data sent" },
        EventInfo { id: 14, name: "UDPRecv", description: "UDP data received" },
        EventInfo { id: 15, name: "UDPSend", description: "UDP data sent" },
    ]
}

pub fn kernel_registry_events() -> Vec<EventInfo> {
    vec![
        EventInfo { id: 10, name: "RegCreateKey", description: "Registry key created" },
        EventInfo { id: 11, name: "RegDeleteKey", description: "Registry key deleted" },
        EventInfo { id: 12, name: "RegSetValue", description: "Registry value set" },
        EventInfo { id: 13, name: "RegDeleteValue", description: "Registry value deleted" },
        EventInfo { id: 14, name: "RegQueryKey", description: "Registry key queried" },
        EventInfo { id: 15, name: "RegQueryValue", description: "Registry value queried" },
    ]
}
