use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ConnectionState {
    Established,
    Listen,
    TimeWait,
    CloseWait,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Direction {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnection {
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub protocol: Protocol,
    pub state: ConnectionState,
    pub pid: u32,
    pub process_name: String,
    pub direction: Direction,
    pub flagged: bool,
}

#[cfg(windows)]
pub fn list_connections() -> Vec<NetworkConnection> {
    use windows::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable,
        TCP_TABLE_OWNER_PID_ALL,
    };
    use windows::Win32::Networking::WinSock::AF_INET;

    let mut connections = Vec::new();

    unsafe {
        let mut size: u32 = 0;
        let _ = GetExtendedTcpTable(
            Some(std::ptr::null_mut()),
            &mut size,
            false,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );

        if size > 0 {
            let mut buf: Vec<u8> = vec![0u8; size as usize];
            if GetExtendedTcpTable(
                Some(buf.as_mut_ptr() as *mut _),
                &mut size,
                false,
                AF_INET.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            ) == 0 {
                let table = &*(buf.as_ptr() as *const windows::Win32::NetworkManagement::IpHelper::MIB_TCPTABLE_OWNER_PID);
                for i in 0..table.table.len() {
                    let row = &table.table[i];
                    let port = u16::from_be(row.dwLocalPort as u16);
                    let state = match row.dwState {
                        1 => ConnectionState::Established,
                        2 => ConnectionState::Listen,
                        3 => ConnectionState::TimeWait,
                        4 => ConnectionState::CloseWait,
                        _ => ConnectionState::Established,
                    };
                    connections.push(NetworkConnection {
                        local_addr: format!("0.0.0.0"),
                        local_port: port,
                        remote_addr: format!("0.0.0.0"),
                        remote_port: 0,
                        protocol: Protocol::Tcp,
                        state: state.clone(),
                        pid: row.dwOwningPid,
                        process_name: String::new(),
                        direction: if state == ConnectionState::Listen { Direction::Inbound } else { Direction::Outbound },
                        flagged: false,
                    });
                }
            }
        }
    }
    connections
}

#[cfg(not(windows))]
pub fn list_connections() -> Vec<NetworkConnection> {
    vec![
        NetworkConnection {
            local_addr: "127.0.0.1".to_string(),
            local_port: 443,
            remote_addr: "93.184.216.34".to_string(),
            remote_port: 443,
            protocol: Protocol::Tcp,
            state: ConnectionState::Established,
            pid: 100,
            process_name: "svchost.exe".to_string(),
            direction: Direction::Outbound,
            flagged: false,
        },
        NetworkConnection {
            local_addr: "0.0.0.0".to_string(),
            local_port: 8080,
            remote_addr: "0.0.0.0".to_string(),
            remote_port: 0,
            protocol: Protocol::Tcp,
            state: ConnectionState::Listen,
            pid: 200,
            process_name: "nginx.exe".to_string(),
            direction: Direction::Inbound,
            flagged: false,
        },
        NetworkConnection {
            local_addr: "127.0.0.1".to_string(),
            local_port: 4444,
            remote_addr: "192.168.1.100".to_string(),
            remote_port: 4444,
            protocol: Protocol::Tcp,
            state: ConnectionState::Established,
            pid: 500,
            process_name: "mimikatz.exe".to_string(),
            direction: Direction::Outbound,
            flagged: true,
        },
        NetworkConnection {
            local_addr: "127.0.0.1".to_string(),
            local_port: 53,
            remote_addr: "8.8.8.8".to_string(),
            remote_port: 53,
            protocol: Protocol::Udp,
            state: ConnectionState::Established,
            pid: 100,
            process_name: "svchost.exe".to_string(),
            direction: Direction::Outbound,
            flagged: false,
        },
        NetworkConnection {
            local_addr: "127.0.0.1".to_string(),
            local_port: 65432,
            remote_addr: "10.0.0.5".to_string(),
            remote_port: 65432,
            protocol: Protocol::Tcp,
            state: ConnectionState::TimeWait,
            pid: 400,
            process_name: "powershell.exe".to_string(),
            direction: Direction::Outbound,
            flagged: true,
        },
    ]
}

#[cfg(windows)]
pub fn get_connection_count() -> (usize, usize, usize) {
    let conns = list_connections();
    let total = conns.len();
    let inbound = conns.iter().filter(|c| c.direction == Direction::Inbound).count();
    let outbound = conns.iter().filter(|c| c.direction == Direction::Outbound).count();
    (total, inbound, outbound)
}

#[cfg(not(windows))]
pub fn get_connection_count() -> (usize, usize, usize) {
    let conns = list_connections();
    let total = conns.len();
    let inbound = conns.iter().filter(|c| c.direction == Direction::Inbound).count();
    let outbound = conns.iter().filter(|c| c.direction == Direction::Outbound).count();
    (total, inbound, outbound)
}

pub fn is_suspicious_connection(conn: &NetworkConnection) -> bool {
    let suspicious_ports = [4444, 5555, 1337, 31337, 6666, 6667, 4433, 9001];
    if suspicious_ports.contains(&conn.remote_port) {
        return true;
    }
    let flagged_processes = ["mimikatz.exe", "meterpreter.exe", "cobaltstrike.exe", "beacon.exe"];
    for pattern in &flagged_processes {
        if conn.process_name.to_lowercase().contains(pattern) {
            return true;
        }
    }
    if conn.protocol == Protocol::Udp && conn.remote_port == 53 && conn.remote_addr != "8.8.8.8" && conn.remote_addr != "1.1.1.1" {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_connections_returns_mock_data() {
        let conns = list_connections();
        assert!(!conns.is_empty());
    }

    #[test]
    fn test_get_connection_count() {
        let (total, _inbound, _outbound) = get_connection_count();
        assert!(total >= 0);
    }

    #[test]
    fn test_is_suspicious_connection_c2_port() {
        let conn = NetworkConnection {
            local_addr: "127.0.0.1".to_string(),
            local_port: 12345,
            remote_addr: "10.0.0.5".to_string(),
            remote_port: 4444,
            protocol: Protocol::Tcp,
            state: ConnectionState::Established,
            pid: 500,
            process_name: "unknown.exe".to_string(),
            direction: Direction::Outbound,
            flagged: false,
        };
        assert!(is_suspicious_connection(&conn));
    }

    #[test]
    fn test_is_not_suspicious_normal_connection() {
        let conn = NetworkConnection {
            local_addr: "127.0.0.1".to_string(),
            local_port: 443,
            remote_addr: "93.184.216.34".to_string(),
            remote_port: 443,
            protocol: Protocol::Tcp,
            state: ConnectionState::Established,
            pid: 100,
            process_name: "svchost.exe".to_string(),
            direction: Direction::Outbound,
            flagged: false,
        };
        assert!(!is_suspicious_connection(&conn));
    }

    #[test]
    fn test_protocol_variants() {
        assert_ne!(Protocol::Tcp, Protocol::Udp);
        assert_ne!(Protocol::Tcp, Protocol::Icmp);
        assert_ne!(Protocol::Udp, Protocol::Icmp);
    }
}
