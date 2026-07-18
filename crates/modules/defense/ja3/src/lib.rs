pub mod prelude;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientHello {
    pub protocol_version: u16,
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub elliptic_curves: Vec<u16>,
    pub signature_algorithms: Vec<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ja3Fingerprint {
    pub hash: String,
    pub protocol: String,
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub elliptic_curves: Vec<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ja3Entry {
    pub hash: String,
    pub malware_family: String,
    pub confidence: f32,
    pub first_seen: String,
}

pub struct Ja3Analyzer {
    known_malicious: HashMap<String, Ja3Entry>,
    fingerprints: Vec<Ja3Fingerprint>,
}

impl Ja3Analyzer {
    pub fn new() -> Self {
        info!("Initializing JA3 fingerprinting analyzer");
        Self {
            known_malicious: HashMap::new(),
            fingerprints: Vec::new(),
        }
    }

    pub fn calculate_ja3(&mut self, client_hello: &ClientHello) -> String {
        let cipher_str = client_hello
            .cipher_suites
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join("-");

        let ext_str = client_hello
            .extensions
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("-");

        let ec_str = client_hello
            .elliptic_curves
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("-");

        let ec_point_str = "0";

        let raw = format!(
            "{},{},{},{},{}",
            client_hello.protocol_version, cipher_str, ext_str, ec_str, ec_point_str
        );

        let hash_bytes = md5_hash(&raw);
        let hash = hash_bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>();

        let fingerprint = Ja3Fingerprint {
            hash: hash.clone(),
            protocol: format!("TLS/{}", client_hello.protocol_version),
            cipher_suites: client_hello.cipher_suites.clone(),
            extensions: client_hello.extensions.clone(),
            elliptic_curves: client_hello.elliptic_curves.clone(),
        };
        self.fingerprints.push(fingerprint);

        hash
    }

    pub fn check_fingerprint(&self, hash: &str) -> Option<Ja3Entry> {
        self.known_malicious.get(hash).cloned()
    }

    pub fn add_malicious_ja3(&mut self, hash: &str, family: &str, confidence: f32) {
        info!(
            hash = hash,
            family = family,
            confidence = confidence,
            "Adding malicious JA3 hash"
        );
        self.known_malicious.insert(
            hash.to_string(),
            Ja3Entry {
                hash: hash.to_string(),
                malware_family: family.to_string(),
                confidence,
                first_seen: Utc::now().to_rfc3339(),
            },
        );
    }

    pub fn get_known_malicious(&self) -> Vec<&Ja3Entry> {
        self.known_malicious.values().collect()
    }

    pub fn is_malicious(&self, hash: &str) -> bool {
        self.known_malicious.contains_key(hash)
    }

    pub fn fingerprints(&self) -> &[Ja3Fingerprint] {
        &self.fingerprints
    }
}

fn md5_hash(data: &str) -> [u8; 16] {
    let bytes = data.as_bytes();
    let mut state = Md5State {
        s: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476],
    };
    md5_compute(&mut state, bytes);
    let mut result = [0u8; 16];
    for i in 0..4 {
        let word = state.s[i].to_le_bytes();
        result[i * 4..(i + 1) * 4].copy_from_slice(&word);
    }
    result
}

struct Md5State {
    s: [u32; 4],
}

fn md5_compute(state: &mut Md5State, message: &[u8]) {
    let mut msg = message.to_vec();
    let bit_len = (msg.len() as u64) * 8;
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    let k: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];

    let s = &mut state.s;

    for chunk in msg.chunks(64) {
        let mut m = [0u32; 16];
        for i in 0..16 {
            m[i] = u32::from_le_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }

        let (mut a, mut b, mut c, mut d) = (s[0], s[1], s[2], s[3]);

        for i in 0..64 {
            let (f_val, g) = match i {
                0..=15 => (((b & c) | (!b & d)), i),
                16..=31 => (((d & b) | (!d & c)), (5 * i + 1) % 16),
                32..=47 => ((b ^ c ^ d), (3 * i + 5) % 16),
                48..=63 => ((c ^ (b | !d)), (7 * i) % 16),
                _ => unreachable!(),
            };

            let temp = d;
            d = c;
            c = b;
            b = b.wrapping_add(
                (a.wrapping_add(f_val).wrapping_add(k[i]).wrapping_add(m[g]))
                    .rotate_left(7)
                    .wrapping_add(b),
            );
            a = temp;
        }

        s[0] = s[0].wrapping_add(a);
        s[1] = s[1].wrapping_add(b);
        s[2] = s[2].wrapping_add(c);
        s[3] = s[3].wrapping_add(d);
    }
}

impl Default for Ja3Analyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_client_hello() -> ClientHello {
        ClientHello {
            protocol_version: 771,
            cipher_suites: vec![4865, 4866, 4867, 49195, 49199],
            extensions: vec![0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 21],
            elliptic_curves: vec![23, 24, 25],
            signature_algorithms: vec![1025, 1027, 515, 513],
        }
    }

    #[test]
    fn test_ja3_analyzer_new() {
        let analyzer = Ja3Analyzer::new();
        assert!(analyzer.known_malicious.is_empty());
        assert!(analyzer.fingerprints.is_empty());
    }

    #[test]
    fn test_calculate_ja3_deterministic() {
        let mut analyzer = Ja3Analyzer::new();
        let ch = make_client_hello();
        let hash1 = analyzer.calculate_ja3(&ch);
        let hash2 = analyzer.calculate_ja3(&ch);
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32);
    }

    #[test]
    fn test_calculate_ja3_different_inputs() {
        let mut analyzer = Ja3Analyzer::new();
        let ch1 = make_client_hello();
        let mut ch2 = make_client_hello();
        ch2.cipher_suites.push(9999);
        let hash1 = analyzer.calculate_ja3(&ch1);
        let hash2 = analyzer.calculate_ja3(&ch2);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_add_malicious_ja3_and_check() {
        let mut analyzer = Ja3Analyzer::new();
        let hash = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6";
        analyzer.add_malicious_ja3(hash, "TrickBot", 0.95);
        assert!(analyzer.is_malicious(hash));
        let entry = analyzer.check_fingerprint(hash);
        let entry = entry.unwrap();
        assert_eq!(entry.malware_family, "TrickBot");
        assert!((entry.confidence - 0.95).abs() < f32::EPSILON);
    }

    #[test]
    fn test_is_not_malicious_unknown() {
        let analyzer = Ja3Analyzer::new();
        assert!(!analyzer.is_malicious("unknown_hash"));
        assert!(analyzer.check_fingerprint("unknown_hash").is_none());
    }

    #[test]
    fn test_get_known_malicious() {
        let mut analyzer = Ja3Analyzer::new();
        analyzer.add_malicious_ja3("hash1", "Emotet", 0.9);
        analyzer.add_malicious_ja3("hash2", "CobaltStrike", 0.85);
        let entries = analyzer.get_known_malicious();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_fingerprints_stored_after_calc() {
        let mut analyzer = Ja3Analyzer::new();
        let ch = make_client_hello();
        analyzer.calculate_ja3(&ch);
        assert_eq!(analyzer.fingerprints().len(), 1);
        assert_eq!(analyzer.fingerprints()[0].protocol, "TLS/771");
    }
}
