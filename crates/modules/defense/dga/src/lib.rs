pub mod prelude;

use royalsecurity_common::types::*;
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use tracing::{warn, info, debug};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DgaConfig {
    pub entropy_threshold: f64,
    pub min_domain_length: usize,
    pub consonant_ratio_threshold: f64,
    pub unique_subdomain_threshold: f64,
    pub query_frequency_threshold: u32,
    pub dictionary_check: bool,
    pub min_queries_for_analysis: u32,
}

impl Default for DgaConfig {
    fn default() -> Self {
        Self {
            entropy_threshold: 3.8,
            min_domain_length: 8,
            consonant_ratio_threshold: 0.65,
            unique_subdomain_threshold: 0.8,
            query_frequency_threshold: 30,
            dictionary_check: true,
            min_queries_for_analysis: 5,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainAnalysis {
    pub domain: String,
    pub entropy: f64,
    pub length: usize,
    pub consonant_ratio: f64,
    pub vowel_ratio: f64,
    pub digit_ratio: f64,
    pub unique_chars: usize,
    pub bigram_entropy: f64,
    pub contains_dictionary_word: bool,
    pub dga_score: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DgaType {
    RandomDga,
    NumericDga,
    CombinationDga,
    NgramDga,
    WordlistDga,
    BitDga,
}

impl std::fmt::Display for DgaType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DgaType::RandomDga => write!(f, "RandomDga"),
            DgaType::NumericDga => write!(f, "NumericDga"),
            DgaType::CombinationDga => write!(f, "CombinationDga"),
            DgaType::NgramDga => write!(f, "NgramDga"),
            DgaType::WordlistDga => write!(f, "WordlistDga"),
            DgaType::BitDga => write!(f, "BitDga"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DgaDetection {
    pub id: Uuid,
    pub dga_type: DgaType,
    pub domain: String,
    pub process_pid: Option<u32>,
    pub process_name: Option<String>,
    pub severity: EventSeverity,
    pub confidence: f32,
    pub dga_score: f64,
    pub entropy: f64,
    pub description: String,
    pub evidence: Vec<String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NgramStats {
    pub bigram_entropy: f64,
    pub trigram_entropy: f64,
    pub most_common_bigram: String,
    pub most_common_trigram: String,
}

pub struct DgaDetector {
    domain_history: HashMap<String, Vec<DnsEvent>>,
    process_domains: HashMap<u32, Vec<String>>,
    detections: Vec<DgaDetection>,
    config: DgaConfig,
    detection_count: u64,
}

const COMMON_WORDS: &[&str] = &[
    "the", "and", "for", "are", "but", "not", "you", "all", "can", "had",
    "her", "was", "one", "our", "out", "day", "get", "has", "him", "his",
    "how", "its", "may", "new", "now", "old", "see", "way", "who", "did",
    "big", "end", "far", "got", "let", "say", "she", "too", "use", "web",
    "map", "run", "top", "box", "red", "set", "try", "ask", "men", "own",
    "put", "say", "six", "ten", "add", "age", "ago", "air", "arm", "art",
    "bad", "bag", "ball", "bank", "best", "bird", "bit", "book", "boss",
    "buy", "car", "cat", "city", "cold", "come", "cool", "cost", "dark",
    "data", "date", "deal", "deep", "dog", "door", "down", "draw", "east",
    "easy", "edge", "face", "fact", "fail", "fair", "fall", "farm", "fast",
    "feed", "feel", "file", "fill", "film", "find", "fine", "fire", "fish",
    "fix", "fly", "food", "foot", "form", "free", "full", "game", "gave",
    "gift", "girl", "give", "glad", "goal", "goes", "gold", "gone", "good",
    "grew", "grow", "hand", "hang", "hard", "hate", "head", "help", "hide",
    "high", "hill", "hire", "hold", "home", "hope", "hour", "huge", "idea",
    "into", "iron", "item", "jack", "jazz", "join", "jump", "jury", "just",
    "keen", "keep", "kept", "kill", "king", "knew", "know", "lack", "laid",
    "lake", "land", "lane", "last", "late", "lead", "left", "less", "life",
    "lift", "like", "line", "link", "list", "live", "lock", "long", "look",
    "lord", "loss", "lost", "love", "made", "main", "make", "male", "many",
    "mark", "mass", "math", "meal", "mean", "meet", "milk", "mind", "mine",
    "miss", "mode", "moon", "move", "much", "must", "name", "near", "need",
    "news", "next", "nice", "node", "none", "nose", "note", "okay", "only",
    "open", "oral", "page", "pain", "pair", "pale", "pan", "park", "part",
    "pass", "past", "path", "peak", "pick", "plan", "play", "plot", "plug",
    "plus", "poem", "poor", "port", "post", "pull", "pure", "push", "race",
    "rain", "rank", "rare", "rate", "read", "real", "rest", "rich", "ride",
    "ring", "rise", "risk", "road", "rock", "role", "roll", "root", "rose",
    "rule", "rush", "safe", "said", "sake", "sale", "salt", "same", "sand",
    "save", "seat", "seek", "seem", "seen", "self", "sell", "send", "ship",
    "shop", "shot", "show", "shut", "sick", "side", "sign", "sing", "site",
    "size", "skin", "slip", "slow", "snow", "soft", "soil", "sold", "sole",
    "some", "song", "soon", "sort", "soul", "spot", "star", "stay", "step",
    "stop", "such", "sure", "swim", "tail", "take", "tale", "talk", "tall",
    "team", "tell", "test", "text", "than", "that", "them", "then", "they",
    "thin", "this", "thus", "till", "time", "tiny", "told", "tone", "took",
    "tool", "trip", "true", "turn", "type", "unit", "upon", "used", "user",
    "vast", "very", "view", "vine", "vote", "wage", "wait", "wake", "walk",
    "wall", "want", "warm", "warn", "wash", "wave", "weak", "wear", "week",
    "well", "went", "were", "west", "what", "when", "whom", "wide", "wife",
    "wild", "will", "wind", "wine", "wing", "wire", "wise", "wish", "with",
    "wolf", "wood", "word", "wore", "work", "yard", "yeah", "year", "yell",
    "your", "zone",
    "google", "facebook", "microsoft", "amazon", "apple",
    "login", "email", "server", "client", "admin", "test",
];

impl DgaDetector {
    pub fn new() -> Self {
        info!("Initializing DGA detector with default configuration");
        Self {
            domain_history: HashMap::new(),
            process_domains: HashMap::new(),
            detections: Vec::new(),
            config: DgaConfig::default(),
            detection_count: 0,
        }
    }

    pub fn with_config(config: DgaConfig) -> Self {
        info!("Initializing DGA detector with custom configuration");
        Self {
            domain_history: HashMap::new(),
            process_domains: HashMap::new(),
            detections: Vec::new(),
            config,
            detection_count: 0,
        }
    }

    pub fn analyze_dns_event(
        &mut self,
        event: &DnsEvent,
        process_pid: Option<u32>,
        process_name: Option<&str>,
    ) -> Option<DgaDetection> {
        let domain = event.query.trim_end_matches('.').to_lowercase();
        if domain.len() < self.config.min_domain_length {
            debug!(domain = %domain, "Domain below minimum length, skipping");
            return None;
        }

        if let Some(pid) = process_pid {
            self.process_domains
                .entry(pid)
                .or_default()
                .push(domain.clone());
        }

        self.domain_history
            .entry(domain.clone())
            .or_default()
            .push(event.clone());

        let history_count = self.domain_history.get(&domain).map_or(0, |v| v.len() as u32);
        if history_count < self.config.min_queries_for_analysis {
            debug!(domain = %domain, count = history_count, "Below minimum query count");
            return None;
        }

        let analysis = self.analyze_domain(&domain);
        if analysis.dga_score <= self.config.entropy_threshold {
            debug!(
                domain = %domain,
                score = analysis.dga_score,
                threshold = self.config.entropy_threshold,
                "Domain below DGA threshold"
            );
            return None;
        }

        let dga_type = self.classify_dga_type(&analysis);
        let severity = if analysis.dga_score >= 8.0 {
            EventSeverity::Critical
        } else if analysis.dga_score >= 6.0 {
            EventSeverity::High
        } else if analysis.dga_score >= 4.5 {
            EventSeverity::Medium
        } else {
            EventSeverity::Low
        };

        let confidence = (analysis.dga_score / 10.0).min(1.0) as f32;
        let evidence = self.build_evidence(&analysis);

        let detection = DgaDetection {
            id: Uuid::new_v4(),
            dga_type,
            domain: domain.clone(),
            process_pid,
            process_name: process_name.map(|s| s.to_string()),
            severity,
            confidence,
            dga_score: analysis.dga_score,
            entropy: analysis.entropy,
            description: format!(
                "DGA-generated domain detected: {} (entropy: {:.2}, score: {:.2})",
                domain, analysis.entropy, analysis.dga_score
            ),
            evidence,
            timestamp: Utc::now(),
        };

        warn!(
            domain = %domain,
            dga_type = %detection.dga_type,
            score = analysis.dga_score,
            severity = %detection.severity,
            confidence = detection.confidence,
            "DGA domain detected"
        );

        self.detection_count += 1;
        self.detections.push(detection.clone());
        Some(detection)
    }

    pub fn analyze_domain(&self, domain: &str) -> DomainAnalysis {
        let entropy = Self::calculate_shannon_entropy(domain);
        let consonant_ratio = Self::calculate_consonant_ratio(domain);
        let bigram_entropy = Self::calculate_bigram_entropy(domain);
        let contains_dictionary_word = self.check_dictionary_words(domain);

        let alpha_count = domain.chars().filter(|c| c.is_alphabetic()).count();
        let digit_count = domain.chars().filter(|c| c.is_ascii_digit()).count();
        let vowel_count = domain.chars().filter(|c| "aeiou".contains(*c)).count();
        let unique_chars = domain.chars().filter(|c| c.is_alphanumeric()).collect::<std::collections::HashSet<_>>().len();

        let total = domain.len().max(1) as f64;
        let vowel_ratio = if alpha_count > 0 { vowel_count as f64 / alpha_count as f64 } else { 0.0 };
        let digit_ratio = digit_count as f64 / total;

        let dga_score = Self::calculate_dga_score_internal(
            entropy, consonant_ratio, bigram_entropy, contains_dictionary_word,
            domain.len(), unique_chars, digit_ratio,
        );

        DomainAnalysis {
            domain: domain.to_string(),
            entropy,
            length: domain.len(),
            consonant_ratio,
            vowel_ratio,
            digit_ratio,
            unique_chars,
            bigram_entropy,
            contains_dictionary_word,
            dga_score,
        }
    }

    pub fn calculate_shannon_entropy(data: &str) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        let len = data.len() as f64;
        let mut freq = HashMap::new();
        for c in data.chars() {
            *freq.entry(c).or_insert(0u32) += 1;
        }
        let mut entropy = 0.0;
        for &count in freq.values() {
            let p = count as f64 / len;
            if p > 0.0 {
                entropy -= p * p.log2();
            }
        }
        entropy
    }

    pub fn calculate_consonant_ratio(domain: &str) -> f64 {
        let alpha_chars: Vec<char> = domain.chars().filter(|c| c.is_alphabetic()).collect();
        if alpha_chars.is_empty() {
            return 0.0;
        }
        let consonants = alpha_chars.iter().filter(|c| !"aeiou".contains(**c)).count();
        consonants as f64 / alpha_chars.len() as f64
    }

    pub fn calculate_bigram_entropy(domain: &str) -> f64 {
        let chars: Vec<char> = domain.chars().collect();
        if chars.len() < 2 {
            return 0.0;
        }
        let mut bigram_freq: HashMap<(char, char), u32> = HashMap::new();
        for window in chars.windows(2) {
            let bigram = (window[0], window[1]);
            *bigram_freq.entry(bigram).or_insert(0) += 1;
        }
        let total = chars.len() as f64 - 1.0;
        let mut entropy = 0.0;
        for &count in bigram_freq.values() {
            let p = count as f64 / total;
            if p > 0.0 {
                entropy -= p * p.log2();
            }
        }
        entropy
    }

    pub fn check_dictionary_words(&self, domain: &str) -> bool {
        if !self.config.dictionary_check {
            return false;
        }
        let name_part = domain.split('.').next().unwrap_or(domain).to_lowercase();
        if name_part.len() < 3 {
            return false;
        }
        for &word in COMMON_WORDS {
            if word.len() >= 3 && name_part.contains(word) {
                return true;
            }
        }
        false
    }

    pub fn calculate_dga_score(analysis: &DomainAnalysis) -> f64 {
        Self::calculate_dga_score_internal(
            analysis.entropy,
            analysis.consonant_ratio,
            analysis.bigram_entropy,
            analysis.contains_dictionary_word,
            analysis.length,
            analysis.unique_chars,
            analysis.digit_ratio,
        )
    }

    fn calculate_dga_score_internal(
        entropy: f64,
        consonant_ratio: f64,
        bigram_entropy: f64,
        contains_dictionary_word: bool,
        length: usize,
        unique_chars: usize,
        digit_ratio: f64,
    ) -> f64 {
        let mut score = 0.0;

        if entropy > 3.5 {
            score += 2.0 * (entropy / 4.5).min(1.0);
        } else if entropy > 2.5 {
            score += 1.0 * (entropy / 4.5);
        }

        if consonant_ratio > 0.7 {
            score += 2.0;
        } else if consonant_ratio > 0.5 {
            score += 1.0;
        }

        if bigram_entropy > 3.0 {
            score += 1.5 * (bigram_entropy / 4.0).min(1.0);
        } else if bigram_entropy > 2.0 {
            score += 0.75;
        }

        if contains_dictionary_word {
            score -= 1.5;
        }

        if length >= 16 {
            score += 1.0;
        } else if length >= 12 {
            score += 0.5;
        }

        if length > 0 && unique_chars as f64 / length as f64 > 0.7 {
            score += 1.0;
        }

        if digit_ratio > 0.3 {
            score += 1.0;
        } else if digit_ratio > 0.15 {
            score += 0.5;
        }

        score.max(0.0).min(10.0)
    }

    pub fn classify_dga_type(&self, analysis: &DomainAnalysis) -> DgaType {
        let alpha_count = analysis.domain.chars().filter(|c| c.is_alphabetic()).count();
        let digit_count = analysis.domain.chars().filter(|c| c.is_ascii_digit()).count();

        if alpha_count == 0 && digit_count > 0 {
            return DgaType::NumericDga;
        }

        if analysis.consonant_ratio > 0.75 && !analysis.contains_dictionary_word {
            return DgaType::RandomDga;
        }

        if analysis.unique_chars as f64 / analysis.length.max(1) as f64 > 0.85
            && analysis.contains_dictionary_word
        {
            return DgaType::CombinationDga;
        }

        if analysis.bigram_entropy > 3.2 && analysis.unique_chars as f64 / analysis.length.max(1) as f64 > 0.7 {
            return DgaType::NgramDga;
        }

        if analysis.contains_dictionary_word && analysis.digit_ratio > 0.2 {
            return DgaType::WordlistDga;
        }

        if analysis.digit_ratio > 0.4 && analysis.consonant_ratio > 0.5 {
            return DgaType::BitDga;
        }

        if analysis.consonant_ratio > 0.6 {
            return DgaType::RandomDga;
        }

        DgaType::CombinationDga
    }

    fn build_evidence(&self, analysis: &DomainAnalysis) -> Vec<String> {
        let mut evidence = Vec::new();
        evidence.push(format!("Shannon entropy: {:.4} (threshold: {})", analysis.entropy, 3.8));
        evidence.push(format!("Consonant ratio: {:.4}", analysis.consonant_ratio));
        evidence.push(format!("Vowel ratio: {:.4}", analysis.vowel_ratio));
        evidence.push(format!("Digit ratio: {:.4}", analysis.digit_ratio));
        evidence.push(format!("Bigram entropy: {:.4}", analysis.bigram_entropy));
        evidence.push(format!("Unique characters: {}/{}", analysis.unique_chars, analysis.length));
        evidence.push(format!("Contains dictionary word: {}", analysis.contains_dictionary_word));
        evidence.push(format!("Overall DGA score: {:.4}", analysis.dga_score));
        evidence
    }

    pub fn get_suspicious_domains(&self, process_pid: Option<u32>) -> Vec<(String, f64)> {
        let mut results = Vec::new();

        let domains_to_check: Vec<String> = if let Some(pid) = process_pid {
            self.process_domains.get(&pid).cloned().unwrap_or_default()
        } else {
            self.domain_history.keys().cloned().collect()
        };

        for domain in domains_to_check {
            if domain.len() < self.config.min_domain_length {
                continue;
            }
            let analysis = self.analyze_domain(&domain);
            if analysis.dga_score > self.config.entropy_threshold {
                results.push((domain, analysis.dga_score));
            }
        }

        results.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        results
    }

    pub fn detection_count(&self) -> u64 {
        self.detection_count
    }

    pub fn clear(&mut self) {
        info!("Clearing DGA detector state");
        self.domain_history.clear();
        self.process_domains.clear();
        self.detections.clear();
        self.detection_count = 0;
    }
}

impl Default for DgaDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    fn make_dns_event(query: &str) -> DnsEvent {
        DnsEvent {
            query: query.to_string(),
            query_type: "A".to_string(),
            response: Some("1.2.3.4".to_string()),
            response_code: Some("NOERROR".to_string()),
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn test_dga_detector_new() {
        let detector = DgaDetector::new();
        assert_eq!(detector.detection_count(), 0);
        assert!(detector.domain_history.is_empty());
        assert!(detector.process_domains.is_empty());
        assert!(detector.detections.is_empty());
        assert_eq!(detector.config.entropy_threshold, 3.8);
        assert_eq!(detector.config.min_domain_length, 8);
    }

    #[test]
    fn test_dga_detector_with_config() {
        let config = DgaConfig {
            entropy_threshold: 4.5,
            min_domain_length: 12,
            consonant_ratio_threshold: 0.7,
            unique_subdomain_threshold: 0.9,
            query_frequency_threshold: 50,
            dictionary_check: false,
            min_queries_for_analysis: 10,
        };
        let detector = DgaDetector::with_config(config.clone());
        assert_eq!(detector.config.entropy_threshold, 4.5);
        assert_eq!(detector.config.min_domain_length, 12);
        assert!(!detector.config.dictionary_check);
    }

    #[test]
    fn test_calculate_shannon_entropy_uniform() {
        let entropy = DgaDetector::calculate_shannon_entropy("aaaa");
        assert!(entropy < 0.01, "Uniform string should have near-zero entropy, got {}", entropy);
    }

    #[test]
    fn test_calculate_shannon_entropy_high() {
        let entropy = DgaDetector::calculate_shannon_entropy("abcdefghij");
        assert!(entropy > 3.0, "High-entropy string should have entropy > 3.0, got {}", entropy);
    }

    #[test]
    fn test_calculate_shannon_entropy_empty() {
        let entropy = DgaDetector::calculate_shannon_entropy("");
        assert_eq!(entropy, 0.0);
    }

    #[test]
    fn test_calculate_shannon_entropy_binary() {
        let entropy = DgaDetector::calculate_shannon_entropy("01");
        assert!(entropy > 0.9 && entropy < 1.1, "Two-char uniform should have entropy ~1.0, got {}", entropy);
    }

    #[test]
    fn test_analyze_domain_dga_high_entropy() {
        let detector = DgaDetector::new();
        let analysis = detector.analyze_domain("xkqjzmwpnbvhtyr");
        assert!(analysis.entropy > 3.5, "Random-looking domain should have high entropy, got {}", analysis.entropy);
        assert!(analysis.consonant_ratio > 0.6, "Random domain should have high consonant ratio, got {}", analysis.consonant_ratio);
        assert!(analysis.dga_score > 3.0, "DGA domain should score above 3.0, got {}", analysis.dga_score);
        assert!(!analysis.contains_dictionary_word);
    }

    #[test]
    fn test_analyze_domain_normal_low_entropy() {
        let detector = DgaDetector::new();
        let analysis = detector.analyze_domain("aboutme.com");
        assert!(analysis.contains_dictionary_word, "aboutme.com should contain dictionary word 'about'");
        assert!(analysis.dga_score < 6.0, "Normal domain should score below 6.0, got {}", analysis.dga_score);
    }

    #[test]
    fn test_analyze_domain_dictionary_detected() {
        let detector = DgaDetector::new();
        let analysis = detector.analyze_domain("emailserver.com");
        assert!(analysis.contains_dictionary_word, "emailserver contains 'email' and 'server'");
    }

    #[test]
    fn test_calculate_consonant_ratio_all_consonants() {
        let ratio = DgaDetector::calculate_consonant_ratio("bcdfg");
        assert!((ratio - 1.0).abs() < 0.01, "All consonants should give ratio ~1.0, got {}", ratio);
    }

    #[test]
    fn test_calculate_consonant_ratio_all_vowels() {
        let ratio = DgaDetector::calculate_consonant_ratio("aeiou");
        assert!((ratio - 0.0).abs() < 0.01, "All vowels should give ratio ~0.0, got {}", ratio);
    }

    #[test]
    fn test_calculate_consonant_ratio_mixed() {
        let ratio = DgaDetector::calculate_consonant_ratio("abcde");
        assert!((ratio - 0.6).abs() < 0.01, "Mixed ratio should be ~0.6, got {}", ratio);
    }

    #[test]
    fn test_calculate_consonant_ratio_no_alpha() {
        let ratio = DgaDetector::calculate_consonant_ratio("12345");
        assert_eq!(ratio, 0.0, "No alpha should give 0.0");
    }

    #[test]
    fn test_calculate_bigram_entropy() {
        let low = DgaDetector::calculate_bigram_entropy("aaaaaaaaaa");
        let high = DgaDetector::calculate_bigram_entropy("abcdefghijklmnop");
        assert!(low < 1.0, "Repeated chars should have low bigram entropy, got {}", low);
        assert!(high > 2.0, "Varied domain should have higher bigram entropy, got {}", high);
    }

    #[test]
    fn test_check_dictionary_words_found() {
        let detector = DgaDetector::new();
        assert!(detector.check_dictionary_words("mailserver.com"));
        assert!(detector.check_dictionary_words("login-page.net"));
    }

    #[test]
    fn test_check_dictionary_words_not_found() {
        let detector = DgaDetector::new();
        assert!(!detector.check_dictionary_words("xkqjzmwpnbvhtyr.com"));
    }

    #[test]
    fn test_check_dictionary_words_disabled() {
        let config = DgaConfig { dictionary_check: false, ..Default::default() };
        let detector = DgaDetector::with_config(config);
        assert!(!detector.check_dictionary_words("login.com"));
    }

    #[test]
    fn test_calculate_dga_score_dga_higher_than_normal() {
        let dga_analysis = DomainAnalysis {
            domain: "xkqjzmwpnbvhtyr".to_string(),
            entropy: 4.2,
            length: 16,
            consonant_ratio: 0.85,
            vowel_ratio: 0.15,
            digit_ratio: 0.0,
            unique_chars: 14,
            bigram_entropy: 3.5,
            contains_dictionary_word: false,
            dga_score: 0.0,
        };
        let normal_analysis = DomainAnalysis {
            domain: "google.com".to_string(),
            entropy: 2.8,
            length: 10,
            consonant_ratio: 0.5,
            vowel_ratio: 0.5,
            digit_ratio: 0.0,
            unique_chars: 7,
            bigram_entropy: 2.5,
            contains_dictionary_word: true,
            dga_score: 0.0,
        };
        let dga_score = DgaDetector::calculate_dga_score(&dga_analysis);
        let normal_score = DgaDetector::calculate_dga_score(&normal_analysis);
        assert!(dga_score > normal_score, "DGA score ({}) should exceed normal score ({})", dga_score, normal_score);
    }

    #[test]
    fn test_classify_dga_type_numeric() {
        let detector = DgaDetector::new();
        let analysis = DomainAnalysis {
            domain: "12345678".to_string(),
            entropy: 3.0,
            length: 8,
            consonant_ratio: 0.0,
            vowel_ratio: 0.0,
            digit_ratio: 1.0,
            unique_chars: 8,
            bigram_entropy: 2.0,
            contains_dictionary_word: false,
            dga_score: 5.0,
        };
        assert_eq!(detector.classify_dga_type(&analysis), DgaType::NumericDga);
    }

    #[test]
    fn test_classify_dga_type_random() {
        let detector = DgaDetector::new();
        let analysis = DomainAnalysis {
            domain: "xkqjzmwpnbvhtyr".to_string(),
            entropy: 4.2,
            length: 16,
            consonant_ratio: 0.875,
            vowel_ratio: 0.125,
            digit_ratio: 0.0,
            unique_chars: 14,
            bigram_entropy: 3.5,
            contains_dictionary_word: false,
            dga_score: 7.0,
        };
        assert_eq!(detector.classify_dga_type(&analysis), DgaType::RandomDga);
    }

    #[test]
    fn test_analyze_dns_event_triggers_on_suspicious_domain() {
        let mut detector = DgaDetector::new();
        let suspicious_domain = "xkqjzmwpnbvhtyr.com";
        for _ in 0..10 {
            let event = make_dns_event(suspicious_domain);
            detector.analyze_dns_event(&event, Some(1234), Some("malware.exe"));
        }
        let detection = detector.analyze_dns_event(
            &make_dns_event(suspicious_domain), Some(1234), Some("malware.exe"),
        );
        assert!(detection.is_some(), "Suspicious domain should trigger detection");
        let det = detection.unwrap();
        assert_eq!(det.process_pid, Some(1234));
        assert_eq!(det.process_name.as_deref(), Some("malware.exe"));
        assert!(det.dga_score > detector.config.entropy_threshold);
        assert!(!det.evidence.is_empty());
    }

    #[test]
    fn test_analyze_dns_event_below_threshold_no_trigger() {
        let mut detector = DgaDetector::new();
        for i in 0..10 {
            let event = make_dns_event(&format!("google{}.com", i));
            detector.analyze_dns_event(&event, None, None);
        }
        let event = make_dns_event("google.com");
        let detection = detector.analyze_dns_event(&event, None, None);
        assert!(detection.is_none(), "Normal domain should not trigger detection");
    }

    #[test]
    fn test_analyze_dns_event_below_min_length() {
        let mut detector = DgaDetector::new();
        let event = make_dns_event("a.com");
        let detection = detector.analyze_dns_event(&event, None, None);
        assert!(detection.is_none(), "Very short domain should not trigger");
    }

    #[test]
    fn test_get_suspicious_domains() {
        let mut detector = DgaDetector::new();
        for _ in 0..10 {
            detector.domain_history
                .entry("xkqjzmwpnbvhtyr.com".to_string())
                .or_default()
                .push(make_dns_event("xkqjzmwpnbvhtyr.com"));
            detector.process_domains
                .entry(1234)
                .or_default()
                .push("xkqjzmwpnbvhtyr.com".to_string());
        }
        detector.domain_history
            .entry("google.com".to_string())
            .or_default()
            .push(make_dns_event("google.com"));

        let suspicious = detector.get_suspicious_domains(Some(1234));
        assert!(!suspicious.is_empty(), "Should find suspicious domains for PID 1234");
        assert!(suspicious.iter().any(|(d, _)| d == "xkqjzmwpnbvhtyr.com"));
    }

    #[test]
    fn test_clear() {
        let mut detector = DgaDetector::new();
        let event = make_dns_event("xkqjzmwpnbvhtyr.com");
        for _ in 0..10 {
            detector.analyze_dns_event(&event, Some(999), Some("test.exe"));
        }
        assert!(detector.detection_count() > 0);
        detector.clear();
        assert_eq!(detector.detection_count(), 0);
        assert!(detector.domain_history.is_empty());
        assert!(detector.process_domains.is_empty());
        assert!(detector.detections.is_empty());
    }

    #[test]
    fn test_ngram_stats_creation() {
        let stats = NgramStats {
            bigram_entropy: 3.5,
            trigram_entropy: 2.8,
            most_common_bigram: "th".to_string(),
            most_common_trigram: "the".to_string(),
        };
        assert_eq!(stats.most_common_bigram, "th");
        assert_eq!(stats.most_common_trigram, "the");
    }

    #[test]
    fn test_dga_type_display() {
        assert_eq!(format!("{}", DgaType::RandomDga), "RandomDga");
        assert_eq!(format!("{}", DgaType::NumericDga), "NumericDga");
        assert_eq!(format!("{}", DgaType::CombinationDga), "CombinationDga");
        assert_eq!(format!("{}", DgaType::NgramDga), "NgramDga");
        assert_eq!(format!("{}", DgaType::WordlistDga), "WordlistDga");
        assert_eq!(format!("{}", DgaType::BitDga), "BitDga");
    }

    #[test]
    fn test_dga_score_capped_at_10() {
        let analysis = DomainAnalysis {
            domain: "abcdefghijklmnopqrstuvwxyz0123456789".to_string(),
            entropy: 5.0,
            length: 36,
            consonant_ratio: 0.9,
            vowel_ratio: 0.1,
            digit_ratio: 0.5,
            unique_chars: 36,
            bigram_entropy: 4.5,
            contains_dictionary_word: false,
            dga_score: 0.0,
        };
        let score = DgaDetector::calculate_dga_score(&analysis);
        assert!(score <= 10.0, "Score should be capped at 10.0, got {}", score);
    }
}
