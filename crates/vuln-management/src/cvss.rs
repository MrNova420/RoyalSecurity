use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CvssVector {
    pub attack_vector: String,
    pub attack_complexity: String,
    pub privileges_required: String,
    pub user_interaction: String,
    pub scope: String,
    pub confidentiality: String,
    pub integrity: String,
    pub availability: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CvssScore {
    pub base_score: f64,
    pub temporal_score: f64,
    pub environmental_score: f64,
    pub severity: String,
    pub vector_string: String,
}

impl CvssScore {
    pub fn calculate_v3(vector: &CvssVector) -> Self {
        let av = match vector.attack_vector.as_str() {
            "N" => 0.85, "A" => 0.62, "L" => 0.55, "P" => 0.20, _ => 0.5,
        };
        let ac = match vector.attack_complexity.as_str() {
            "L" => 0.77, "H" => 0.44, _ => 0.5,
        };
        let s = &vector.scope;
        let pr = match vector.privileges_required.as_str() {
            "N" => 0.85,
            "L" => if s == "C" { 0.68 } else { 0.62 },
            "H" => if s == "C" { 0.50 } else { 0.27 },
            _ => 0.5,
        };
        let ui = match vector.user_interaction.as_str() {
            "N" => 0.85, "R" => 0.62, _ => 0.5,
        };

        let isc_base = 1.0 - ((1.0 - impact_sub(&vector.confidentiality))
            * (1.0 - impact_sub(&vector.integrity))
            * (1.0 - impact_sub(&vector.availability)));

        let impact = if s == "C" {
            let isc_expanded = isc_base;
            7.52 * (isc_expanded - 0.029) - 3.25 * (isc_expanded * 0.9731 - 0.02).powi(13)
        } else {
            6.42 * isc_base
        };

        let exploitability = 8.22 * av * ac * pr * ui;

        let base = if impact <= 0.0 {
            0.0
        } else {
            if s == "C" {
                (impact + exploitability).min(10.0)
            } else {
                ((impact + exploitability) * 1.08).min(10.0)
            }
        };

        let base_score = (base * 10.0).ceil() / 10.0;
        let base_score = (base_score * 10.0).round() / 10.0;
        let severity = if base_score >= 9.0 {
            "Critical".to_string()
        } else if base_score >= 7.0 {
            "High".to_string()
        } else if base_score >= 4.0 {
            "Medium".to_string()
        } else {
            "Low".to_string()
        };
        let vector_string = format!(
            "CVSS:3.1/AV:{}/AC:{}/PR:{}/UI:{}/S:{}/C:{}/I:{}/A:{}",
            vector.attack_vector, vector.attack_complexity, vector.privileges_required,
            vector.user_interaction, vector.scope, vector.confidentiality,
            vector.integrity, vector.availability
        );
        CvssScore {
            base_score,
            temporal_score: base_score,
            environmental_score: base_score,
            severity,
            vector_string,
        }
    }
}

fn impact_sub(value: &str) -> f64 {
    match value { "H" => 0.56, "L" => 0.22, "N" => 0.0, _ => 0.0 }
}

pub fn severity_from_score(score: f64) -> String {
    if score >= 9.0 { "Critical".into() } else if score >= 7.0 { "High".into() } else if score >= 4.0 { "Medium".into() } else { "Low".into() }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SeverityRating {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

impl SeverityRating {
    pub fn from_score(score: f64) -> Self {
        if score >= 9.0 { Self::Critical }
        else if score >= 7.0 { Self::High }
        else if score >= 4.0 { Self::Medium }
        else if score > 0.0 { Self::Low }
        else { Self::Informational }
    }
}

impl std::fmt::Display for SeverityRating {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Critical => write!(f, "Critical"),
            Self::High => write!(f, "High"),
            Self::Medium => write!(f, "Medium"),
            Self::Low => write!(f, "Low"),
            Self::Informational => write!(f, "Informational"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_critical_cvss() {
        let v = CvssVector { attack_vector:"N".into(), attack_complexity:"L".into(), privileges_required:"N".into(), user_interaction:"N".into(), scope:"C".into(), confidentiality:"H".into(), integrity:"H".into(), availability:"H".into() };
        let s = CvssScore::calculate_v3(&v);
        assert!(s.base_score >= 9.0);
        assert_eq!(s.severity, "Critical");
    }
    #[test]
    fn test_low_cvss() {
        let v = CvssVector { attack_vector:"P".into(), attack_complexity:"H".into(), privileges_required:"H".into(), user_interaction:"R".into(), scope:"U".into(), confidentiality:"N".into(), integrity:"L".into(), availability:"N".into() };
        let s = CvssScore::calculate_v3(&v);
        assert!(s.base_score < 4.0);
        assert_eq!(s.severity, "Low");
    }
    #[test]
    fn test_severity_from_score() {
        assert_eq!(severity_from_score(9.5), "Critical");
        assert_eq!(severity_from_score(7.5), "High");
        assert_eq!(severity_from_score(5.0), "Medium");
        assert_eq!(severity_from_score(2.0), "Low");
    }
    #[test]
    fn test_vector_string() {
        let v = CvssVector { attack_vector:"N".into(), attack_complexity:"L".into(), privileges_required:"N".into(), user_interaction:"N".into(), scope:"U".into(), confidentiality:"H".into(), integrity:"H".into(), availability:"H".into() };
        let s = CvssScore::calculate_v3(&v);
        assert!(s.vector_string.contains("CVSS:3.1"));
    }
}
