pub mod prelude;

use chrono::{DateTime, Datelike, Timelike, Utc, Weekday};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info, warn};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum EntityType {
    Host,
    IpAddress,
    Domain,
    Process,
    File,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AnomalyType {
    UnusualLoginTime,
    UnusualVolume,
    UnusualDestination,
    PrivilegeAbuse,
    DataExfiltration,
    UnusualProcess,
    ImpossibleTravel,
    UnusualFileAccess,
    UnusualNetworkActivity,
    OffHoursActivity,
    NewResourceAccess,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeSeriesStats {
    pub mean: f64,
    pub std_dev: f64,
    pub min: f64,
    pub max: f64,
    pub sample_count: u32,
    pub last_updated: DateTime<Utc>,
}

impl Default for TimeSeriesStats {
    fn default() -> Self {
        Self {
            mean: 0.0,
            std_dev: 0.0,
            min: f64::MAX,
            max: f64::MIN,
            sample_count: 0,
            last_updated: Utc::now(),
        }
    }
}

impl TimeSeriesStats {
    pub fn update(&mut self, value: f64) {
        let n = self.sample_count as f64;
        let new_n = n + 1.0;
        let old_mean = self.mean;
        self.mean = (n * self.mean + value) / new_n;
        if self.sample_count > 0 {
            let delta = value - old_mean;
            let new_delta = value - self.mean;
            self.std_dev = ((n * (self.std_dev * self.std_dev) + delta * new_delta) / new_n).sqrt();
        }
        self.min = self.min.min(value);
        self.max = self.max.max(value);
        self.sample_count += 1;
        self.last_updated = Utc::now();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HourDistribution {
    pub hour_counts: [u32; 24],
}

impl Default for HourDistribution {
    fn default() -> Self {
        Self {
            hour_counts: [0; 24],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DayDistribution {
    pub day_counts: [u32; 7],
}

impl Default for DayDistribution {
    fn default() -> Self {
        Self {
            day_counts: [0; 7],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityBaseline {
    pub logins_per_day: TimeSeriesStats,
    pub files_accessed_per_day: TimeSeriesStats,
    pub network_connections_per_day: TimeSeriesStats,
    pub processes_spawned_per_day: TimeSeriesStats,
    pub active_hours: HourDistribution,
    pub active_days: DayDistribution,
}

impl Default for ActivityBaseline {
    fn default() -> Self {
        Self {
            logins_per_day: TimeSeriesStats::default(),
            files_accessed_per_day: TimeSeriesStats::default(),
            network_connections_per_day: TimeSeriesStats::default(),
            processes_spawned_per_day: TimeSeriesStats::default(),
            active_hours: HourDistribution::default(),
            active_days: DayDistribution::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessPattern {
    pub resource: String,
    pub access_count: u32,
    pub first_access: DateTime<Utc>,
    pub last_access: DateTime<Utc>,
    pub typical_hours: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfile {
    pub username: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub activity_baseline: ActivityBaseline,
    pub access_patterns: HashMap<String, AccessPattern>,
    pub risk_score: f64,
    pub anomaly_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityProfile {
    pub entity_id: String,
    pub entity_type: EntityType,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub activity_baseline: ActivityBaseline,
    pub risk_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UebaAnomaly {
    pub id: Uuid,
    pub anomaly_type: AnomalyType,
    pub username: Option<String>,
    pub entity_id: Option<String>,
    pub severity: EventSeverity,
    pub confidence: f32,
    pub deviation_score: f64,
    pub description: String,
    pub evidence: Vec<String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UebaConfig {
    pub learning_period_hours: u64,
    pub anomaly_threshold: f64,
    pub min_samples_for_baseline: u32,
    pub enable_user_profiling: bool,
    pub enable_entity_profiling: bool,
    pub enable_temporal_analysis: bool,
    pub sensitive_paths: Vec<String>,
    pub admin_users: Vec<String>,
}

impl Default for UebaConfig {
    fn default() -> Self {
        Self {
            learning_period_hours: 168,
            anomaly_threshold: 2.5,
            min_samples_for_baseline: 30,
            enable_user_profiling: true,
            enable_entity_profiling: true,
            enable_temporal_analysis: true,
            sensitive_paths: vec![
                "C:\\Windows\\System32".to_string(),
                "C:\\Users\\*\\Documents".to_string(),
                "C:\\Users\\*\\Desktop".to_string(),
                "C:\\Users\\*\\Downloads".to_string(),
                "HKLM\\SYSTEM".to_string(),
                "HKLM\\SAM".to_string(),
                "HKLM\\SECURITY".to_string(),
                "C:\\Program Files".to_string(),
                "C:\\Windows\\System32\\config".to_string(),
            ],
            admin_users: vec![
                "Administrator".to_string(),
                "SYSTEM".to_string(),
                "LOCAL SERVICE".to_string(),
                "NETWORK SERVICE".to_string(),
            ],
        }
    }
}

pub struct UebaEngine {
    pub user_profiles: HashMap<String, UserProfile>,
    pub entity_profiles: HashMap<String, EntityProfile>,
    pub anomalies: Vec<UebaAnomaly>,
    pub config: UebaConfig,
    pub detection_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserActivity {
    pub timestamp: DateTime<Utc>,
    pub files_accessed: u32,
    pub processes_spawned: u32,
    pub network_connections: u32,
    pub login: bool,
    pub source_ip: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityActivity {
    pub timestamp: DateTime<Utc>,
    pub metric_name: String,
    pub metric_value: f64,
}

use royalsecurity_common::types::EventSeverity;

impl UebaEngine {
    pub fn new() -> Self {
        info!("UebaEngine initialized with default config");
        Self {
            user_profiles: HashMap::new(),
            entity_profiles: HashMap::new(),
            anomalies: Vec::new(),
            config: UebaConfig::default(),
            detection_count: 0,
        }
    }

    pub fn with_config(config: UebaConfig) -> Self {
        info!(
            "UebaEngine initialized: learning_period={}h, threshold={}, min_samples={}",
            config.learning_period_hours, config.anomaly_threshold, config.min_samples_for_baseline
        );
        Self {
            user_profiles: HashMap::new(),
            entity_profiles: HashMap::new(),
            anomalies: Vec::new(),
            config,
            detection_count: 0,
        }
    }

    pub fn update_user_activity(
        &mut self,
        username: &str,
        activity: UserActivity,
    ) -> Vec<UebaAnomaly> {
        if !self.config.enable_user_profiling {
            return Vec::new();
        }

        let key = username.to_lowercase();
        let mut anomalies = Vec::new();
        let now = activity.timestamp;

        let profile = self.user_profiles.entry(key.clone()).or_insert_with(|| {
            debug!("New user profile created for {}", username);
            UserProfile {
                username: username.to_string(),
                first_seen: now,
                last_seen: now,
                activity_baseline: ActivityBaseline::default(),
                access_patterns: HashMap::new(),
                risk_score: 0.0,
                anomaly_count: 0,
            }
        });

        profile.last_seen = now;

        if activity.login {
            profile.activity_baseline.logins_per_day.update(1.0);
        }
        profile
            .activity_baseline
            .files_accessed_per_day
            .update(activity.files_accessed as f64);
        profile
            .activity_baseline
            .network_connections_per_day
            .update(activity.network_connections as f64);
        profile
            .activity_baseline
            .processes_spawned_per_day
            .update(activity.processes_spawned as f64);

        let hour = now.hour() as usize;
        profile.activity_baseline.active_hours.hour_counts[hour] += 1;

        let day_idx = match now.weekday() {
            Weekday::Mon => 0,
            Weekday::Tue => 1,
            Weekday::Wed => 2,
            Weekday::Thu => 3,
            Weekday::Fri => 4,
            Weekday::Sat => 5,
            Weekday::Sun => 6,
        };
        profile.activity_baseline.active_days.day_counts[day_idx] += 1;

        if profile.activity_baseline.logins_per_day.sample_count >= self.config.min_samples_for_baseline
        {
            let login_deviation =
                Self::calculate_deviation(1.0, &profile.activity_baseline.logins_per_day);
            if login_deviation.abs() > self.config.anomaly_threshold {
                let anomaly = UebaAnomaly {
                    id: Uuid::new_v4(),
                    anomaly_type: AnomalyType::UnusualVolume,
                    username: Some(username.to_string()),
                    entity_id: None,
                    severity: EventSeverity::Medium,
                    confidence: 0.7,
                    deviation_score: login_deviation,
                    description: format!(
                        "User {} login frequency deviation: {:.2} std devs from baseline",
                        username, login_deviation
                    ),
                    evidence: vec![
                        format!("Baseline mean: {:.2}", profile.activity_baseline.logins_per_day.mean),
                        format!("Deviation: {:.2}", login_deviation),
                    ],
                    timestamp: now,
                };
                warn!("UEBA anomaly detected for {}: UnusualVolume", username);
                self.detection_count += 1;
                anomalies.push(anomaly);
            }

            let files_deviation = Self::calculate_deviation(
                activity.files_accessed as f64,
                &profile.activity_baseline.files_accessed_per_day,
            );
            if files_deviation.abs() > self.config.anomaly_threshold {
                let anomaly = UebaAnomaly {
                    id: Uuid::new_v4(),
                    anomaly_type: AnomalyType::UnusualVolume,
                    username: Some(username.to_string()),
                    entity_id: None,
                    severity: if files_deviation > 3.0 {
                        EventSeverity::High
                    } else {
                        EventSeverity::Medium
                    },
                    confidence: 0.75,
                    deviation_score: files_deviation,
                    description: format!(
                        "User {} file access volume deviation: {:.2} std devs from baseline",
                        username, files_deviation
                    ),
                    evidence: vec![
                        format!("Current: {}", activity.files_accessed),
                        format!("Baseline mean: {:.2}", profile.activity_baseline.files_accessed_per_day.mean),
                    ],
                    timestamp: now,
                };
                warn!("UEBA anomaly detected for {}: UnusualFileVolume", username);
                self.detection_count += 1;
                anomalies.push(anomaly);
            }

            let net_deviation = Self::calculate_deviation(
                activity.network_connections as f64,
                &profile.activity_baseline.network_connections_per_day,
            );
            if net_deviation.abs() > self.config.anomaly_threshold {
                let anomaly = UebaAnomaly {
                    id: Uuid::new_v4(),
                    anomaly_type: AnomalyType::UnusualNetworkActivity,
                    username: Some(username.to_string()),
                    entity_id: None,
                    severity: if net_deviation > 3.0 {
                        EventSeverity::High
                    } else {
                        EventSeverity::Medium
                    },
                    confidence: 0.7,
                    deviation_score: net_deviation,
                    description: format!(
                        "User {} network connection volume deviation: {:.2} std devs from baseline",
                        username, net_deviation
                    ),
                    evidence: vec![
                        format!("Current: {}", activity.network_connections),
                        format!("Baseline mean: {:.2}", profile.activity_baseline.network_connections_per_day.mean),
                    ],
                    timestamp: now,
                };
                warn!("UEBA anomaly detected for {}: UnusualNetworkActivity", username);
                self.detection_count += 1;
                anomalies.push(anomaly);
            }
        }

        for anomaly in &anomalies {
            let risk_increment = match anomaly.severity {
                EventSeverity::Critical => 2.0,
                EventSeverity::High => 1.5,
                EventSeverity::Medium => 1.0,
                EventSeverity::Low => 0.5,
                EventSeverity::Informational => 0.1,
            };
            let risk_profile = self.user_profiles.get_mut(&key).unwrap();
            risk_profile.risk_score = (risk_profile.risk_score + risk_increment).min(10.0);
            risk_profile.anomaly_count += 1;
        }

        if anomalies.is_empty() {
            debug!("No anomalies for user {} at {}", username, now);
        }

        let all_anomalies = anomalies.clone();
        self.anomalies.extend(anomalies);
        all_anomalies
    }

    pub fn update_entity_activity(
        &mut self,
        entity_id: &str,
        entity_type: EntityType,
        activity: EntityActivity,
    ) -> Vec<UebaAnomaly> {
        if !self.config.enable_entity_profiling {
            return Vec::new();
        }

        let key = entity_id.to_lowercase();
        let mut anomalies = Vec::new();
        let now = activity.timestamp;

        let profile = self
            .entity_profiles
            .entry(key.clone())
            .or_insert_with(|| {
                debug!("New entity profile created for {}", entity_id);
                EntityProfile {
                    entity_id: entity_id.to_string(),
                    entity_type,
                    first_seen: now,
                    last_seen: now,
                    activity_baseline: ActivityBaseline::default(),
                    risk_score: 0.0,
                }
            });

        profile.last_seen = now;

        match activity.metric_name.as_str() {
            "network_connections" => {
                profile
                    .activity_baseline
                    .network_connections_per_day
                    .update(activity.metric_value);
                if profile.activity_baseline.network_connections_per_day.sample_count
                    >= self.config.min_samples_for_baseline
                {
                    let deviation = Self::calculate_deviation(
                        activity.metric_value,
                        &profile.activity_baseline.network_connections_per_day,
                    );
                    if deviation.abs() > self.config.anomaly_threshold {
                        let anomaly = UebaAnomaly {
                            id: Uuid::new_v4(),
                            anomaly_type: AnomalyType::UnusualNetworkActivity,
                            username: None,
                            entity_id: Some(entity_id.to_string()),
                            severity: EventSeverity::Medium,
                            confidence: 0.65,
                            deviation_score: deviation,
                            description: format!(
                                "Entity {} network activity deviation: {:.2} std devs",
                                entity_id, deviation
                            ),
                            evidence: vec![
                                format!("Metric: {}", activity.metric_name),
                                format!("Current: {}", activity.metric_value),
                                format!(
                                    "Baseline mean: {:.2}",
                                    profile.activity_baseline.network_connections_per_day.mean
                                ),
                            ],
                            timestamp: now,
                        };
                        warn!("UEBA entity anomaly for {}: UnusualNetworkActivity", entity_id);
                        self.detection_count += 1;
                        anomalies.push(anomaly);
                    }
                }
            }
            "processes_spawned" => {
                profile
                    .activity_baseline
                    .processes_spawned_per_day
                    .update(activity.metric_value);
                if profile.activity_baseline.processes_spawned_per_day.sample_count
                    >= self.config.min_samples_for_baseline
                {
                    let deviation = Self::calculate_deviation(
                        activity.metric_value,
                        &profile.activity_baseline.processes_spawned_per_day,
                    );
                    if deviation.abs() > self.config.anomaly_threshold {
                        let anomaly = UebaAnomaly {
                            id: Uuid::new_v4(),
                            anomaly_type: AnomalyType::UnusualProcess,
                            username: None,
                            entity_id: Some(entity_id.to_string()),
                            severity: EventSeverity::Medium,
                            confidence: 0.6,
                            deviation_score: deviation,
                            description: format!(
                                "Entity {} process spawn deviation: {:.2} std devs",
                                entity_id, deviation
                            ),
                            evidence: vec![
                                format!("Current: {}", activity.metric_value),
                                format!(
                                    "Baseline mean: {:.2}",
                                    profile.activity_baseline.processes_spawned_per_day.mean
                                ),
                            ],
                            timestamp: now,
                        };
                        warn!("UEBA entity anomaly for {}: UnusualProcess", entity_id);
                        self.detection_count += 1;
                        anomalies.push(anomaly);
                    }
                }
            }
            "files_accessed" => {
                profile
                    .activity_baseline
                    .files_accessed_per_day
                    .update(activity.metric_value);
                if profile.activity_baseline.files_accessed_per_day.sample_count
                    >= self.config.min_samples_for_baseline
                {
                    let deviation = Self::calculate_deviation(
                        activity.metric_value,
                        &profile.activity_baseline.files_accessed_per_day,
                    );
                    if deviation.abs() > self.config.anomaly_threshold {
                        let anomaly = UebaAnomaly {
                            id: Uuid::new_v4(),
                            anomaly_type: AnomalyType::UnusualFileAccess,
                            username: None,
                            entity_id: Some(entity_id.to_string()),
                            severity: EventSeverity::Medium,
                            confidence: 0.6,
                            deviation_score: deviation,
                            description: format!(
                                "Entity {} file access deviation: {:.2} std devs",
                                entity_id, deviation
                            ),
                            evidence: vec![
                                format!("Current: {}", activity.metric_value),
                                format!(
                                    "Baseline mean: {:.2}",
                                    profile.activity_baseline.files_accessed_per_day.mean
                                ),
                            ],
                            timestamp: now,
                        };
                        warn!("UEBA entity anomaly for {}: UnusualFileAccess", entity_id);
                        self.detection_count += 1;
                        anomalies.push(anomaly);
                    }
                }
            }
            _ => {
                debug!("Unknown metric for entity {}: {}", entity_id, activity.metric_name);
            }
        }

        for anomaly in &anomalies {
            let risk_increment = match anomaly.severity {
                EventSeverity::Critical => 2.0,
                EventSeverity::High => 1.5,
                EventSeverity::Medium => 1.0,
                EventSeverity::Low => 0.5,
                EventSeverity::Informational => 0.1,
            };
            let risk_profile = self.entity_profiles.get_mut(&key).unwrap();
            risk_profile.risk_score = (risk_profile.risk_score + risk_increment).min(10.0);
        }

        self.anomalies.extend(anomalies.clone());
        anomalies
    }

    pub fn check_login_event(
        &mut self,
        username: &str,
        timestamp: DateTime<Utc>,
        source_ip: &str,
        success: bool,
    ) -> Vec<UebaAnomaly> {
        let mut anomalies = Vec::new();
        let key = username.to_lowercase();
        let hour = timestamp.hour() as usize;

        if self.config.enable_temporal_analysis {
            let profile = self.user_profiles.get(&key);
            if let Some(profile) = profile {
                if profile.activity_baseline.active_hours.hour_counts.iter().sum::<u32>()
                    >= self.config.min_samples_for_baseline
                {
                    let total_activity: u32 =
                        profile.activity_baseline.active_hours.hour_counts.iter().sum();
                    if total_activity > 0 {
                        let hour_fraction =
                            profile.activity_baseline.active_hours.hour_counts[hour] as f64
                                / total_activity as f64;
                        if hour_fraction < 0.02
                            && profile.activity_baseline.active_hours.hour_counts[hour] == 0
                        {
                            let anomaly = UebaAnomaly {
                                id: Uuid::new_v4(),
                                anomaly_type: AnomalyType::OffHoursActivity,
                                username: Some(username.to_string()),
                                entity_id: None,
                                severity: EventSeverity::Medium,
                                confidence: 0.7,
                                deviation_score: 3.0,
                                description: format!(
                                    "User {} logged in at unusual hour: {}:00 (never active at this hour)",
                                    username, hour
                                ),
                                evidence: vec![
                                    format!("Login hour: {}:00", hour),
                                    format!(
                                        "Typical active hours count: {}",
                                        profile
                                            .activity_baseline
                                            .active_hours
                                            .hour_counts
                                            .iter()
                                            .filter(|&&c| c > 0)
                                            .count()
                                    ),
                                ],
                                timestamp,
                            };
                            warn!(
                                "UEBA off-hours login detected for {} at {}:00",
                                username, hour
                            );
                            self.detection_count += 1;
                            anomalies.push(anomaly);
                        } else if hour_fraction < 0.03 {
                            let anomaly = UebaAnomaly {
                                id: Uuid::new_v4(),
                                anomaly_type: AnomalyType::UnusualLoginTime,
                                username: Some(username.to_string()),
                                entity_id: None,
                                severity: EventSeverity::Low,
                                confidence: 0.5,
                                deviation_score: 2.0,
                                description: format!(
                                    "User {} login at less common hour: {}:00",
                                    username, hour
                                ),
                                evidence: vec![
                                    format!("Hour frequency: {:.2}%", hour_fraction * 100.0),
                                    format!("Login hour: {}:00", hour),
                                ],
                                timestamp,
                            };
                            debug!(
                                "UEBA unusual login time for {} at {}:00",
                                username, hour
                            );
                            self.detection_count += 1;
                            anomalies.push(anomaly);
                        }
                    }
                }
            }
        }

        if self.user_profiles.contains_key(&key) {
            if let Some(last) = self.anomalies.iter().rev().find(|a| {
                a.username.as_deref() == Some(username)
                    && a.anomaly_type == AnomalyType::ImpossibleTravel
            }) {
                let time_diff = (timestamp - last.timestamp).num_minutes();
                if time_diff < 30 && time_diff > 0 {
                    let anomaly = UebaAnomaly {
                        id: Uuid::new_v4(),
                        anomaly_type: AnomalyType::ImpossibleTravel,
                        username: Some(username.to_string()),
                        entity_id: None,
                        severity: EventSeverity::Critical,
                        confidence: 0.85,
                        deviation_score: 5.0,
                        description: format!(
                            "User {} logged in from {} and previously from different location within {} minutes",
                            username, source_ip, time_diff
                        ),
                        evidence: vec![
                            format!("Source IP: {}", source_ip),
                            format!("Time since last login from different IP: {} minutes", time_diff),
                            format!("Previous event: {}", last.timestamp),
                        ],
                        timestamp,
                    };
                    warn!(
                        "UEBA impossible travel detected for {} from {}",
                        username, source_ip
                    );
                    self.detection_count += 1;
                    anomalies.push(anomaly);
                }
            }
        }

        if !success {
            let recent_failures: u32 = self
                .anomalies
                .iter()
                .filter(|a| {
                    a.username.as_deref() == Some(username)
                        && a.anomaly_type == AnomalyType::UnusualVolume
                        && (timestamp - a.timestamp).num_minutes() < 15
                })
                .count() as u32;

            if recent_failures >= 5 {
                let anomaly = UebaAnomaly {
                    id: Uuid::new_v4(),
                    anomaly_type: AnomalyType::PrivilegeAbuse,
                    username: Some(username.to_string()),
                    entity_id: None,
                    severity: EventSeverity::High,
                    confidence: 0.8,
                    deviation_score: 4.0,
                    description: format!(
                        "Possible brute force: {} failed login attempts for {} within 15 minutes",
                        recent_failures + 1,
                        username
                    ),
                    evidence: vec![
                        format!("Failed attempts: {}", recent_failures + 1),
                        format!("Source IP: {}", source_ip),
                        format!("Time window: 15 minutes"),
                    ],
                    timestamp,
                };
                warn!(
                    "UEBA brute force detected for {} from {}",
                    username, source_ip
                );
                self.detection_count += 1;
                anomalies.push(anomaly);
            }
        }

        let profile = self
            .user_profiles
            .entry(key.clone())
            .or_insert_with(|| UserProfile {
                username: username.to_string(),
                first_seen: timestamp,
                last_seen: timestamp,
                activity_baseline: ActivityBaseline::default(),
                access_patterns: HashMap::new(),
                risk_score: 0.0,
                anomaly_count: 0,
            });
        profile.last_seen = timestamp;

        for anomaly in &anomalies {
            let risk_increment = match anomaly.severity {
                EventSeverity::Critical => 2.5,
                EventSeverity::High => 1.5,
                EventSeverity::Medium => 1.0,
                EventSeverity::Low => 0.5,
                EventSeverity::Informational => 0.1,
            };
            profile.risk_score = (profile.risk_score + risk_increment).min(10.0);
            profile.anomaly_count += 1;
        }

        self.anomalies.extend(anomalies.clone());
        anomalies
    }

    pub fn check_file_access(
        &mut self,
        username: &str,
        file_path: &str,
        action: &str,
    ) -> Vec<UebaAnomaly> {
        let mut anomalies = Vec::new();
        let key = username.to_lowercase();
        let now = Utc::now();
        let path_lower = file_path.to_lowercase();

        let is_sensitive = self.config.sensitive_paths.iter().any(|sp| {
            let sp_lower = sp.to_lowercase();
            path_lower.starts_with(&sp_lower)
        });

        if is_sensitive {
            let profile = self.user_profiles.get(&key);
            let is_new_resource = profile.map_or(true, |p| {
                !p.access_patterns.contains_key(&path_lower)
            });

            if is_new_resource {
                let anomaly = UebaAnomaly {
                    id: Uuid::new_v4(),
                    anomaly_type: AnomalyType::NewResourceAccess,
                    username: Some(username.to_string()),
                    entity_id: None,
                    severity: if path_lower.contains("system32\\config")
                        || path_lower.contains("hklm\\security")
                        || path_lower.contains("hklm\\sam")
                    {
                        EventSeverity::Critical
                    } else {
                        EventSeverity::High
                    },
                    confidence: 0.75,
                    deviation_score: 3.5,
                    description: format!(
                        "User {} accessing sensitive resource for the first time: {} (action: {})",
                        username, file_path, action
                    ),
                    evidence: vec![
                        format!("File path: {}", file_path),
                        format!("Action: {}", action),
                        format!("Sensitive path match: {}", is_sensitive),
                    ],
                    timestamp: now,
                };
                warn!(
                    "UEBA sensitive new resource access for {}: {}",
                    username, file_path
                );
                self.detection_count += 1;
                anomalies.push(anomaly);
            } else {
                let profile = self.user_profiles.get(&key).unwrap();
                if let Some(pattern) = profile.access_patterns.get(&path_lower) {
                    let hour = now.hour() as u8;
                    if !pattern.typical_hours.contains(&hour) && !pattern.typical_hours.is_empty() {
                        let anomaly = UebaAnomaly {
                            id: Uuid::new_v4(),
                            anomaly_type: AnomalyType::UnusualFileAccess,
                            username: Some(username.to_string()),
                            entity_id: None,
                            severity: EventSeverity::Medium,
                            confidence: 0.65,
                            deviation_score: 2.8,
                            description: format!(
                                "User {} accessing sensitive file {} at unusual hour {}:00",
                                username, file_path, hour
                            ),
                            evidence: vec![
                                format!("File: {}", file_path),
                                format!("Hour: {}:00", hour),
                                format!(
                                    "Typical hours: {:?}",
                                    pattern.typical_hours
                                ),
                            ],
                            timestamp: now,
                        };
                        debug!(
                            "UEBA unusual file access time for {}: {}",
                            username, file_path
                        );
                        self.detection_count += 1;
                        anomalies.push(anomaly);
                    }
                }
            }
        }

        let profile = self
            .user_profiles
            .entry(key.clone())
            .or_insert_with(|| UserProfile {
                username: username.to_string(),
                first_seen: now,
                last_seen: now,
                activity_baseline: ActivityBaseline::default(),
                access_patterns: HashMap::new(),
                risk_score: 0.0,
                anomaly_count: 0,
            });

        let pattern = profile
            .access_patterns
            .entry(path_lower.clone())
            .or_insert_with(|| AccessPattern {
                resource: file_path.to_string(),
                access_count: 0,
                first_access: now,
                last_access: now,
                typical_hours: Vec::new(),
            });
        pattern.access_count += 1;
        pattern.last_access = now;
        let hour = now.hour() as u8;
        if !pattern.typical_hours.contains(&hour) {
            pattern.typical_hours.push(hour);
            pattern.typical_hours.sort();
            pattern.typical_hours.dedup();
        }

        for anomaly in &anomalies {
            let risk_increment = match anomaly.severity {
                EventSeverity::Critical => 2.5,
                EventSeverity::High => 1.5,
                EventSeverity::Medium => 1.0,
                EventSeverity::Low => 0.5,
                EventSeverity::Informational => 0.1,
            };
            profile.risk_score = (profile.risk_score + risk_increment).min(10.0);
            profile.anomaly_count += 1;
        }

        self.anomalies.extend(anomalies.clone());
        anomalies
    }

    pub fn check_network_activity(
        &mut self,
        username: Option<&str>,
        process_name: &str,
        dst_ip: &str,
        bytes_out: u64,
    ) -> Vec<UebaAnomaly> {
        let mut anomalies = Vec::new();
        let now = Utc::now();

        if bytes_out > 100_000_000 {
            let anomaly = UebaAnomaly {
                id: Uuid::new_v4(),
                anomaly_type: AnomalyType::DataExfiltration,
                username: username.map(|s| s.to_string()),
                entity_id: Some(dst_ip.to_string()),
                severity: EventSeverity::Critical,
                confidence: 0.9,
                deviation_score: 5.0,
                description: format!(
                    "Large data transfer detected: {} bytes outbound to {} via {} (possible exfiltration)",
                    bytes_out, dst_ip, process_name
                ),
                evidence: vec![
                    format!("Bytes out: {}", bytes_out),
                    format!("Destination: {}", dst_ip),
                    format!("Process: {}", process_name),
                    if let Some(u) = username {
                        format!("User: {}", u)
                    } else {
                        "No user context".to_string()
                    },
                ],
                timestamp: now,
            };
            warn!(
                "UEBA data exfiltration indicator: {} bytes to {} via {}",
                bytes_out, dst_ip, process_name
            );
            self.detection_count += 1;
            anomalies.push(anomaly);
        } else if bytes_out > 50_000_000 {
            if let Some(user) = username {
                let key = user.to_lowercase();
                if let Some(profile) = self.user_profiles.get(&key) {
                    let net_baseline = &profile.activity_baseline.network_connections_per_day;
                    if net_baseline.sample_count >= self.config.min_samples_for_baseline {
                        let deviation = Self::calculate_deviation(
                            bytes_out as f64 / 1_000_000.0,
                            &TimeSeriesStats {
                                mean: net_baseline.mean * 100_000.0,
                                std_dev: if net_baseline.std_dev > 0.0 {
                                    net_baseline.std_dev * 100_000.0
                                } else {
                                    1.0
                                },
                                min: net_baseline.min,
                                max: net_baseline.max,
                                sample_count: net_baseline.sample_count,
                                last_updated: net_baseline.last_updated,
                            },
                        );
                        if deviation.abs() > self.config.anomaly_threshold {
                            let anomaly = UebaAnomaly {
                                id: Uuid::new_v4(),
                                anomaly_type: AnomalyType::UnusualVolume,
                                username: Some(user.to_string()),
                                entity_id: Some(dst_ip.to_string()),
                                severity: EventSeverity::High,
                                confidence: 0.8,
                                deviation_score: deviation,
                                description: format!(
                                    "User {} large outbound transfer: {} bytes to {} (deviation: {:.2})",
                                    user, bytes_out, dst_ip, deviation
                                ),
                                evidence: vec![
                                    format!("Bytes out: {}", bytes_out),
                                    format!("Destination: {}", dst_ip),
                                    format!("Process: {}", process_name),
                                    format!("Deviation: {:.2}", deviation),
                                ],
                                timestamp: now,
                            };
                            warn!(
                                "UEBA unusual volume for {}: {} bytes to {}",
                                user, bytes_out, dst_ip
                            );
                            self.detection_count += 1;
                            anomalies.push(anomaly);
                        }
                    }
                }
            }
        }

        let suspicious_processes = [
            "powershell.exe",
            "cmd.exe",
            "certutil.exe",
            "bitsadmin.exe",
            "mshta.exe",
            "wscript.exe",
            "cscript.exe",
            "rundll32.exe",
            "regsvr32.exe",
            "msiexec.exe",
        ];

        let proc_lower = process_name.to_lowercase();
        if suspicious_processes.iter().any(|&sp| proc_lower == sp) && bytes_out > 1_000_000 {
            let anomaly = UebaAnomaly {
                id: Uuid::new_v4(),
                anomaly_type: AnomalyType::UnusualProcess,
                username: username.map(|s| s.to_string()),
                entity_id: Some(dst_ip.to_string()),
                severity: EventSeverity::High,
                confidence: 0.7,
                deviation_score: 3.0,
                description: format!(
                    "Suspicious process {} making large network transfer ({} bytes) to {}",
                    process_name, bytes_out, dst_ip
                ),
                evidence: vec![
                    format!("Process: {}", process_name),
                    format!("Bytes out: {}", bytes_out),
                    format!("Destination: {}", dst_ip),
                ],
                timestamp: now,
            };
            warn!(
                "UEBA suspicious process network activity: {} to {}",
                process_name, dst_ip
            );
            self.detection_count += 1;
            anomalies.push(anomaly);
        }

        if let Some(user) = username {
            let key = user.to_lowercase();
            let profile = self
                .user_profiles
                .entry(key.clone())
                .or_insert_with(|| UserProfile {
                    username: user.to_string(),
                    first_seen: now,
                    last_seen: now,
                    activity_baseline: ActivityBaseline::default(),
                    access_patterns: HashMap::new(),
                    risk_score: 0.0,
                    anomaly_count: 0,
                });

            for anomaly in &anomalies {
                let risk_increment = match anomaly.severity {
                    EventSeverity::Critical => 2.5,
                    EventSeverity::High => 1.5,
                    EventSeverity::Medium => 1.0,
                    EventSeverity::Low => 0.5,
                    EventSeverity::Informational => 0.1,
                };
                profile.risk_score = (profile.risk_score + risk_increment).min(10.0);
                profile.anomaly_count += 1;
            }
        }

        self.anomalies.extend(anomalies.clone());
        anomalies
    }

    pub fn calculate_deviation(current: f64, baseline: &TimeSeriesStats) -> f64 {
        if baseline.std_dev <= f64::EPSILON || baseline.sample_count == 0 {
            return 0.0;
        }
        (current - baseline.mean) / baseline.std_dev
    }

    pub fn calculate_hour_distribution(timestamps: &[DateTime<Utc>]) -> HourDistribution {
        let mut dist = HourDistribution::default();
        for ts in timestamps {
            let hour = ts.hour() as usize;
            if hour < 24 {
                dist.hour_counts[hour] += 1;
            }
        }
        dist
    }

    pub fn calculate_day_distribution(timestamps: &[DateTime<Utc>]) -> DayDistribution {
        let mut dist = DayDistribution::default();
        for ts in timestamps {
            let day_idx = match ts.weekday() {
                Weekday::Mon => 0,
                Weekday::Tue => 1,
                Weekday::Wed => 2,
                Weekday::Thu => 3,
                Weekday::Fri => 4,
                Weekday::Sat => 5,
                Weekday::Sun => 6,
            };
            dist.day_counts[day_idx] += 1;
        }
        dist
    }

    pub fn calculate_risk_score(profile: &UserProfile) -> f64 {
        let frequency_factor = if profile.anomaly_count > 20 {
            2.0
        } else if profile.anomaly_count > 10 {
            1.5
        } else if profile.anomaly_count > 5 {
            1.2
        } else {
            1.0
        };

        let recent_anomalies = profile.anomaly_count.min(20) as f64;
        let base_score = (recent_anomalies * 0.3).min(8.0);

        let time_factor = {
            let days_active = (profile.last_seen - profile.first_seen).num_days().max(1) as f64;
            if days_active < 7.0 {
                1.3
            } else if days_active < 30.0 {
                1.1
            } else {
                1.0
            }
        };

        let score = (base_score * frequency_factor * time_factor).min(10.0);
        (profile.risk_score * 0.7 + score * 0.3).min(10.0)
    }

    pub fn get_high_risk_users(&self, threshold: f64) -> Vec<(String, f64)> {
        let mut high_risk: Vec<(String, f64)> = self
            .user_profiles
            .iter()
            .map(|(name, profile)| {
                let score = Self::calculate_risk_score(profile);
                (name.clone(), score)
            })
            .filter(|(_, score)| *score >= threshold)
            .collect();

        high_risk.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        high_risk
    }

    pub fn get_anomalies_for_user(&self, username: &str) -> Vec<&UebaAnomaly> {
        let key = username.to_lowercase();
        self.anomalies
            .iter()
            .filter(|a| {
                a.username
                    .as_ref()
                    .map(|u| u.to_lowercase() == key)
                    .unwrap_or(false)
            })
            .collect()
    }

    pub fn detection_count(&self) -> u64 {
        self.detection_count
    }
}

impl Default for UebaEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, TimeZone};

    #[test]
    fn test_ueba_engine_new() {
        let engine = UebaEngine::new();
        assert_eq!(engine.detection_count(), 0);
        assert!(engine.user_profiles.is_empty());
        assert!(engine.entity_profiles.is_empty());
        assert!(engine.anomalies.is_empty());
        assert_eq!(engine.config.learning_period_hours, 168);
        assert!((engine.config.anomaly_threshold - 2.5).abs() < f64::EPSILON);
        assert_eq!(engine.config.min_samples_for_baseline, 30);
        assert!(engine.config.enable_user_profiling);
        assert!(engine.config.enable_entity_profiling);
        assert!(engine.config.enable_temporal_analysis);
        assert!(!engine.config.sensitive_paths.is_empty());
    }

    #[test]
    fn test_update_user_activity_normal() {
        let mut engine = UebaEngine::new();
        let now = Utc::now();

        let activity = UserActivity {
            timestamp: now,
            files_accessed: 5,
            processes_spawned: 3,
            network_connections: 10,
            login: true,
            source_ip: Some("192.168.1.100".to_string()),
        };

        let anomalies = engine.update_user_activity("testuser", activity);
        assert!(anomalies.is_empty());
        assert!(engine.user_profiles.contains_key("testuser"));
        let profile = engine.user_profiles.get("testuser").unwrap();
        assert_eq!(profile.username, "testuser");
        assert_eq!(profile.anomaly_count, 0);
    }

    #[test]
    fn test_update_user_activity_detects_unusual_volume() {
        let mut engine = UebaEngine::new();
        let base = Utc.with_ymd_and_hms(2025, 1, 1, 9, 0, 0).unwrap();

        for i in 0..35u32 {
            let ts = base + Duration::hours(i as i64);
            let activity = UserActivity {
                timestamp: ts,
                files_accessed: 5,
                processes_spawned: 2,
                network_connections: 10,
                login: true,
                source_ip: Some("192.168.1.100".to_string()),
            };
            engine.update_user_activity("testuser", activity);
        }

        let unusual_activity = UserActivity {
            timestamp: base + Duration::hours(35),
            files_accessed: 500,
            processes_spawned: 2,
            network_connections: 10,
            login: false,
            source_ip: Some("192.168.1.100".to_string()),
        };

        let anomalies = engine.update_user_activity("testuser", unusual_activity);
        let volume_anomalies: Vec<_> = anomalies
            .iter()
            .filter(|a| a.anomaly_type == AnomalyType::UnusualVolume)
            .collect();
        assert!(
            !volume_anomalies.is_empty(),
            "Should detect unusual file access volume"
        );
    }

    #[test]
    fn test_check_login_event_detects_off_hours() {
        let mut engine = UebaEngine::new();
        let base = Utc.with_ymd_and_hms(2025, 1, 1, 9, 0, 0).unwrap();

        for i in 0..35 {
            let ts = base + Duration::hours(i as i64);
            let activity = UserActivity {
                timestamp: ts,
                files_accessed: 5,
                processes_spawned: 2,
                network_connections: 10,
                login: true,
                source_ip: Some("192.168.1.100".to_string()),
            };
            engine.update_user_activity("testuser", activity);
        }

        let night_time = Utc.with_ymd_and_hms(2025, 2, 10, 3, 0, 0).unwrap();
        let anomalies = engine.check_login_event("testuser", night_time, "192.168.1.100", true);

        let off_hours: Vec<_> = anomalies
            .iter()
            .filter(|a| {
                matches!(
                    a.anomaly_type,
                    AnomalyType::OffHoursActivity | AnomalyType::UnusualLoginTime
                )
            })
            .collect();
        assert!(
            !off_hours.is_empty(),
            "Should detect off-hours login"
        );
    }

    #[test]
    fn test_calculate_deviation() {
        let baseline = TimeSeriesStats {
            mean: 10.0,
            std_dev: 2.0,
            min: 5.0,
            max: 15.0,
            sample_count: 30,
            last_updated: Utc::now(),
        };

        let deviation = UebaEngine::calculate_deviation(10.0, &baseline);
        assert!((deviation - 0.0).abs() < f64::EPSILON);

        let deviation = UebaEngine::calculate_deviation(14.0, &baseline);
        assert!((deviation - 2.0).abs() < f64::EPSILON);

        let deviation = UebaEngine::calculate_deviation(6.0, &baseline);
        assert!((deviation - (-2.0)).abs() < f64::EPSILON);

        let zero_baseline = TimeSeriesStats {
            mean: 5.0,
            std_dev: 0.0,
            min: 5.0,
            max: 5.0,
            sample_count: 10,
            last_updated: Utc::now(),
        };
        let deviation = UebaEngine::calculate_deviation(10.0, &zero_baseline);
        assert!((deviation - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_calculate_hour_distribution() {
        let timestamps = vec![
            Utc.with_ymd_and_hms(2025, 1, 1, 9, 0, 0).unwrap(),
            Utc.with_ymd_and_hms(2025, 1, 1, 9, 30, 0).unwrap(),
            Utc.with_ymd_and_hms(2025, 1, 1, 14, 0, 0).unwrap(),
            Utc.with_ymd_and_hms(2025, 1, 1, 9, 15, 0).unwrap(),
            Utc.with_ymd_and_hms(2025, 1, 2, 22, 0, 0).unwrap(),
        ];

        let dist = UebaEngine::calculate_hour_distribution(&timestamps);
        assert_eq!(dist.hour_counts[9], 3);
        assert_eq!(dist.hour_counts[14], 1);
        assert_eq!(dist.hour_counts[22], 1);
        assert_eq!(dist.hour_counts[0], 0);
        assert_eq!(dist.hour_counts[12], 0);
    }

    #[test]
    fn test_calculate_risk_score() {
        let low_risk = UserProfile {
            username: "low_risk".to_string(),
            first_seen: Utc::now() - Duration::days(90),
            last_seen: Utc::now(),
            activity_baseline: ActivityBaseline::default(),
            access_patterns: HashMap::new(),
            risk_score: 0.5,
            anomaly_count: 2,
        };

        let high_risk = UserProfile {
            username: "high_risk".to_string(),
            first_seen: Utc::now() - Duration::days(3),
            last_seen: Utc::now(),
            activity_baseline: ActivityBaseline::default(),
            access_patterns: HashMap::new(),
            risk_score: 5.0,
            anomaly_count: 25,
        };

        let low_score = UebaEngine::calculate_risk_score(&low_risk);
        let high_score = UebaEngine::calculate_risk_score(&high_risk);

        assert!(
            high_score > low_score,
            "High risk user should have higher score: {} vs {}",
            high_score,
            low_score
        );
        assert!(high_score <= 10.0);
        assert!(low_score >= 0.0);
    }

    #[test]
    fn test_get_high_risk_users() {
        let mut engine = UebaEngine::new();

        for i in 0..25 {
            let activity = UserActivity {
                timestamp: Utc::now() - Duration::hours(25 - i),
                files_accessed: 5,
                processes_spawned: 2,
                network_connections: 10,
                login: true,
                source_ip: Some("192.168.1.100".to_string()),
            };
            engine.update_user_activity("high_risk_user", activity);
        }

        let activity = UserActivity {
            timestamp: Utc::now(),
            files_accessed: 2,
            processes_spawned: 1,
            network_connections: 3,
            login: true,
            source_ip: Some("192.168.1.100".to_string()),
        };
        engine.update_user_activity("low_risk_user", activity);

        let high_risk = engine.get_high_risk_users(0.0);
        assert!(
            !high_risk.is_empty(),
            "Should find high risk users"
        );
        assert!(
            high_risk[0].1 >= high_risk.last().unwrap().1,
            "Results should be sorted by risk descending"
        );
    }

    #[test]
    fn test_check_file_access_detects_sensitive_path() {
        let mut engine = UebaEngine::new();

        let anomalies =
            engine.check_file_access("testuser", "C:\\Windows\\System32\\config\\SAM", "read");
        assert!(!anomalies.is_empty(), "Should detect sensitive path access");
        assert!(anomalies.iter().any(|a| matches!(
            a.anomaly_type,
            AnomalyType::NewResourceAccess
        )));
        assert!(anomalies.iter().any(|a| a.severity == EventSeverity::Critical));
    }

    #[test]
    fn test_check_network_activity_detects_unusual_volume() {
        let mut engine = UebaEngine::new();

        let anomalies = engine.check_network_activity(
            Some("testuser"),
            "cmd.exe",
            "10.0.0.99",
            150_000_000,
        );

        assert!(
            !anomalies.is_empty(),
            "Should detect large data transfer"
        );
        assert!(anomalies.iter().any(|a| matches!(
            a.anomaly_type,
            AnomalyType::DataExfiltration
        )));
        assert!(anomalies.iter().any(|a| a.severity == EventSeverity::Critical));
    }

    #[test]
    fn test_check_network_activity_suspicious_process() {
        let mut engine = UebaEngine::new();

        let anomalies = engine.check_network_activity(
            Some("testuser"),
            "powershell.exe",
            "10.0.0.99",
            5_000_000,
        );

        let process_anomalies: Vec<_> = anomalies
            .iter()
            .filter(|a| a.anomaly_type == AnomalyType::UnusualProcess)
            .collect();
        assert!(
            !process_anomalies.is_empty(),
            "Should detect suspicious process network activity"
        );
    }

    #[test]
    fn test_get_anomalies_for_user() {
        let mut engine = UebaEngine::new();

        let anomalies =
            engine.check_file_access("alice", "C:\\Windows\\System32\\config\\SAM", "read");
        assert!(!anomalies.is_empty());

        engine.check_file_access("bob", "C:\\Windows\\System32\\config\\SAM", "read");

        let alice_anomalies = engine.get_anomalies_for_user("alice");
        let bob_anomalies = engine.get_anomalies_for_user("bob");
        assert_eq!(alice_anomalies.len(), 1);
        assert_eq!(bob_anomalies.len(), 1);
        assert_eq!(alice_anomalies[0].username, Some("alice".to_string()));
    }

    #[test]
    fn test_update_entity_activity() {
        let mut engine = UebaEngine::new();

        for i in 0..35 {
            let activity = EntityActivity {
                timestamp: Utc::now() - Duration::hours(35 - i),
                metric_name: "network_connections".to_string(),
                metric_value: 50.0,
            };
            engine.update_entity_activity("webserver01", EntityType::Host, activity);
        }

        let unusual_activity = EntityActivity {
            timestamp: Utc::now(),
            metric_name: "network_connections".to_string(),
            metric_value: 5000.0,
        };
        let anomalies =
            engine.update_entity_activity("webserver01", EntityType::Host, unusual_activity);

        let net_anomalies: Vec<_> = anomalies
            .iter()
            .filter(|a| a.anomaly_type == AnomalyType::UnusualNetworkActivity)
            .collect();
        assert!(
            !net_anomalies.is_empty(),
            "Should detect entity network anomaly"
        );
    }

    #[test]
    fn test_with_config() {
        let config = UebaConfig {
            learning_period_hours: 72,
            anomaly_threshold: 3.0,
            min_samples_for_baseline: 10,
            enable_user_profiling: false,
            ..Default::default()
        };

        let engine = UebaEngine::with_config(config);
        assert_eq!(engine.config.learning_period_hours, 72);
        assert!((engine.config.anomaly_threshold - 3.0).abs() < f64::EPSILON);
        assert_eq!(engine.config.min_samples_for_baseline, 10);
        assert!(!engine.config.enable_user_profiling);
    }

    #[test]
    fn test_disabled_user_profiling() {
        let config = UebaConfig {
            enable_user_profiling: false,
            ..Default::default()
        };
        let mut engine = UebaEngine::with_config(config);

        let activity = UserActivity {
            timestamp: Utc::now(),
            files_accessed: 500,
            processes_spawned: 200,
            network_connections: 300,
            login: true,
            source_ip: Some("10.0.0.1".to_string()),
        };
        let anomalies = engine.update_user_activity("testuser", activity);
        assert!(anomalies.is_empty());
        assert!(engine.user_profiles.is_empty());
    }

    #[test]
    fn test_detection_count_increments() {
        let mut engine = UebaEngine::new();

        engine.check_file_access("user1", "C:\\Windows\\System32\\config\\SAM", "read");
        assert!(engine.detection_count() > 0);

        let count_before = engine.detection_count();
        engine.check_network_activity(
            Some("user2"),
            "cmd.exe",
            "10.0.0.99",
            200_000_000,
        );
        assert!(engine.detection_count() > count_before);
    }

    #[test]
    fn test_calculate_day_distribution() {
        let timestamps = vec![
            Utc.with_ymd_and_hms(2025, 1, 6, 10, 0, 0).unwrap(), // Mon
            Utc.with_ymd_and_hms(2025, 1, 7, 10, 0, 0).unwrap(), // Tue
            Utc.with_ymd_and_hms(2025, 1, 7, 14, 0, 0).unwrap(), // Tue
            Utc.with_ymd_and_hms(2025, 1, 8, 10, 0, 0).unwrap(), // Wed
        ];

        let dist = UebaEngine::calculate_day_distribution(&timestamps);
        assert_eq!(dist.day_counts[0], 1); // Mon
        assert_eq!(dist.day_counts[1], 2); // Tue
        assert_eq!(dist.day_counts[2], 1); // Wed
        assert_eq!(dist.day_counts[3], 0); // Thu
    }
}
