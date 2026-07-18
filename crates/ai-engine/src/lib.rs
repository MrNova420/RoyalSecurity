pub mod prelude;

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use royalsecurity_common::types::EventSeverity;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ModelType {
    AnomalyDetector,
    Classifier,
    Regressor,
    Clustering,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FeatureTransform {
    Normalize { min: f64, max: f64 },
    Standardize { mean: f64, std_dev: f64 },
    LogTransform,
    SquareRoot,
    BinValues { bins: Vec<f64> },
    OneHot { categories: Vec<String> },
}

// ---------------------------------------------------------------------------
// Core data structures
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiConfig {
    pub anomaly_threshold: f64,
    pub min_training_samples: u32,
    pub model_update_interval_secs: u64,
    pub enable_online_learning: bool,
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            anomaly_threshold: 2.5,
            min_training_samples: 100,
            model_update_interval_secs: 3600,
            enable_online_learning: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Model {
    pub id: String,
    pub name: String,
    pub model_type: ModelType,
    pub weights: Vec<Vec<f64>>,
    pub bias: Vec<f64>,
    pub feature_names: Vec<String>,
    pub accuracy: f64,
    pub trained_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Prediction {
    pub model_id: String,
    pub input_features: Vec<f64>,
    pub output: f64,
    pub confidence: f64,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyResult {
    pub entity_id: String,
    pub feature_name: String,
    pub value: f64,
    pub expected_mean: f64,
    pub z_score: f64,
    pub is_anomaly: bool,
    pub severity: EventSeverity,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RunningStats {
    pub mean: f64,
    pub m2: f64,
    pub count: u64,
}

impl RunningStats {
    pub fn variance(&self) -> f64 {
        if self.count < 2 {
            return 0.0;
        }
        self.m2 / (self.count - 1) as f64
    }

    pub fn std_dev(&self) -> f64 {
        self.variance().sqrt()
    }

    pub fn update(&mut self, value: f64) {
        self.count += 1;
        let delta = value - self.mean;
        self.mean += delta / self.count as f64;
        let delta2 = value - self.mean;
        self.m2 += delta * delta2;
    }

    pub fn z_score(&self, value: f64) -> f64 {
        let sd = self.std_dev();
        if sd == 0.0 {
            return 0.0;
        }
        (value - self.mean) / sd
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureProfile {
    pub entity_id: String,
    pub feature_stats: HashMap<String, RunningStats>,
    pub last_updated: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeaturePipeline {
    pub transformers: Vec<FeatureTransform>,
}

// ---------------------------------------------------------------------------
// AiEngine
// ---------------------------------------------------------------------------

pub struct AiEngine {
    pub models: HashMap<String, Model>,
    pub feature_pipeline: FeaturePipeline,
    pub anomaly_detector: AnomalyDetector,
    pub predictions: Vec<Prediction>,
    pub config: AiConfig,
}

pub struct AnomalyDetector {
    pub profiles: HashMap<String, FeatureProfile>,
    pub threshold: f64,
}

// ---------------------------------------------------------------------------
// Constructors
// ---------------------------------------------------------------------------

impl AiEngine {
    pub fn new() -> Self {
        Self::with_config(AiConfig::default())
    }

    pub fn with_config(config: AiConfig) -> Self {
        let threshold = config.anomaly_threshold;
        Self {
            models: HashMap::new(),
            feature_pipeline: FeaturePipeline {
                transformers: Vec::new(),
            },
            anomaly_detector: AnomalyDetector {
                profiles: HashMap::new(),
                threshold,
            },
            predictions: Vec::new(),
            config,
        }
    }
}

// ---------------------------------------------------------------------------
// Training
// ---------------------------------------------------------------------------

impl AiEngine {
    pub fn train_simple_model(
        &mut self,
        name: &str,
        model_type: ModelType,
        training_data: &[(Vec<f64>, f64)],
    ) -> String {
        let min_samples = self.config.min_training_samples as usize;
        if training_data.len() < min_samples {
            warn!(
                "Insufficient training data for '{}': {} < {}",
                name,
                training_data.len(),
                min_samples
            );
        }

        let feature_count = training_data.first().map_or(0, |(x, _)| x.len());
        let mut weights = vec![0.0f64; feature_count];
        let mut bias = 0.0f64;

        if feature_count > 0 && !training_data.is_empty() {
            let lr = 0.01f64;
            let epochs = 100usize;

            for _ in 0..epochs {
                let mut grad_w = vec![0.0f64; feature_count];
                let mut grad_b = 0.0f64;
                let n = training_data.len() as f64;

                for (features, target) in training_data {
                    let pred = predict_linear(features, &weights, bias);
                    let error = pred - target;

                    for (j, xj) in features.iter().enumerate() {
                        grad_w[j] += error * xj;
                    }
                    grad_b += error;
                }

                for w in grad_w.iter_mut() {
                    *w = *w / n;
                }
                grad_b /= n;

                for (w, gw) in weights.iter_mut().zip(grad_w.iter()) {
                    *w -= lr * gw;
                }
                bias -= lr * grad_b;
            }
        }

        let accuracy = compute_accuracy(training_data, &weights, bias);
        let id = Uuid::new_v4().to_string();

        let model = Model {
            id: id.clone(),
            name: name.to_string(),
            model_type,
            weights: vec![weights],
            bias: vec![bias],
            feature_names: (0..feature_count)
                .map(|i| format!("f{}", i))
                .collect(),
            accuracy,
            trained_at: Utc::now(),
        };

        info!(
            "Trained model '{}' (id={}) – accuracy {:.4}",
            name, id, accuracy
        );
        self.models.insert(id.clone(), model);
        id
    }
}

// ---------------------------------------------------------------------------
// Prediction
// ---------------------------------------------------------------------------

impl AiEngine {
    pub fn predict(&mut self, model_id: &str, features: &[f64]) -> Option<Prediction> {
        let model = self.models.get(model_id)?;
        let weights = model.weights.first()?;
        let bias = model.bias.first()?;

        let output = predict_linear(features, weights, *bias);
        let confidence = Self::sigmoid(output.abs());

        let prediction = Prediction {
            model_id: model_id.to_string(),
            input_features: features.to_vec(),
            output,
            confidence,
            timestamp: Utc::now(),
        };

        self.predictions.push(prediction.clone());
        Some(prediction)
    }
}

// ---------------------------------------------------------------------------
// Online learning / profiling
// ---------------------------------------------------------------------------

impl AiEngine {
    pub fn update_profile(&mut self, entity_id: &str, feature_name: &str, value: f64) {
        if !self.config.enable_online_learning {
            return;
        }

        let now = Utc::now();
        let profile = self
            .anomaly_detector
            .profiles
            .entry(entity_id.to_string())
            .or_insert_with(|| FeatureProfile {
                entity_id: entity_id.to_string(),
                feature_stats: HashMap::new(),
                last_updated: now,
            });

        let stats = profile
            .feature_stats
            .entry(feature_name.to_string())
            .or_insert_with(RunningStats::default);

        stats.update(value);
        profile.last_updated = now;
    }
}

// ---------------------------------------------------------------------------
// Anomaly detection
// ---------------------------------------------------------------------------

impl AiEngine {
    pub fn detect_anomalies(
        &mut self,
        entity_id: &str,
        features: &[(String, f64)],
    ) -> Vec<AnomalyResult> {
        let threshold = self.anomaly_detector.threshold;
        let mut results = Vec::new();

        for (feature_name, value) in features {
            let profile = self
                .anomaly_detector
                .profiles
                .get(entity_id);

            let (mean, z) = match profile.and_then(|p| p.feature_stats.get(feature_name)) {
                Some(stats) if stats.count >= 2 => {
                    (stats.mean, stats.z_score(*value))
                }
                _ => {
                    (*value, 0.0)
                }
            };

            let is_anomaly = z.abs() > threshold;
            let severity = if is_anomaly {
                classify_severity(z.abs())
            } else {
                EventSeverity::Informational
            };

            results.push(AnomalyResult {
                entity_id: entity_id.to_string(),
                feature_name: feature_name.clone(),
                value: *value,
                expected_mean: mean,
                z_score: z,
                is_anomaly,
                severity,
            });

            if is_anomaly {
                warn!(
                    "Anomaly detected: entity={}, feature={}, value={:.4}, z={:.2}",
                    entity_id, feature_name, value, z
                );
            }
        }

        results
    }
}

// ---------------------------------------------------------------------------
// Feature transforms
// ---------------------------------------------------------------------------

impl AiEngine {
    pub fn transform_features(input: &[f64], transforms: &[FeatureTransform]) -> Vec<f64> {
        let mut output: Vec<f64> = input.to_vec();

        for transform in transforms {
            output = match transform {
                FeatureTransform::Normalize { min, max } => {
                    output.iter().map(|&v| Self::normalize(v, *min, *max)).collect()
                }
                FeatureTransform::Standardize { mean, std_dev } => {
                    output.iter().map(|&v| Self::standardize(v, *mean, *std_dev)).collect()
                }
                FeatureTransform::LogTransform => {
                    output.iter().map(|&v| v.ln().max(0.0)).collect()
                }
                FeatureTransform::SquareRoot => {
                    output.iter().map(|&v| v.max(0.0).sqrt()).collect()
                }
                FeatureTransform::BinValues { bins } => {
                    output.iter().map(|&v| bin_value(v, bins)).collect()
                }
                FeatureTransform::OneHot { categories } => {
                    let mut result = vec![0.0; categories.len()];
                    if let Some(first) = output.first() {
                        let idx = (*first as usize).min(categories.len().saturating_sub(1));
                        if idx < result.len() {
                            result[idx] = 1.0;
                        }
                    }
                    result
                }
            };
        }

        output
    }

    pub fn standardize(value: f64, mean: f64, std_dev: f64) -> f64 {
        if std_dev == 0.0 {
            return 0.0;
        }
        (value - mean) / std_dev
    }

    pub fn normalize(value: f64, min: f64, max: f64) -> f64 {
        let range = max - min;
        if range == 0.0 {
            return 0.0;
        }
        (value - min) / range
    }

    pub fn sigmoid(x: f64) -> f64 {
        1.0 / (1.0 + (-x).exp())
    }

    pub fn model_names(&self) -> Vec<String> {
        self.models.values().map(|m| m.name.clone()).collect()
    }

    pub fn get_model(&self, model_id: &str) -> Option<&Model> {
        self.models.get(model_id)
    }
}

// ---------------------------------------------------------------------------
// Free helpers
// ---------------------------------------------------------------------------

fn predict_linear(features: &[f64], weights: &[f64], bias: f64) -> f64 {
    features
        .iter()
        .zip(weights.iter())
        .map(|(x, w)| x * w)
        .sum::<f64>()
        + bias
}

fn compute_accuracy(data: &[(Vec<f64>, f64)], weights: &[f64], bias: f64) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut sum_sq_err = 0.0;
    let mut sum_sq_tot = 0.0;
    let mean_target: f64 = data.iter().map(|(_, y)| y).sum::<f64>() / data.len() as f64;

    for (features, target) in data {
        let pred = predict_linear(features, weights, bias);
        sum_sq_err += (target - pred).powi(2);
        sum_sq_tot += (target - mean_target).powi(2);
    }

    if sum_sq_tot == 0.0 {
        return 1.0;
    }

    1.0 - (sum_sq_err / sum_sq_tot)
}

fn bin_value(value: f64, bins: &[f64]) -> f64 {
    for (i, &edge) in bins.iter().enumerate() {
        if value < edge {
            return i as f64;
        }
    }
    bins.len() as f64
}

fn classify_severity(z_abs: f64) -> EventSeverity {
    if z_abs > 4.0 {
        EventSeverity::Critical
    } else if z_abs > 3.5 {
        EventSeverity::High
    } else if z_abs > 3.0 {
        EventSeverity::Medium
    } else {
        EventSeverity::Low
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_engine() -> AiEngine {
        AiEngine::new()
    }

    fn training_data_simple() -> Vec<(Vec<f64>, f64)> {
        // y ≈ 2*x0 + 3*x1 (small values for gradient descent stability)
        (0..120)
            .map(|i| {
                let x0 = (i % 10) as f64;
                let x1 = ((i / 10) % 10) as f64;
                let y = 2.0 * x0 + 3.0 * x1;
                (vec![x0, x1], y)
            })
            .collect()
    }

    #[test]
    fn test_new_engine_defaults() {
        let engine = make_engine();
        assert!(engine.models.is_empty());
        assert!(engine.predictions.is_empty());
        assert_eq!(engine.config.anomaly_threshold, 2.5);
        assert!(engine.config.enable_online_learning);
    }

    #[test]
    fn test_with_config() {
        let config = AiConfig {
            anomaly_threshold: 3.0,
            min_training_samples: 50,
            model_update_interval_secs: 7200,
            enable_online_learning: false,
        };
        let engine = AiEngine::with_config(config);
        assert_eq!(engine.anomaly_detector.threshold, 3.0);
        assert!(!engine.config.enable_online_learning);
    }

    #[test]
    fn test_train_simple_model() {
        let mut engine = make_engine();
        let data = training_data_simple();
        let id = engine.train_simple_model("test_linear", ModelType::Regressor, &data);

        assert!(engine.models.contains_key(&id));
        let model = engine.get_model(&id).unwrap();
        assert_eq!(model.name, "test_linear");
        assert!(model.accuracy > 0.9);
    }

    #[test]
    fn test_predict_after_train() {
        let mut engine = make_engine();
        let data = training_data_simple();
        let id = engine.train_simple_model("pred_test", ModelType::Regressor, &data);

        let prediction = engine.predict(&id, &[10.0, 5.0]);
        assert!(prediction.is_some());

        let p = prediction.unwrap();
        let expected = 2.0 * 10.0 + 3.0 * 5.0;
        assert!(
            (p.output - expected).abs() < 5.0,
            "prediction {} too far from expected {}",
            p.output,
            expected
        );
        assert!(p.confidence > 0.0 && p.confidence <= 1.0);
    }

    #[test]
    fn test_predict_nonexistent_model() {
        let mut engine = make_engine();
        assert!(engine.predict("no-such-id", &[1.0, 2.0]).is_none());
    }

    #[test]
    fn test_update_profile_and_detect() {
        let mut engine = make_engine();

        // Feed 50 samples with mean ~10
        for i in 0..50 {
            engine.update_profile("host1", "cpu_usage", 10.0 + (i as f64 % 5.0));
        }

        // Normal value → not anomalous
        let results = engine.detect_anomalies("host1", &[("cpu_usage".into(), 12.0)]);
        assert!(!results[0].is_anomaly);

        // Extreme value → anomaly
        let results = engine.detect_anomalies("host1", &[("cpu_usage".into(), 50.0)]);
        assert!(results[0].is_anomaly);
        assert!(results[0].z_score.abs() > engine.anomaly_detector.threshold);
    }

    #[test]
    fn test_detect_anomalies_no_profile() {
        let mut engine = make_engine();
        let results = engine.detect_anomalies("unknown", &[("feat".into(), 42.0)]);
        assert_eq!(results.len(), 1);
        assert!(!results[0].is_anomaly);
    }

    #[test]
    fn test_z_score_computation() {
        let mut stats = RunningStats::default();
        for v in [10.0, 12.0, 8.0, 11.0, 9.0] {
            stats.update(v);
        }
        assert!((stats.mean - 10.0).abs() < 1e-10);
        assert!(stats.std_dev() > 0.0);

        let z = stats.z_score(10.0);
        assert!(z.abs() < 1e-10, "z-score of mean should be ~0");

        let z = stats.z_score(20.0);
        assert!(z > 2.0, "outlier should have high z-score");
    }

    #[test]
    fn test_normalize_and_standardize() {
        assert_eq!(AiEngine::normalize(5.0, 0.0, 10.0), 0.5);
        assert_eq!(AiEngine::normalize(0.0, 0.0, 10.0), 0.0);
        assert_eq!(AiEngine::normalize(10.0, 0.0, 10.0), 1.0);
        assert_eq!(AiEngine::normalize(5.0, 5.0, 5.0), 0.0);

        let std = AiEngine::standardize(10.0, 10.0, 2.0);
        assert!(std.abs() < 1e-10);
        assert_eq!(AiEngine::standardize(5.0, 5.0, 0.0), 0.0);
    }

    #[test]
    fn test_sigmoid() {
        assert!((AiEngine::sigmoid(0.0) - 0.5).abs() < 1e-10);
        assert!(AiEngine::sigmoid(100.0) > 0.99);
        assert!(AiEngine::sigmoid(-100.0) < 0.01);
    }

    #[test]
    fn test_transform_features_normalize() {
        let input = vec![2.0, 4.0, 6.0];
        let transforms = vec![FeatureTransform::Normalize { min: 0.0, max: 10.0 }];
        let output = AiEngine::transform_features(&input, &transforms);
        assert!((output[0] - 0.2).abs() < 1e-10);
        assert!((output[1] - 0.4).abs() < 1e-10);
        assert!((output[2] - 0.6).abs() < 1e-10);
    }

    #[test]
    fn test_transform_features_standardize() {
        let input = vec![10.0, 20.0, 30.0];
        let transforms = vec![FeatureTransform::Standardize { mean: 20.0, std_dev: 10.0 }];
        let output = AiEngine::transform_features(&input, &transforms);
        assert!((output[0] - (-1.0)).abs() < 1e-10);
        assert!((output[1] - 0.0).abs() < 1e-10);
        assert!((output[2] - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_transform_features_chained() {
        let input = vec![5.0];
        let transforms = vec![
            FeatureTransform::Normalize { min: 0.0, max: 10.0 },
            FeatureTransform::SquareRoot,
        ];
        let output = AiEngine::transform_features(&input, &transforms);
        // first: 5/10 = 0.5, then sqrt(0.5) ≈ 0.7071
        assert!((output[0] - 0.5_f64.sqrt()).abs() < 1e-10);
    }

    #[test]
    fn test_model_names() {
        let mut engine = make_engine();
        let data = training_data_simple();
        engine.train_simple_model("alpha", ModelType::Classifier, &data);
        engine.train_simple_model("beta", ModelType::Regressor, &data);

        let names = engine.model_names();
        assert!(names.contains(&"alpha".to_string()));
        assert!(names.contains(&"beta".to_string()));
    }

    #[test]
    fn test_online_learning_disabled() {
        let config = AiConfig {
            enable_online_learning: false,
            ..AiConfig::default()
        };
        let mut engine = AiEngine::with_config(config);
        engine.update_profile("host1", "cpu", 50.0);

        assert!(
            engine.anomaly_detector.profiles.is_empty(),
            "profile should not be created when online learning is off"
        );
    }

    #[test]
    fn test_anomaly_severity_classification() {
        assert_eq!(classify_severity(5.0), EventSeverity::Critical);
        assert_eq!(classify_severity(3.7), EventSeverity::High);
        assert_eq!(classify_severity(3.2), EventSeverity::Medium);
        assert_eq!(classify_severity(2.6), EventSeverity::Low);
    }

    #[test]
    fn test_bin_values() {
        let transforms = vec![FeatureTransform::BinValues {
            bins: vec![3.0, 7.0, 10.0],
        }];
        assert_eq!(AiEngine::transform_features(&[1.0], &transforms)[0], 0.0);
        assert_eq!(AiEngine::transform_features(&[5.0], &transforms)[0], 1.0);
        assert_eq!(AiEngine::transform_features(&[8.0], &transforms)[0], 2.0);
        assert_eq!(AiEngine::transform_features(&[11.0], &transforms)[0], 3.0);
    }

    #[test]
    fn test_one_hot() {
        let transforms = vec![FeatureTransform::OneHot {
            categories: vec!["a".into(), "b".into(), "c".into()],
        }];
        let out = AiEngine::transform_features(&[1.0], &transforms);
        assert_eq!(out, vec![0.0, 1.0, 0.0]);
    }

    #[test]
    fn test_prediction_stored() {
        let mut engine = make_engine();
        let data = training_data_simple();
        let id = engine.train_simple_model("store_test", ModelType::Regressor, &data);
        engine.predict(&id, &[1.0, 2.0]).unwrap();

        assert_eq!(engine.predictions.len(), 1);
        assert_eq!(engine.predictions[0].model_id, id);
    }
}
