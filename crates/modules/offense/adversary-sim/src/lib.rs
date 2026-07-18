pub mod prelude;

use chrono::{DateTime, Utc};
use tracing::{info, warn, debug};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttackAction {
    ExecuteCommand(String),
    CreateProcess(String),
    ModifyRegistry(String, String),
    NetworkConnection(String, u16),
    FileOperation(String),
    CredentialAccess(String),
    PersistenceInstall(String),
    DefenseEvasion(String),
}

impl std::fmt::Display for AttackAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttackAction::ExecuteCommand(cmd) => write!(f, "ExecuteCommand({})", cmd),
            AttackAction::CreateProcess(proc) => write!(f, "CreateProcess({})", proc),
            AttackAction::ModifyRegistry(key, val) => write!(f, "ModifyRegistry({}, {})", key, val),
            AttackAction::NetworkConnection(host, port) => write!(f, "NetworkConnection({}, {})", host, port),
            AttackAction::FileOperation(path) => write!(f, "FileOperation({})", path),
            AttackAction::CredentialAccess(target) => write!(f, "CredentialAccess({})", target),
            AttackAction::PersistenceInstall(name) => write!(f, "PersistenceInstall({})", name),
            AttackAction::DefenseEvasion(method) => write!(f, "DefenseEvasion({})", method),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackStep {
    pub name: String,
    pub action: AttackAction,
    pub expected_result: String,
    pub detection_expected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackScenario {
    pub id: String,
    pub name: String,
    pub description: String,
    pub mitre_tactic: String,
    pub mitre_technique: String,
    pub steps: Vec<AttackStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationResult {
    pub scenario_id: String,
    pub steps_run: usize,
    pub steps_detected: usize,
    pub detections_triggered: Vec<String>,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub detection_rate: f64,
}

pub struct AdversarySim {
    scenarios: HashMap<String, AttackScenario>,
    detections: Vec<String>,
    results: Vec<SimulationResult>,
}

impl AdversarySim {
    pub fn new() -> Self {
        info!("Initializing adversary simulation engine");
        Self {
            scenarios: HashMap::new(),
            detections: Vec::new(),
            results: Vec::new(),
        }
    }

    pub fn create_scenario(
        &mut self,
        name: &str,
        description: &str,
        tactic: &str,
        technique: &str,
        steps: Vec<AttackStep>,
    ) -> String {
        let id = format!("SCN-{:04}", self.scenarios.len() + 1);
        info!(id = %id, name = %name, tactic = %tactic, "Creating attack scenario");

        let scenario = AttackScenario {
            id: id.clone(),
            name: name.to_string(),
            description: description.to_string(),
            mitre_tactic: tactic.to_string(),
            mitre_technique: technique.to_string(),
            steps,
        };
        self.scenarios.insert(id.clone(), scenario);
        id
    }

    pub fn run_scenario(&mut self, scenario_id: &str) -> SimulationResult {
        let scenario = self.scenarios.get(scenario_id);
        if scenario.is_none() {
            warn!(id = %scenario_id, "Scenario not found");
            return SimulationResult {
                scenario_id: scenario_id.to_string(),
                steps_run: 0,
                steps_detected: 0,
                detections_triggered: Vec::new(),
                start_time: Utc::now(),
                end_time: Utc::now(),
                detection_rate: 0.0,
            };
        }

        let scenario = scenario.unwrap();
        info!(
            id = %scenario_id,
            name = %scenario.name,
            steps = scenario.steps.len(),
            "Running attack scenario"
        );

        let start_time = Utc::now();
        let mut detections_triggered = Vec::new();
        let mut steps_detected = 0;

        for step in &scenario.steps {
            debug!(
                step = %step.name,
                action = %step.action,
                expected_detection = step.detection_expected,
                "Executing attack step"
            );

            if step.detection_expected {
                steps_detected += 1;
                let detection_msg = format!(
                    "[{}] Step '{}' action {} - detection triggered",
                    scenario.id, step.name, step.action
                );
                detections_triggered.push(detection_msg.clone());
                self.detections.push(detection_msg);
            }
        }

        let end_time = Utc::now();
        let steps_run = scenario.steps.len();
        let detection_rate = if steps_run > 0 {
            steps_detected as f64 / steps_run as f64
        } else {
            0.0
        };

        let result = SimulationResult {
            scenario_id: scenario_id.to_string(),
            steps_run,
            steps_detected,
            detections_triggered,
            start_time,
            end_time,
            detection_rate,
        };

        self.results.push(result.clone());
        info!(
            id = %scenario_id,
            steps_run = steps_run,
            steps_detected = steps_detected,
            rate = detection_rate,
            "Scenario execution completed"
        );

        result
    }

    pub fn get_detections(&self) -> Vec<String> {
        self.detections.clone()
    }

    pub fn calculate_detection_rate(result: &SimulationResult) -> f64 {
        result.detection_rate
    }

    pub fn list_scenarios(&self) -> Vec<&AttackScenario> {
        self.scenarios.values().collect()
    }
}

impl Default for AdversarySim {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_step(name: &str, action: AttackAction, detection_expected: bool) -> AttackStep {
        AttackStep {
            name: name.to_string(),
            action,
            expected_result: "success".to_string(),
            detection_expected,
        }
    }

    #[test]
    fn test_new_sim() {
        let sim = AdversarySim::new();
        assert!(sim.scenarios.is_empty());
        assert!(sim.detections.is_empty());
        assert!(sim.results.is_empty());
    }

    #[test]
    fn test_create_scenario() {
        let mut sim = AdversarySim::new();
        let steps = vec![
            make_step("Step1", AttackAction::ExecuteCommand("whoami".into()), true),
        ];
        let id = sim.create_scenario("Test", "Desc", "Execution", "T1059", steps);
        assert_eq!(id, "SCN-0001");
        assert_eq!(sim.scenarios.len(), 1);
    }

    #[test]
    fn test_run_scenario_success() {
        let mut sim = AdversarySim::new();
        let steps = vec![
            make_step("Step1", AttackAction::ExecuteCommand("cmd.exe".into()), true),
            make_step("Step2", AttackAction::CreateProcess("payload.exe".into()), true),
        ];
        let id = sim.create_scenario("Test", "Desc", "Execution", "T1059", steps);
        let result = sim.run_scenario(&id);

        assert_eq!(result.steps_run, 2);
        assert_eq!(result.steps_detected, 2);
        assert!((result.detection_rate - 1.0).abs() < f64::EPSILON);
        assert_eq!(result.detections_triggered.len(), 2);
    }

    #[test]
    fn test_run_scenario_no_detection() {
        let mut sim = AdversarySim::new();
        let steps = vec![
            make_step("Step1", AttackAction::DefenseEvasion("obfuscate".into()), false),
        ];
        let id = sim.create_scenario("Stealth", "No detect", "DefenseEvasion", "T1027", steps);
        let result = sim.run_scenario(&id);

        assert_eq!(result.steps_run, 1);
        assert_eq!(result.steps_detected, 0);
        assert!((result.detection_rate).abs() < f64::EPSILON);
        assert!(result.detections_triggered.is_empty());
    }

    #[test]
    fn test_run_scenario_nonexistent() {
        let mut sim = AdversarySim::new();
        let result = sim.run_scenario("SCN-9999");
        assert_eq!(result.steps_run, 0);
        assert!((result.detection_rate).abs() < f64::EPSILON);
    }

    #[test]
    fn test_get_detections() {
        let mut sim = AdversarySim::new();
        let steps = vec![
            make_step("Step1", AttackAction::FileOperation("/tmp/test".into()), true),
        ];
        let id = sim.create_scenario("Test", "Desc", "Collection", "T1005", steps);
        sim.run_scenario(&id);

        let detections = sim.get_detections();
        assert_eq!(detections.len(), 1);
        assert!(detections[0].contains("Step1"));
    }

    #[test]
    fn test_calculate_detection_rate() {
        let result = SimulationResult {
            scenario_id: "test".into(),
            steps_run: 10,
            steps_detected: 5,
            detections_triggered: vec![],
            start_time: Utc::now(),
            end_time: Utc::now(),
            detection_rate: 0.5,
        };
        let rate = AdversarySim::calculate_detection_rate(&result);
        assert!((rate - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_list_scenarios() {
        let mut sim = AdversarySim::new();
        let steps1 = vec![make_step("S1", AttackAction::ExecuteCommand("cmd".into()), true)];
        let steps2 = vec![make_step("S2", AttackAction::NetworkConnection("10.0.0.1".into(), 443), false)];
        sim.create_scenario("Scenario A", "Desc A", "InitialAccess", "T1190", steps1);
        sim.create_scenario("Scenario B", "Desc B", "CommandAndControl", "T1071", steps2);

        let scenarios = sim.list_scenarios();
        assert_eq!(scenarios.len(), 2);
    }

    #[test]
    fn test_attack_action_display() {
        let action = AttackAction::NetworkConnection("evil.com".into(), 443);
        assert_eq!(format!("{}", action), "NetworkConnection(evil.com, 443)");

        let action = AttackAction::CredentialAccess("lsass".into());
        assert_eq!(format!("{}", action), "CredentialAccess(lsass)");
    }

    #[test]
    fn test_attack_action_variants() {
        let actions = vec![
            AttackAction::ExecuteCommand("cmd".into()),
            AttackAction::CreateProcess("proc.exe".into()),
            AttackAction::ModifyRegistry("key".into(), "val".into()),
            AttackAction::NetworkConnection("host".into(), 80),
            AttackAction::FileOperation("path".into()),
            AttackAction::CredentialAccess("target".into()),
            AttackAction::PersistenceInstall("svc".into()),
            AttackAction::DefenseEvasion("method".into()),
        ];
        assert_eq!(actions.len(), 8);
    }

    #[test]
    fn test_mixed_detection_scenario() {
        let mut sim = AdversarySim::new();
        let steps = vec![
            make_step("Recon", AttackAction::ExecuteCommand("net user".into()), false),
            make_step("Exploit", AttackAction::CreateProcess("exploit.exe".into()), true),
            make_step("Persist", AttackAction::PersistenceInstall("backdoor".into()), true),
            make_step("Evade", AttackAction::DefenseEvasion("clear logs".into()), false),
        ];
        let id = sim.create_scenario("APT Sim", "Full chain", "LateralMovement", "T1021", steps);
        let result = sim.run_scenario(&id);

        assert_eq!(result.steps_run, 4);
        assert_eq!(result.steps_detected, 2);
        assert!((result.detection_rate - 0.5).abs() < f64::EPSILON);
    }
}
