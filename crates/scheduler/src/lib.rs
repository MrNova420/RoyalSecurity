pub mod prelude;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, warn};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TaskPriority {
    Critical,
    High,
    Medium,
    Low,
}

impl std::fmt::Display for TaskPriority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TaskPriority::Critical => write!(f, "Critical"),
            TaskPriority::High => write!(f, "High"),
            TaskPriority::Medium => write!(f, "Medium"),
            TaskPriority::Low => write!(f, "Low"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Schedule {
    Cron(String),
    Interval(u64),
    Once(DateTime<Utc>),
    EventTrigger(String),
    Dependency(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TaskAction {
    ExecuteCommand(String),
    RunCheck(String),
    UpdateFeed(String),
    PurgeOldData,
    RunComplianceScan,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScheduleStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskResult {
    pub task_id: String,
    pub success: bool,
    pub message: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledTask {
    pub id: String,
    pub name: String,
    pub description: String,
    pub schedule: Schedule,
    pub priority: TaskPriority,
    pub enabled: bool,
    pub last_run: Option<DateTime<Utc>>,
    pub next_run: Option<DateTime<Utc>>,
    pub run_count: u64,
    pub action: TaskAction,
}

#[derive(Debug)]
pub struct TaskScheduler {
    tasks: HashMap<String, ScheduledTask>,
    pub executed_count: u64,
    pub failed_count: u64,
}

fn compute_next_run(schedule: &Schedule) -> Option<DateTime<Utc>> {
    match schedule {
        Schedule::Cron(expr) => expr
            .parse::<cron::Schedule>()
            .ok()
            .and_then(|s| s.upcoming(Utc).next()),
        Schedule::Interval(secs) => Some(Utc::now() + chrono::Duration::seconds(*secs as i64)),
        Schedule::Once(at) => Some(*at),
        Schedule::EventTrigger(_) | Schedule::Dependency(_) => None,
    }
}

impl Default for TaskScheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl TaskScheduler {
    pub fn new() -> Self {
        Self {
            tasks: HashMap::new(),
            executed_count: 0,
            failed_count: 0,
        }
    }

    pub fn add_task(
        &mut self,
        name: &str,
        schedule: Schedule,
        action: TaskAction,
        priority: TaskPriority,
    ) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        let next_run = compute_next_run(&schedule);
        let task = ScheduledTask {
            id: id.clone(),
            name: name.to_string(),
            description: String::new(),
            schedule,
            priority,
            enabled: true,
            last_run: None,
            next_run,
            run_count: 0,
            action,
        };
        self.tasks.insert(id.clone(), task);
        info!("Scheduled task '{}' added with id '{}'", name, id);
        id
    }

    pub fn remove_task(&mut self, task_id: &str) -> bool {
        let removed = self.tasks.remove(task_id);
        if removed.is_some() {
            info!("Scheduled task '{}' removed", task_id);
        }
        removed.is_some()
    }

    pub fn enable_task(&mut self, task_id: &str) {
        if let Some(task) = self.tasks.get_mut(task_id) {
            task.enabled = true;
            info!("Scheduled task '{}' enabled", task_id);
        } else {
            warn!("Task '{}' not found for enable", task_id);
        }
    }

    pub fn disable_task(&mut self, task_id: &str) {
        if let Some(task) = self.tasks.get_mut(task_id) {
            task.enabled = false;
            info!("Scheduled task '{}' disabled", task_id);
        } else {
            warn!("Task '{}' not found for disable", task_id);
        }
    }

    pub fn trigger_event(&self, event_type: &str) -> Vec<String> {
        self.tasks
            .iter()
            .filter(|(_, task)| {
                task.enabled && task.schedule == Schedule::EventTrigger(event_type.to_string())
            })
            .map(|(id, _)| id.clone())
            .collect()
    }

    pub fn get_due_tasks(&self) -> Vec<&ScheduledTask> {
        let now = Utc::now();
        self.tasks
            .values()
            .filter(|task| task.enabled && task.next_run.map_or(false, |nr| nr <= now))
            .collect()
    }

    pub fn update_next_run(&mut self, task_id: &str) {
        let now = Utc::now();
        if let Some(task) = self.tasks.get_mut(task_id) {
            task.next_run = compute_next_run(&task.schedule);
            if task.next_run.is_some() {
                task.last_run = Some(now);
                task.run_count += 1;
            }
        }
    }

    pub fn get_task(&self, task_id: &str) -> Option<&ScheduledTask> {
        self.tasks.get(task_id)
    }

    pub fn all_tasks(&self) -> Vec<&ScheduledTask> {
        self.tasks.values().collect()
    }

    pub fn executed_count(&self) -> u64 {
        self.executed_count
    }

    pub fn failed_count(&self) -> u64 {
        self.failed_count
    }

    pub fn sort_by_priority(tasks: &mut Vec<&ScheduledTask>) {
        tasks.sort_by(|a, b| a.priority.cmp(&b.priority));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_scheduler_with_tasks() -> TaskScheduler {
        let mut scheduler = TaskScheduler::new();

        scheduler.add_task(
            "cron-task",
            Schedule::Cron("0 0 */2 * * ? *".to_string()),
            TaskAction::RunCheck("integrity".to_string()),
            TaskPriority::High,
        );

        scheduler.add_task(
            "interval-task",
            Schedule::Interval(300),
            TaskAction::UpdateFeed("threat-intel".to_string()),
            TaskPriority::Medium,
        );

        scheduler.add_task(
            "once-task",
            Schedule::Once(Utc::now() + chrono::Duration::hours(1)),
            TaskAction::ExecuteCommand("backup".to_string()),
            TaskPriority::Critical,
        );

        scheduler.add_task(
            "event-task",
            Schedule::EventTrigger("ThreatDetected".to_string()),
            TaskAction::RunComplianceScan,
            TaskPriority::Low,
        );

        scheduler
    }

    #[test]
    fn test_new_scheduler_is_empty() {
        let scheduler = TaskScheduler::new();
        assert_eq!(scheduler.all_tasks().len(), 0);
        assert_eq!(scheduler.executed_count(), 0);
        assert_eq!(scheduler.failed_count(), 0);
    }

    #[test]
    fn test_add_task_returns_unique_id() {
        let mut scheduler = TaskScheduler::new();
        let id1 = scheduler.add_task(
            "task-a",
            Schedule::Interval(60),
            TaskAction::PurgeOldData,
            TaskPriority::Low,
        );
        let id2 = scheduler.add_task(
            "task-b",
            Schedule::Interval(60),
            TaskAction::PurgeOldData,
            TaskPriority::Low,
        );
        assert_ne!(id1, id2);
        assert_eq!(scheduler.all_tasks().len(), 2);
    }

    #[test]
    fn test_remove_task() {
        let mut scheduler = TaskScheduler::new();
        let id = scheduler.add_task(
            "temp",
            Schedule::Interval(60),
            TaskAction::PurgeOldData,
            TaskPriority::Low,
        );
        assert!(scheduler.remove_task(&id));
        assert!(!scheduler.remove_task(&id));
        assert_eq!(scheduler.all_tasks().len(), 0);
    }

    #[test]
    fn test_enable_disable_task() {
        let mut scheduler = TaskScheduler::new();
        let id = scheduler.add_task(
            "toggle-me",
            Schedule::Interval(60),
            TaskAction::PurgeOldData,
            TaskPriority::Medium,
        );
        scheduler.disable_task(&id);
        assert!(!scheduler.get_task(&id).unwrap().enabled);
        scheduler.enable_task(&id);
        assert!(scheduler.get_task(&id).unwrap().enabled);
    }

    #[test]
    fn test_trigger_event_returns_matching_tasks() {
        let scheduler = make_scheduler_with_tasks();
        let triggered = scheduler.trigger_event("ThreatDetected");
        assert_eq!(triggered.len(), 1);
        assert_eq!(scheduler.get_task(&triggered[0]).unwrap().name, "event-task");
    }

    #[test]
    fn test_trigger_event_returns_empty_on_no_match() {
        let scheduler = make_scheduler_with_tasks();
        let triggered = scheduler.trigger_event("NonExistentEvent");
        assert!(triggered.is_empty());
    }

    #[test]
    fn test_trigger_event_ignores_disabled_tasks() {
        let mut scheduler = TaskScheduler::new();
        let id = scheduler.add_task(
            "disabled-event",
            Schedule::EventTrigger("ThreatDetected".to_string()),
            TaskAction::RunComplianceScan,
            TaskPriority::Critical,
        );
        scheduler.disable_task(&id);
        let triggered = scheduler.trigger_event("ThreatDetected");
        assert!(triggered.is_empty());
    }

    #[test]
    fn test_get_due_tasks() {
        let mut scheduler = TaskScheduler::new();
        scheduler.add_task(
            "past-due",
            Schedule::Once(Utc::now() - chrono::Duration::hours(1)),
            TaskAction::PurgeOldData,
            TaskPriority::Low,
        );
        scheduler.add_task(
            "future",
            Schedule::Once(Utc::now() + chrono::Duration::hours(1)),
            TaskAction::PurgeOldData,
            TaskPriority::Low,
        );
        let due = scheduler.get_due_tasks();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].name, "past-due");
    }

    #[test]
    fn test_update_next_run_cron() {
        let mut scheduler = TaskScheduler::new();
        let id = scheduler.add_task(
            "cron-test",
            Schedule::Cron("0 0 12 * * ? *".to_string()),
            TaskAction::PurgeOldData,
            TaskPriority::Medium,
        );
        scheduler.update_next_run(&id);
        let task = scheduler.get_task(&id).unwrap();
        assert!(task.next_run.is_some());
        assert!(task.last_run.is_some());
        assert_eq!(task.run_count, 1);
    }

    #[test]
    fn test_update_next_run_interval() {
        let mut scheduler = TaskScheduler::new();
        let id = scheduler.add_task(
            "interval-test",
            Schedule::Interval(60),
            TaskAction::PurgeOldData,
            TaskPriority::Medium,
        );
        scheduler.update_next_run(&id);
        let task = scheduler.get_task(&id).unwrap();
        assert!(task.next_run.is_some());
        let expected = Utc::now() + chrono::Duration::seconds(60);
        let diff = (task.next_run.unwrap() - expected).num_seconds().abs();
        assert!(
            diff <= 2,
            "Next run should be ~60s from now, diff was {}s",
            diff
        );
    }

    #[test]
    fn test_sort_by_priority() {
        let mut scheduler = TaskScheduler::new();
        scheduler.add_task(
            "low",
            Schedule::Interval(1),
            TaskAction::PurgeOldData,
            TaskPriority::Low,
        );
        scheduler.add_task(
            "critical",
            Schedule::Interval(1),
            TaskAction::PurgeOldData,
            TaskPriority::Critical,
        );
        scheduler.add_task(
            "medium",
            Schedule::Interval(1),
            TaskAction::PurgeOldData,
            TaskPriority::Medium,
        );
        scheduler.add_task(
            "high",
            Schedule::Interval(1),
            TaskAction::PurgeOldData,
            TaskPriority::High,
        );

        let mut tasks = scheduler.all_tasks();
        TaskScheduler::sort_by_priority(&mut tasks);

        assert_eq!(tasks[0].priority, TaskPriority::Critical);
        assert_eq!(tasks[1].priority, TaskPriority::High);
        assert_eq!(tasks[2].priority, TaskPriority::Medium);
        assert_eq!(tasks[3].priority, TaskPriority::Low);
    }

    #[test]
    fn test_dependency_schedule_no_next_run() {
        let mut scheduler = TaskScheduler::new();
        let id = scheduler.add_task(
            "dep-task",
            Schedule::Dependency("other-task-id".to_string()),
            TaskAction::RunCheck("fs".to_string()),
            TaskPriority::Low,
        );
        assert!(scheduler.get_task(&id).unwrap().next_run.is_none());
    }

    #[test]
    fn test_task_result_fields() {
        let result = TaskResult {
            task_id: "abc".into(),
            success: true,
            message: "done".into(),
            started_at: Utc::now(),
            completed_at: Utc::now(),
            duration_ms: 42,
        };
        assert!(result.success);
        assert_eq!(result.duration_ms, 42);
    }

    #[test]
    fn test_priority_ordering() {
        assert!(TaskPriority::Critical < TaskPriority::High);
        assert!(TaskPriority::High < TaskPriority::Medium);
        assert!(TaskPriority::Medium < TaskPriority::Low);
    }
}
