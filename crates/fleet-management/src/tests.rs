#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::*;
    use crate::commands::*;
    use crate::policies::*;
    use crate::groups::*;
    use crate::monitoring::*;
    use chrono::Utc;

    #[test]
    fn test_agent_registration() {
        let registry = AgentRegistry::new();
        let agent = AgentInfo::new(
            "test-host".to_string(),
            "windows".to_string(),
            "192.168.1.1".to_string(),
            "1.0.0".to_string(),
        );
        let id = agent.id;
        registry.register_agent(agent);
        assert_eq!(registry.list_agents().len(), 1);
        assert!(registry.get_agent(&id).is_some());
    }

    #[test]
    fn test_agent_heartbeat() {
        let registry = AgentRegistry::new();
        let mut agent = AgentInfo::new(
            "test-host".to_string(),
            "windows".to_string(),
            "192.168.1.1".to_string(),
            "1.0.0".to_string(),
        );
        let id = agent.id;
        registry.register_agent(agent);
        assert!(registry.heartbeat(&id));
        let retrieved = registry.get_agent(&id).unwrap();
        assert_eq!(retrieved.status, AgentStatus::Online);
    }

    #[test]
    fn test_command_dispatch() {
        let dispatcher = CommandDispatcher::new();
        let agent_id = uuid::Uuid::new_v4();
        let command = FleetCommand::Ping;
        let command_id = dispatcher.send_command(agent_id, command);
        assert!(dispatcher.dispatch_command(&command_id));
        assert!(dispatcher.complete_command(&command_id, None));
        let result = dispatcher.get_status(&command_id).unwrap();
        assert_eq!(result.status, CommandStatus::Completed);
    }

    #[test]
    fn test_command_retry() {
        let dispatcher = CommandDispatcher::new();
        let agent_id = uuid::Uuid::new_v4();
        let command = FleetCommand::Ping;
        let command_id = dispatcher.send_command(agent_id, command);
        dispatcher.dispatch_command(&command_id);
        dispatcher.fail_command(&command_id, "test error".to_string());
        assert!(dispatcher.retry_command(&command_id));
        let result = dispatcher.get_status(&command_id).unwrap();
        assert_eq!(result.status, CommandStatus::Pending);
        assert_eq!(result.retry_count, 1);
    }

    #[test]
    fn test_policy_engine() {
        let engine = PolicyEngine::new();
        let mut policy = Policy::new(
            "test policy".to_string(),
            "test description".to_string(),
            PolicyTargets::All,
        );
        policy.add_condition(Condition::AlertSeverity {
            severity: "critical".to_string(),
        });
        policy.add_action(Action::SendNotification {
            message: "alert".to_string(),
            channels: vec!["email".to_string()],
        });
        let policy_id = engine.add_policy(policy);
        assert_eq!(engine.list_policies().len(), 1);

        let context = EvaluationContext {
            online_agent_count: 10,
            current_severity: "critical".to_string(),
            event_type: "intrusion".to_string(),
            last_policy_execution: None,
            agent_tags: Vec::new(),
            agent_os: "windows".to_string(),
        };

        let actions = engine.evaluate_policies(&context);
        assert_eq!(actions.len(), 1);
    }

    #[test]
    fn test_group_management() {
        let manager = GroupManager::new();
        let group_id = manager.create_group(
            "test group".to_string(),
            "test description".to_string(),
        );
        let agent_id = uuid::Uuid::new_v4();
        assert!(manager.add_agent_to_group(&group_id, agent_id));
        let agents = manager.get_group_agents(&group_id);
        assert_eq!(agents.len(), 1);
        assert!(manager.remove_agent_from_group(&group_id, &agent_id));
        let agents = manager.get_group_agents(&group_id);
        assert_eq!(agents.len(), 0);
    }

    #[tokio::test]
    async fn test_monitoring_service() {
        let service = MonitoringService::new();
        let registry = AgentRegistry::new();
        let stats = service.get_fleet_stats(&registry).await;
        assert_eq!(stats.total_agents, 0);
        assert_eq!(stats.online_agents, 0);
    }

    #[test]
    fn test_agent_stale_detection() {
        let agent = AgentInfo {
            id: uuid::Uuid::new_v4(),
            hostname: "test".to_string(),
            os: "windows".to_string(),
            ip: "192.168.1.1".to_string(),
            version: "1.0.0".to_string(),
            status: AgentStatus::Online,
            last_seen: Utc::now() - chrono::Duration::minutes(10),
            registered_at: Utc::now(),
            tags: Vec::new(),
        };
        assert!(agent.is_stale());
    }

    #[test]
    fn test_auto_grouping() {
        let manager = GroupManager::new();
        let group_id = manager.create_group(
            "windows hosts".to_string(),
            "all windows agents".to_string(),
        );
        manager.add_auto_group_rule(
            &group_id,
            AutoGroupRule::ByOs {
                os_pattern: "windows".to_string(),
            },
        );

        let agent = AgentInfo::new(
            "win-host".to_string(),
            "windows 10".to_string(),
            "192.168.1.1".to_string(),
            "1.0.0".to_string(),
        );

        let assignments = manager.apply_auto_grouping(&[agent]);
        assert_eq!(assignments.len(), 1);
        assert_eq!(assignments[0].1.len(), 1);
    }

    #[test]
    fn test_agent_tags() {
        let registry = AgentRegistry::new();
        let mut agent = AgentInfo::new(
            "test-host".to_string(),
            "windows".to_string(),
            "192.168.1.1".to_string(),
            "1.0.0".to_string(),
        );
        let id = agent.id;
        registry.register_agent(agent);
        assert!(registry.add_tag(&id, "critical".to_string()));
        let agents = registry.get_agents_by_tag("critical");
        assert_eq!(agents.len(), 1);
        assert!(registry.remove_tag(&id, "critical"));
        let agents = registry.get_agents_by_tag("critical");
        assert_eq!(agents.len(), 0);
    }

    #[test]
    fn test_policy_targets() {
        let engine = PolicyEngine::new();
        let agent_id = uuid::Uuid::new_v4();
        let mut policy = Policy::new(
            "targeted policy".to_string(),
            "test".to_string(),
            PolicyTargets::AgentIds(vec![agent_id]),
        );
        policy.add_condition(Condition::AgentCountThreshold {
            operator: "gt".to_string(),
            value: 5,
        });
        let policy_id = engine.add_policy(policy);

        let context = EvaluationContext {
            online_agent_count: 10,
            current_severity: "info".to_string(),
            event_type: "test".to_string(),
            last_policy_execution: None,
            agent_tags: Vec::new(),
            agent_os: "windows".to_string(),
        };

        let actions = engine.apply_policy(&policy_id, &context);
        assert!(actions.is_some());
        assert_eq!(actions.unwrap().len(), 0);
    }
}
