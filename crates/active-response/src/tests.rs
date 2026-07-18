use super::actions::*;
use super::containment::*;
use super::playbooks::*;
use super::quarantine::*;

#[test]
fn test_response_action_create() {
    let action = ResponseAction::TerminateProcess { pid: 1234, process_name: Some("malware.exe".into()) };
    let action_type = action.action_type_name();
    assert_eq!(action_type, "TerminateProcess");
}

#[test]
fn test_containment_level_default() {
    let mgr = ContainmentManager::new();
    assert_eq!(*mgr.get_current_level(), ContainmentLevel::None);
}

#[test]
fn test_playbook_engine_new() {
    let engine = PlaybookEngine::new();
    assert_eq!(engine.list_playbooks().len(), 4);
}

#[test]
fn test_quarantine_store_new() {
    let store = QuarantineStore::new();
    assert_eq!(store.count(), 0);
}

#[test]
fn test_quarantine_list_empty() {
    let store = QuarantineStore::new();
    assert!(store.list_quarantined().is_empty());
}

#[test]
fn test_action_result_format() {
    let action = ResponseAction::BlockIp { ip: "1.2.3.4".into(), direction: "inbound".into(), duration_minutes: Some(30) };
    let action_type = action.action_type_name();
    assert_eq!(action_type, "BlockIp");
}

#[test]
fn test_containment_set_levels() {
    let mut mgr = ContainmentManager::new();
    mgr.set_containment_level(ContainmentLevel::Partial, None).unwrap();
    assert_eq!(*mgr.get_current_level(), ContainmentLevel::Partial);
}

#[test]
fn test_playbook_register() {
    let mut engine = PlaybookEngine::new();
    engine.register_playbook(Playbook {
        id: "test-1".into(),
        name: "Test Playbook".into(),
        description: "Test".into(),
        triggers: vec![],
        steps: vec![],
        enabled: true,
    });
    assert_eq!(engine.list_playbooks().len(), 5);
}

#[test]
fn test_restore_not_found() {
    let store = QuarantineStore::new();
    assert!(store.restore_file("nonexistent").is_err());
}

#[test]
fn test_delete_not_found() {
    let mut store = QuarantineStore::new();
    assert!(store.delete_quarantined("nonexistent").is_err());
}
