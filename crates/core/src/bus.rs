use tokio::sync::broadcast;
use crate::common::types::SecurityEvent;

const BUS_CAPACITY: usize = 100_000;

pub struct EventBus {
    sender: broadcast::Sender<SecurityEvent>,
}

impl EventBus {
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(BUS_CAPACITY);
        Self { sender }
    }

    pub fn publish(&self, event: SecurityEvent) -> Result<(), broadcast::error::SendError<SecurityEvent>> {
        self.sender.send(event).map(|_| ())
    }

    pub fn subscribe(&self) -> broadcast::Receiver<SecurityEvent> {
        self.sender.subscribe()
    }

    pub fn subscriber_count(&self) -> usize {
        self.sender.receiver_count()
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for EventBus {
    fn clone(&self) -> Self {
        Self { sender: self.sender.clone() }
    }
}
