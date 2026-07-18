use std::cell::UnsafeCell;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use crate::common::types::SecurityEvent;

const CAPACITY: usize = 100_000;
const UNINIT_SEQ: usize = usize::MAX;

#[derive(Debug)]
pub struct SendError(pub SecurityEvent);

impl std::fmt::Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "event bus send error")
    }
}

impl std::error::Error for SendError {}

#[derive(Debug, PartialEq)]
pub enum TryRecvError {
    Empty,
    Lagged(usize),
}

impl std::fmt::Display for TryRecvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TryRecvError::Empty => write!(f, "channel empty"),
            TryRecvError::Lagged(n) => write!(f, "lagged by {} events", n),
        }
    }
}

impl std::error::Error for TryRecvError {}

#[derive(Debug)]
pub enum RecvError {
    Disconnected,
}

#[derive(Debug)]
pub struct BusStats {
    pub events_published: AtomicUsize,
    pub events_delivered: AtomicUsize,
    pub events_dropped: AtomicUsize,
    pub publish_latency_ns: AtomicUsize,
}

impl Default for BusStats {
    fn default() -> Self {
        Self {
            events_published: AtomicUsize::new(0),
            events_delivered: AtomicUsize::new(0),
            events_dropped: AtomicUsize::new(0),
            publish_latency_ns: AtomicUsize::new(0),
        }
    }
}

impl BusStats {
    pub fn avg_publish_latency_ns(&self) -> f64 {
        let total = self.publish_latency_ns.load(Ordering::Relaxed) as f64;
        let count = self.events_published.load(Ordering::Relaxed) as f64;
        if count == 0.0 {
            0.0
        } else {
            total / count
        }
    }

    pub fn reset(&self) {
        self.events_published.store(0, Ordering::Relaxed);
        self.events_delivered.store(0, Ordering::Relaxed);
        self.events_dropped.store(0, Ordering::Relaxed);
        self.publish_latency_ns.store(0, Ordering::Relaxed);
    }
}

struct Slot {
    sequence: AtomicUsize,
    event: UnsafeCell<MaybeUninit<SecurityEvent>>,
}

unsafe impl Send for Slot {}
unsafe impl Sync for Slot {}

struct RingInner {
    slots: Vec<Slot>,
    write_pos: AtomicUsize,
    subscriber_count: AtomicUsize,
}

impl Drop for RingInner {
    fn drop(&mut self) {
        let write_pos = self.write_pos.load(Ordering::Relaxed);
        let count = write_pos.min(CAPACITY);
        for i in 0..count {
            unsafe {
                (*self.slots[i].event.get()).assume_init_drop();
            }
        }
    }
}

struct RingBuffer {
    inner: Arc<RingInner>,
}

impl RingBuffer {
    fn new() -> Self {
        let mut slots = Vec::with_capacity(CAPACITY);
        for _ in 0..CAPACITY {
            slots.push(Slot {
                sequence: AtomicUsize::new(UNINIT_SEQ),
                event: UnsafeCell::new(MaybeUninit::uninit()),
            });
        }
        Self {
            inner: Arc::new(RingInner {
                slots,
                write_pos: AtomicUsize::new(0),
                subscriber_count: AtomicUsize::new(0),
            }),
        }
    }
}

struct Producer {
    inner: Arc<RingInner>,
    stats: Arc<BusStats>,
}

impl Producer {
    #[inline]
    fn publish(&self, event: SecurityEvent) -> Result<(), SendError> {
        let start = Instant::now();
        let pos = self.inner.write_pos.fetch_add(1, Ordering::Relaxed);
        let idx = pos % CAPACITY;
        let slot = &self.inner.slots[idx];

        unsafe {
            if pos >= CAPACITY {
                (*slot.event.get()).assume_init_drop();
            }
            (*slot.event.get()).as_mut_ptr().write(event);
        }

        slot.sequence.store(pos, Ordering::Release);

        self.stats.events_published.fetch_add(1, Ordering::Relaxed);
        let elapsed_ns = start.elapsed().as_nanos() as usize;
        self.stats
            .publish_latency_ns
            .fetch_add(elapsed_ns, Ordering::Relaxed);
        Ok(())
    }
}

pub struct Receiver {
    inner: Arc<RingInner>,
    read_pos: usize,
    stats: Arc<BusStats>,
}

impl Receiver {
    #[inline]
    pub fn try_recv(&mut self) -> Result<SecurityEvent, TryRecvError> {
        loop {
            let idx = self.read_pos % CAPACITY;
            let slot = &self.inner.slots[idx];
            let seq = slot.sequence.load(Ordering::Acquire);

            if seq == self.read_pos {
                self.read_pos += 1;
                self.stats.events_delivered.fetch_add(1, Ordering::Relaxed);
                unsafe { return Ok((*(*slot.event.get()).as_ptr()).clone()); }
            } else if seq == UNINIT_SEQ || seq < self.read_pos {
                return Err(TryRecvError::Empty);
            } else {
                self.stats.events_dropped.fetch_add(1, Ordering::Relaxed);
                self.read_pos += 1;
            }
        }
    }

    pub fn recv(&mut self) -> Result<SecurityEvent, RecvError> {
        loop {
            match self.try_recv() {
                Ok(event) => return Ok(event),
                Err(TryRecvError::Empty) => std::thread::yield_now(),
                Err(TryRecvError::Lagged(_)) => continue,
            }
        }
    }
}

impl Drop for Receiver {
    fn drop(&mut self) {
        self.inner
            .subscriber_count
            .fetch_sub(1, Ordering::Relaxed);
    }
}

pub struct EventBus {
    producer: Producer,
    stats: Arc<BusStats>,
}

impl EventBus {
    pub fn new() -> Self {
        let ring = RingBuffer::new();
        let stats = Arc::new(BusStats::default());
        Self {
            producer: Producer {
                inner: Arc::clone(&ring.inner),
                stats: Arc::clone(&stats),
            },
            stats,
        }
    }

    pub fn publish(&self, event: SecurityEvent) -> Result<(), SendError> {
        self.producer.publish(event)
    }

    pub fn try_publish(&self, event: SecurityEvent) -> Result<(), SendError> {
        if self.has_backpressure() {
            return Err(SendError(event));
        }
        self.producer.publish(event)
    }

    pub fn publish_batch(&self, events: Vec<SecurityEvent>) -> usize {
        let mut count = 0usize;
        for event in events {
            if self.producer.publish(event).is_ok() {
                count += 1;
            }
        }
        count
    }

    pub fn has_backpressure(&self) -> bool {
        let write = self.producer.inner.write_pos.load(Ordering::Relaxed);
        (write % CAPACITY) > (CAPACITY * 80 / 100)
    }

    pub fn subscribe(&self) -> Receiver {
        self.producer
            .inner
            .subscriber_count
            .fetch_add(1, Ordering::Relaxed);
        Receiver {
            inner: Arc::clone(&self.producer.inner),
            read_pos: self.producer.inner.write_pos.load(Ordering::Acquire),
            stats: Arc::clone(&self.stats),
        }
    }

    pub fn subscriber_count(&self) -> usize {
        self.producer.inner.subscriber_count.load(Ordering::Relaxed)
    }

    pub fn stats(&self) -> &BusStats {
        &self.stats
    }

    pub fn capacity(&self) -> usize {
        CAPACITY
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for EventBus {
    fn clone(&self) -> Self {
        Self {
            producer: Producer {
                inner: Arc::clone(&self.producer.inner),
                stats: Arc::clone(&self.stats),
            },
            stats: Arc::clone(&self.stats),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::types::ProcessInfo;
    use std::thread;

    fn process_event() -> SecurityEvent {
        SecurityEvent::Process(ProcessInfo::default())
    }

    #[test]
    fn test_publish_subscribe() {
        let bus = EventBus::new();
        let mut rx = bus.subscribe();
        bus.publish(process_event()).unwrap();
        assert!(rx.try_recv().is_ok());
    }

    #[test]
    fn test_multiple_subscribers() {
        let bus = EventBus::new();
        let _rx1 = bus.subscribe();
        let _rx2 = bus.subscribe();
        assert_eq!(bus.subscriber_count(), 2);
    }

    #[test]
    fn test_ordering() {
        let bus = EventBus::new();
        let mut rx = bus.subscribe();
        for i in 0..100 {
            let mut evt = ProcessInfo::default();
            evt.pid = i as u32;
            bus.publish(SecurityEvent::Process(evt)).unwrap();
        }
        for i in 0..100 {
            let received = rx.try_recv().unwrap();
            if let SecurityEvent::Process(ref p) = received {
                assert_eq!(p.pid, i as u32);
            } else {
                panic!("Expected Process event");
            }
        }
    }

    #[test]
    fn test_independent_subscribers() {
        let bus = EventBus::new();
        let mut rx1 = bus.subscribe();
        let mut rx2 = bus.subscribe();

        for i in 0..50 {
            let mut evt = ProcessInfo::default();
            evt.pid = i as u32;
            bus.publish(SecurityEvent::Process(evt)).unwrap();
        }

        for i in 0..50 {
            let e1 = rx1.try_recv().unwrap();
            let e2 = rx2.try_recv().unwrap();
            if let SecurityEvent::Process(ref p) = e1 {
                assert_eq!(p.pid, i as u32);
            }
            if let SecurityEvent::Process(ref p) = e2 {
                assert_eq!(p.pid, i as u32);
            }
        }

        assert!(matches!(rx1.try_recv(), Err(TryRecvError::Empty)));
        assert!(matches!(rx2.try_recv(), Err(TryRecvError::Empty)));
    }

    #[test]
    fn test_late_subscriber_gets_empty() {
        let bus = EventBus::new();
        for i in 0..10 {
            let mut evt = ProcessInfo::default();
            evt.pid = i as u32;
            bus.publish(SecurityEvent::Process(evt)).unwrap();
        }
        let mut rx = bus.subscribe();
        assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
    }

    #[test]
    fn test_overflow_drops_oldest() {
        let bus = EventBus::new();
        let mut rx = bus.subscribe();

        for i in 0..(CAPACITY + 100) {
            let mut evt = ProcessInfo::default();
            evt.pid = i as u32;
            bus.publish(SecurityEvent::Process(evt)).unwrap();
        }

        let mut delivered = 0;
        while rx.try_recv().is_ok() {
            delivered += 1;
        }
        assert_eq!(delivered, CAPACITY);

        let dropped = bus.stats().events_dropped.load(Ordering::Relaxed);
        assert_eq!(dropped, 100);
    }

    #[test]
    fn test_stats_tracking() {
        let bus = EventBus::new();
        let mut rx = bus.subscribe();

        for _ in 0..1000 {
            bus.publish(process_event()).unwrap();
        }
        for _ in 0..1000 {
            rx.try_recv().unwrap();
        }

        let stats = bus.stats();
        assert_eq!(stats.events_published.load(Ordering::Relaxed), 1000);
        assert_eq!(stats.events_delivered.load(Ordering::Relaxed), 1000);
        assert!(stats.publish_latency_ns.load(Ordering::Relaxed) > 0);
    }

    #[test]
    fn test_default() {
        let bus = EventBus::default();
        let mut rx = bus.subscribe();
        bus.publish(process_event()).unwrap();
        assert!(rx.try_recv().is_ok());
    }

    #[test]
    fn test_clone_shares_state() {
        let bus1 = EventBus::new();
        let bus2 = bus1.clone();
        let mut rx = bus1.subscribe();
        bus2.publish(process_event()).unwrap();
        assert!(rx.try_recv().is_ok());
        assert_eq!(bus1.subscriber_count(), 1);
    }

    #[test]
    fn test_concurrent_publish_subscribe() {
        let bus = EventBus::new();
        let mut rx = bus.subscribe();
        let count = 100_000usize;

        let bus_clone = bus.clone();
        let producer = thread::spawn(move || {
            for i in 0..count {
                let mut evt = ProcessInfo::default();
                evt.pid = i as u32;
                bus_clone.publish(SecurityEvent::Process(evt)).unwrap();
            }
        });

        let mut received = 0u64;
        let mut sum: u64 = 0;
        while received < count as u64 {
            match rx.try_recv() {
                Ok(SecurityEvent::Process(p)) => {
                    sum = sum.wrapping_add(p.pid as u64);
                    received += 1;
                }
                Ok(_) => unreachable!(),
                Err(TryRecvError::Empty) => std::thread::yield_now(),
                Err(TryRecvError::Lagged(_)) => continue,
            }
        }

        producer.join().unwrap();
        assert_eq!(received, count as u64);
    }

    #[test]
    fn test_subscriber_count_after_drop() {
        let bus = EventBus::new();
        assert_eq!(bus.subscriber_count(), 0);
        {
            let _rx1 = bus.subscribe();
            let _rx2 = bus.subscribe();
            assert_eq!(bus.subscriber_count(), 2);
        }
        assert_eq!(bus.subscriber_count(), 0);
    }

    #[test]
    fn test_rapid_publish_subscribe() {
        let bus = EventBus::new();
        let mut rx = bus.subscribe();

        for _ in 0..50_000 {
            bus.publish(process_event()).unwrap();
        }

        let mut count = 0;
        while rx.try_recv().is_ok() {
            count += 1;
        }
        assert_eq!(count, 50_000);
    }

    #[test]
    fn test_multi_threaded_broadcast() {
        let bus = EventBus::new();
        let num_consumers = 4;
        let num_events = 50_000usize;

        let mut handles = Vec::new();
        for _ in 0..num_consumers {
            let mut rx = bus.subscribe();
            handles.push(thread::spawn(move || {
                let mut count = 0;
                loop {
                    match rx.try_recv() {
                        Ok(_) => count += 1,
                        Err(TryRecvError::Empty) => {
                            if count >= num_events {
                                break;
                            }
                            std::thread::yield_now();
                        }
                        Err(TryRecvError::Lagged(_)) => continue,
                    }
                }
                count
            }));
        }

        for i in 0..num_events {
            let mut evt = ProcessInfo::default();
            evt.pid = i as u32;
            bus.publish(SecurityEvent::Process(evt)).unwrap();
        }

        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        for (i, count) in results.iter().enumerate() {
            assert!(
                *count <= num_events,
                "Consumer {} got {} events (expected <= {})",
                i,
                count,
                num_events
            );
        }
    }

    #[test]
    fn test_perf_throughput() {
        let bus = EventBus::new();
        let mut rx = bus.subscribe();
        let n = 100_000usize;

        let start = Instant::now();
        for _ in 0..n {
            bus.publish(process_event()).unwrap();
        }
        let pub_elapsed = start.elapsed();

        let start = Instant::now();
        let mut received = 0;
        while rx.try_recv().is_ok() {
            received += 1;
        }
        let recv_elapsed = start.elapsed();

        assert_eq!(received, n);

        let pub_rate = n as f64 / pub_elapsed.as_secs_f64();
        let recv_rate = n as f64 / recv_elapsed.as_secs_f64();

        eprintln!(
            "Throughput: publish={:.0} evt/s, recv={:.0} evt/s",
            pub_rate, recv_rate
        );
        assert!(pub_rate > 500_000.0, "Publish rate too low: {pub_rate}");
        assert!(recv_rate > 500_000.0, "Receive rate too low: {recv_rate}");
    }

    #[test]
    fn test_publish_batch() {
        let bus = EventBus::new();
        let mut rx = bus.subscribe();
        let events: Vec<_> = (0..10)
            .map(|i| {
                let mut evt = ProcessInfo::default();
                evt.pid = i;
                SecurityEvent::Process(evt)
            })
            .collect();
        let published = bus.publish_batch(events);
        assert_eq!(published, 10);
        for i in 0..10 {
            let received = rx.try_recv().unwrap();
            if let SecurityEvent::Process(ref p) = received {
                assert_eq!(p.pid, i);
            } else {
                panic!("Expected Process event");
            }
        }
    }

    #[test]
    fn test_publish_batch_empty() {
        let bus = EventBus::new();
        let published = bus.publish_batch(vec![]);
        assert_eq!(published, 0);
    }

    #[test]
    fn test_try_publish_ok() {
        let bus = EventBus::new();
        let mut rx = bus.subscribe();
        let result = bus.try_publish(process_event());
        assert!(result.is_ok());
        assert!(rx.try_recv().is_ok());
    }

    #[test]
    fn test_try_publish_backpressure() {
        let bus = EventBus::new();
        let _rx = bus.subscribe();
        assert!(!bus.has_backpressure());
        for _ in 0..(CAPACITY + 1) {
            let _ = bus.try_publish(process_event());
        }
        assert!(bus.has_backpressure());
        let result = bus.try_publish(process_event());
        assert!(result.is_err());
    }

    #[test]
    fn test_has_backpressure_initial() {
        let bus = EventBus::new();
        let _rx = bus.subscribe();
        assert!(!bus.has_backpressure());
    }

    #[test]
    fn test_has_backpressure_after_heavy_publish() {
        let bus = EventBus::new();
        let _rx = bus.subscribe();
        for _ in 0..(CAPACITY * 81 / 100 + 1) {
            bus.publish(process_event()).unwrap();
        }
        assert!(bus.has_backpressure());
    }

    #[test]
    fn test_publish_batch_large() {
        let bus = EventBus::new();
        let mut rx = bus.subscribe();
        let events: Vec<_> = (0..10_000)
            .map(|i| {
                let mut evt = ProcessInfo::default();
                evt.pid = i as u32;
                SecurityEvent::Process(evt)
            })
            .collect();
        let published = bus.publish_batch(events);
        assert_eq!(published, 10_000);
        let mut count = 0;
        while rx.try_recv().is_ok() {
            count += 1;
        }
        assert_eq!(count, 10_000);
    }
}
