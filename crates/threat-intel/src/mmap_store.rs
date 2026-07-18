use crate::feed::IocEntry;

pub struct MmapIocStore {
    entries: Vec<IocEntry>,
}

impl MmapIocStore {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn bulk_insert(&mut self, mut entries: Vec<IocEntry>) {
        self.entries.append(&mut entries);
        self.entries
            .sort_by(|a, b| a.value.cmp(&b.value));
    }

    pub fn search_by_prefix(&self, prefix: &str) -> Vec<&IocEntry> {
        let pos = match self.entries.binary_search_by(|e| e.value.as_str().cmp(prefix)) {
            Ok(i) => i,
            Err(i) => i,
        };

        let mut results = Vec::new();
        for entry in &self.entries[pos..] {
            if entry.value.starts_with(prefix) {
                results.push(entry);
            } else {
                break;
            }
        }
        results
    }

    pub fn size_hint(&self) -> usize {
        let base = std::mem::size_of::<Self>();
        let entries: usize = self
            .entries
            .iter()
            .map(|e| {
                std::mem::size_of::<IocEntry>()
                    + e.value.len()
                    + e.severity.len()
                    + e.source.len()
                    + e.tags.iter().map(|t| t.len()).sum::<usize>()
            })
            .sum();
        base + entries
    }

    pub fn count(&self) -> usize {
        self.entries.len()
    }
}

impl Default for MmapIocStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feed::IocType;
    use chrono::Utc;

    fn make_entry(value: &str) -> IocEntry {
        IocEntry {
            value: value.into(),
            ioc_type: IocType::Domain,
            confidence: 0.8,
            severity: "high".into(),
            source: "test".into(),
            tags: vec!["malware".into()],
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            expiry: None,
        }
    }

    #[test]
    fn test_new_store_is_empty() {
        let store = MmapIocStore::new();
        assert_eq!(store.count(), 0);
    }

    #[test]
    fn test_bulk_insert_and_count() {
        let mut store = MmapIocStore::new();
        store.bulk_insert(vec![
            make_entry("zebra.com"),
            make_entry("alpha.com"),
            make_entry("middle.com"),
        ]);
        assert_eq!(store.count(), 3);
    }

    #[test]
    fn test_bulk_insert_sorts_entries() {
        let mut store = MmapIocStore::new();
        store.bulk_insert(vec![
            make_entry("z.com"),
            make_entry("a.com"),
            make_entry("m.com"),
        ]);
        assert_eq!(store.entries[0].value, "a.com");
        assert_eq!(store.entries[1].value, "m.com");
        assert_eq!(store.entries[2].value, "z.com");
    }

    #[test]
    fn test_search_by_prefix() {
        let mut store = MmapIocStore::new();
        store.bulk_insert(vec![
            make_entry("evil.com"),
            make_entry("evil.net"),
            make_entry("evil.org"),
            make_entry("good.com"),
            make_entry("malware.evil.com"),
        ]);

        let results = store.search_by_prefix("evil");
        assert_eq!(results.len(), 3);
        for r in &results {
            assert!(r.value.starts_with("evil"));
        }
    }

    #[test]
    fn test_search_by_prefix_no_match() {
        let mut store = MmapIocStore::new();
        store.bulk_insert(vec![make_entry("a.com"), make_entry("b.com")]);
        let results = store.search_by_prefix("zzz");
        assert!(results.is_empty());
    }

    #[test]
    fn test_search_by_prefix_exact_match() {
        let mut store = MmapIocStore::new();
        store.bulk_insert(vec![make_entry("evil.com")]);
        let results = store.search_by_prefix("evil.com");
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_search_empty_store() {
        let store = MmapIocStore::new();
        let results = store.search_by_prefix("any");
        assert!(results.is_empty());
    }

    #[test]
    fn test_size_hint_nonzero() {
        let mut store = MmapIocStore::new();
        store.bulk_insert(vec![make_entry("evil.com"), make_entry("good.net")]);
        let hint = store.size_hint();
        assert!(hint > std::mem::size_of::<MmapIocStore>());
    }

    #[test]
    fn test_size_hint_empty() {
        let store = MmapIocStore::new();
        let hint = store.size_hint();
        assert!(hint >= std::mem::size_of::<MmapIocStore>());
    }

    #[test]
    fn test_default_trait() {
        let store = MmapIocStore::default();
        assert_eq!(store.count(), 0);
    }
}
