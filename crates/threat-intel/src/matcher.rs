use aho_corasick::AhoCorasick;
use crate::feed::{IocEntry, IocType};
use std::collections::HashMap;
use tracing::info;

pub struct IocMatcher {
    iocs: HashMap<String, IocEntry>,
    ac_matchers: HashMap<IocType, AhoCorasick>,
}

impl IocMatcher {
    pub fn new() -> Self {
        Self {
            iocs: HashMap::new(),
            ac_matchers: HashMap::new(),
        }
    }

    pub fn load_iocs(&mut self, iocs: Vec<IocEntry>) {
        let mut by_type: HashMap<IocType, Vec<String>> = HashMap::new();
        for ioc in iocs {
            by_type
                .entry(ioc.ioc_type.clone())
                .or_default()
                .push(ioc.value.clone());
            self.iocs.insert(ioc.value.clone(), ioc);
        }

        for (ioc_type, patterns) in &by_type {
            if !patterns.is_empty() {
                let ac = AhoCorasick::new(patterns)
                    .unwrap_or_else(|_| {
                        AhoCorasick::new(vec!["never-match-this-string-1234567890"])
                            .expect("fallback pattern must compile")
                    });
                self.ac_matchers.insert(ioc_type.clone(), ac);
            }
        }

        info!(count = self.iocs.len(), "Loaded IOCs into matcher");
    }

    pub fn check_value(&self, value: &str) -> Option<&IocEntry> {
        if let Some(ioc) = self.iocs.get(value) {
            return Some(ioc);
        }
        for (_ioc_type, ac) in &self.ac_matchers {
            if ac.find(value).is_some() {
                for ioc in self.iocs.values() {
                    if value.contains(ioc.value.as_str()) {
                        return Some(ioc);
                    }
                }
            }
        }
        None
    }

    pub fn check_batch<'a>(&self, values: &[&'a str]) -> Vec<(&'a str, &IocEntry)> {
        values
            .iter()
            .filter_map(|v| self.check_value(v).map(|ioc| (*v, ioc)))
            .collect()
    }

    pub fn ioc_count(&self) -> usize {
        self.iocs.len()
    }

    pub fn iocs_by_type(&self, ioc_type: &IocType) -> Vec<&IocEntry> {
        self.iocs
            .values()
            .filter(|ioc| &ioc.ioc_type == ioc_type)
            .collect()
    }
}
