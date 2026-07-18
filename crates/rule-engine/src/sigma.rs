use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use tracing::info;
use yaml_rust2::YamlLoader;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigmaRule {
    pub title: String,
    pub id: Option<String>,
    pub status: Option<String>,
    pub description: Option<String>,
    pub references: Option<Vec<String>>,
    pub author: Option<String>,
    pub date: Option<String>,
    pub modified: Option<String>,
    pub tags: Option<Vec<String>>,
    pub logsource: Option<SigmaLogsource>,
    pub detection: SigmaDetection,
    pub falsepositives: Option<Vec<String>>,
    pub level: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigmaLogsource {
    pub category: Option<String>,
    pub product: Option<String>,
    pub service: Option<String>,
    pub definition: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigmaDetection {
    pub condition: String,
    #[serde(flatten)]
    pub keywords: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledSigmaRule {
    pub id: String,
    pub title: String,
    pub level: String,
    pub tags: Vec<String>,
    pub condition: String,
    pub patterns: Vec<SigmaPattern>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigmaPattern {
    pub field: String,
    pub value: String,
    pub operator: PatternOperator,
    pub negated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PatternOperator {
    Contains,
    StartsWith,
    EndsWith,
    Equals,
    Regex,
    Gt,
    Lt,
    Gte,
    Lte,
    Exists,
}

fn yaml_to_json(yaml: &yaml_rust2::Yaml) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
    match yaml {
        yaml_rust2::Yaml::Null => Ok(serde_json::Value::Null),
        yaml_rust2::Yaml::Boolean(b) => Ok(serde_json::Value::Bool(*b)),
        yaml_rust2::Yaml::Integer(i) => Ok(serde_json::Value::Number((*i).into())),
        yaml_rust2::Yaml::Real(r) => {
            if let Ok(f) = r.parse::<f64>() {
                Ok(serde_json::Value::Number(
                    serde_json::Number::from_f64(f).unwrap_or(serde_json::Number::from(0)),
                ))
            } else {
                Ok(serde_json::Value::String(r.clone()))
            }
        }
        yaml_rust2::Yaml::String(s) => Ok(serde_json::Value::String(s.clone())),
        yaml_rust2::Yaml::Array(arr) => {
            let mut json_arr = Vec::new();
            for item in arr {
                json_arr.push(yaml_to_json(item)?);
            }
            Ok(serde_json::Value::Array(json_arr))
        }
        yaml_rust2::Yaml::Hash(hash) => {
            let mut json_obj = serde_json::Map::new();
            for (k, v) in hash {
                if let Some(key) = k.as_str() {
                    json_obj.insert(key.to_string(), yaml_to_json(v)?);
                }
            }
            Ok(serde_json::Value::Object(json_obj))
        }
        _ => Ok(serde_json::Value::Null),
    }
}

impl SigmaRule {
    pub fn parse(yaml: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let docs = YamlLoader::load_from_str(yaml)?;
        let doc = docs.into_iter().next().ok_or("Empty YAML document")?;
        let json_value = yaml_to_json(&doc)?;
        let rule: SigmaRule = serde_json::from_value(json_value)?;
        Ok(rule)
    }

    pub fn parse_multi(yaml: &str) -> Result<Vec<Self>, Box<dyn std::error::Error + Send + Sync>> {
        let docs = YamlLoader::load_from_str(yaml)?;
        let mut rules = Vec::new();
        for doc in docs {
            let json_value = yaml_to_json(&doc)?;
            let rule: SigmaRule = serde_json::from_value(json_value)?;
            rules.push(rule);
        }
        Ok(rules)
    }

    pub fn compile(&self) -> Result<CompiledSigmaRule, Box<dyn std::error::Error + Send + Sync>> {
        let id = self
            .id
            .clone()
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let mut patterns = Vec::new();

        for (field, value) in &self.detection.keywords {
            if field == "condition" {
                continue;
            }
            let pattern = Self::parse_pattern(field, value)?;
            patterns.push(pattern);
        }

        info!(
            rule_id = %id,
            title = %self.title,
            pattern_count = patterns.len(),
            "Compiled Sigma rule"
        );

        Ok(CompiledSigmaRule {
            id,
            title: self.title.clone(),
            level: self.level.clone().unwrap_or_else(|| "medium".into()),
            tags: self.tags.clone().unwrap_or_default(),
            condition: self.detection.condition.clone(),
            patterns,
        })
    }

    fn parse_pattern(
        field: &str,
        value: &serde_json::Value,
    ) -> Result<SigmaPattern, Box<dyn std::error::Error + Send + Sync>> {
        let (field_name, operator, negated) = Self::parse_field_modifiers(field);
        let str_value = match value {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Number(n) => n.to_string(),
            serde_json::Value::Bool(b) => b.to_string(),
            _ => value.to_string(),
        };

        Ok(SigmaPattern {
            field: field_name,
            value: str_value,
            operator,
            negated,
        })
    }

    fn parse_field_modifiers(field: &str) -> (String, PatternOperator, bool) {
        let mut field_name = field.to_string();
        let mut operator = PatternOperator::Contains;
        let mut negated = false;

        if field_name.starts_with('!') {
            negated = true;
            field_name = field_name[1..].to_string();
        }

        let first_modifier;
        {
            let modifiers: Vec<&str> = field_name.split('|').collect();
            if modifiers.len() > 1 {
                first_modifier = Some(modifiers[0].to_string());
                for modifier in &modifiers[1..] {
                    match *modifier {
                        "contains" => operator = PatternOperator::Contains,
                        "startswith" => operator = PatternOperator::StartsWith,
                        "endswith" => operator = PatternOperator::EndsWith,
                        "equals" | "is" => operator = PatternOperator::Equals,
                        "regex" | "re" => operator = PatternOperator::Regex,
                        "gt" => operator = PatternOperator::Gt,
                        "lt" => operator = PatternOperator::Lt,
                        "gte" => operator = PatternOperator::Gte,
                        "lte" => operator = PatternOperator::Lte,
                        "exists" => operator = PatternOperator::Exists,
                        _ => {}
                    }
                }
            } else {
                first_modifier = None;
            }
        }
        if let Some(name) = first_modifier {
            field_name = name;
        }

        (field_name, operator, negated)
    }
}
