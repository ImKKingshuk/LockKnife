use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

fn extract_entities(v: &serde_json::Value) -> Vec<String> {
    let keys = [
        "address", "number", "ssid", "package", "domain", "ip", "url", "sha256",
    ];
    let mut out = Vec::new();
    if let serde_json::Value::Object(map) = v {
        for k in keys {
            if let Some(val) = map.get(k) {
                if let Some(s) = val.as_str() {
                    let s = s.trim();
                    if !s.is_empty() {
                        out.push(s.to_string());
                    }
                }
            }
        }
    }
    out
}

fn extract_timestamps(v: &serde_json::Value) -> Vec<i64> {
    let keys = [
        "timestamp",
        "time",
        "date",
        "date_ms",
        "last_visit_time",
        "start_time",
        "end_time",
    ];
    let mut out = Vec::new();
    if let serde_json::Value::Object(map) = v {
        for k in keys {
            if let Some(val) = map.get(k) {
                match val {
                    serde_json::Value::Number(n) => {
                        if let Some(i) = n.as_i64() {
                            out.push(i);
                        }
                    }
                    serde_json::Value::String(s) => {
                        if let Ok(i) = s.trim().parse::<i64>() {
                            out.push(i);
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    out
}

#[derive(Default)]
struct EdgeInfo {
    count: u64,
    artifacts: BTreeSet<usize>,
    timestamps: Vec<i64>,
}

#[pyfunction]
pub fn correlate_artifacts_json(payloads: Vec<String>) -> PyResult<String> {
    let mut entity_set: BTreeSet<String> = BTreeSet::new();
    let mut edges: HashMap<(String, String), EdgeInfo> = HashMap::new();
    let mut artifact_entities: BTreeMap<usize, Vec<String>> = BTreeMap::new();

    for (idx, p) in payloads.iter().enumerate() {
        let v: serde_json::Value =
            serde_json::from_str(p).map_err(|e| PyValueError::new_err(e.to_string()))?;
        let list = match v {
            serde_json::Value::Array(a) => a,
            _ => vec![v],
        };
        let mut artifact_entities_local: HashSet<String> = HashSet::new();
        for item in list {
            let mut entities = extract_entities(&item);
            entities.sort();
            entities.dedup();
            for e in &entities {
                entity_set.insert(e.clone());
                artifact_entities_local.insert(e.clone());
            }
            let timestamps = extract_timestamps(&item);
            for i in 0..entities.len() {
                for j in i + 1..entities.len() {
                    let a = &entities[i];
                    let b = &entities[j];
                    let key = if a <= b {
                        (a.clone(), b.clone())
                    } else {
                        (b.clone(), a.clone())
                    };
                    let info = edges.entry(key).or_default();
                    info.count += 1;
                    info.artifacts.insert(idx);
                    info.timestamps.extend_from_slice(&timestamps);
                }
            }
        }
        let mut ent_list: Vec<String> = artifact_entities_local.into_iter().collect();
        ent_list.sort();
        artifact_entities.insert(idx, ent_list);
    }

    let entities: Vec<String> = entity_set.into_iter().collect();
    let mut edge_list = Vec::new();
    let mut adjacency: HashMap<String, Vec<String>> = HashMap::new();
    for ((a, b), info) in edges.into_iter() {
        if info.count == 0 {
            continue;
        }
        adjacency.entry(a.clone()).or_default().push(b.clone());
        adjacency.entry(b.clone()).or_default().push(a.clone());
        let score = info.count as f64;
        let time_span = if info.timestamps.is_empty() {
            None
        } else {
            let min = info.timestamps.iter().min().copied().unwrap_or(0);
            let max = info.timestamps.iter().max().copied().unwrap_or(0);
            Some(max - min)
        };
        edge_list.push(json!({
            "source": a,
            "target": b,
            "count": info.count,
            "score": score,
            "artifact_indexes": info.artifacts.into_iter().collect::<Vec<_>>(),
            "timestamps": info.timestamps,
            "time_span": time_span,
        }));
    }

    let mut clusters = Vec::new();
    let mut visited: HashSet<String> = HashSet::new();
    for ent in &entities {
        if visited.contains(ent) {
            continue;
        }
        let mut stack = vec![ent.clone()];
        let mut cluster = Vec::new();
        while let Some(cur) = stack.pop() {
            if visited.insert(cur.clone()) {
                cluster.push(cur.clone());
                if let Some(neigh) = adjacency.get(&cur) {
                    for n in neigh {
                        if !visited.contains(n) {
                            stack.push(n.clone());
                        }
                    }
                }
            }
        }
        cluster.sort();
        clusters.push(json!({"entities": cluster}));
    }

    let artifacts = artifact_entities
        .into_iter()
        .map(|(idx, ents)| json!({"index": idx, "entities": ents}))
        .collect::<Vec<_>>();

    let payload = json!({
        "entities": entities,
        "edges": edge_list,
        "clusters": clusters,
        "artifacts": artifacts,
    });
    Ok(serde_json::to_string(&payload).unwrap_or_else(|_| "{}".to_string()))
}

#[cfg(test)]
mod tests {
    use super::correlate_artifacts_json;
    use std::sync::Once;

    static INIT: Once = Once::new();

    fn init_python() {
        INIT.call_once(|| {
            pyo3::Python::initialize();
        });
    }

    #[test]
    fn test_correlate_builds_edges_and_clusters() {
        init_python();
        let out = correlate_artifacts_json(vec![
            r#"[{"number":"+1","ssid":"Home","timestamp":1}]"#.to_string(),
            r#"[{"number":"+1","package":"com.app","timestamp":2}]"#.to_string(),
        ])
        .unwrap();
        assert!(out.contains("edges"));
        assert!(out.contains("clusters"));
        assert!(out.contains("+1"));
    }

    #[test]
    fn test_correlate_empty_input() {
        init_python();
        let out = correlate_artifacts_json(vec![]).unwrap();
        assert!(out.contains("\"entities\":[]"));
    }

    #[test]
    fn test_correlate_malformed_json() {
        init_python();
        let err = correlate_artifacts_json(vec!["{".to_string()]).unwrap_err();
        assert!(!format!("{err}").is_empty());
    }
}
