use crate::model::{JournalKind, Record, RecordKind, Recovered, View};
use crate::parse::{load_journal, load_manifests, load_segment};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

#[derive(Clone)]
struct Effective {
    sequence: u64,
    generation: u64,
    ordinal: usize,
    key: String,
    value: Option<String>,
}

fn durable_epochs(store: &Path) -> Result<HashSet<(u64, String)>, String> {
    #[derive(Default)]
    struct Cycle {
        seal: Option<String>,
        metadata: bool,
        segments: bool,
    }
    let mut cycles: HashMap<u64, Cycle> = HashMap::new();
    let mut durable = HashSet::new();
    for event in load_journal(store)? {
        match event.kind {
            JournalKind::Prepare(seal) => {
                cycles.insert(event.epoch, Cycle { seal: Some(seal), metadata: false, segments: false });
            }
            JournalKind::Sync(domain) => {
                if let Some(cycle) = cycles.get_mut(&event.epoch) {
                    if domain == "metadata" {
                        cycle.metadata = true;
                    } else {
                        cycle.segments = true;
                    }
                }
            }
            JournalKind::Activate(seal) => {
                if let Some(cycle) = cycles.get(&event.epoch) {
                    if cycle.metadata && cycle.segments && cycle.seal.as_deref() == Some(seal.as_str()) {
                        durable.insert((event.epoch, seal));
                    }
                }
            }
        }
    }
    Ok(durable)
}

fn effective_records(records: &[Record]) -> Result<Vec<Effective>, String> {
    let mut terminal: HashMap<String, Option<u64>> = HashMap::new();
    for record in records {
        match &record.kind {
            RecordKind::Commit { txn } => {
                if terminal.insert(txn.clone(), Some(record.sequence)).is_some() {
                    return Err(format!("transaction {txn} has multiple terminal records"));
                }
            }
            RecordKind::Abort { txn } => {
                if terminal.insert(txn.clone(), None).is_some() {
                    return Err(format!("transaction {txn} has multiple terminal records"));
                }
            }
            _ => {}
        }
    }

    let mut out = Vec::new();
    let mut prepared: HashMap<(String, String), Effective> = HashMap::new();
    for record in records {
        match &record.kind {
            RecordKind::Put { key, value } => out.push(Effective { sequence: record.sequence, generation: record.generation, ordinal: record.ordinal, key: key.clone(), value: Some(value.clone()) }),
            RecordKind::Delete { key } => out.push(Effective { sequence: record.sequence, generation: record.generation, ordinal: record.ordinal, key: key.clone(), value: None }),
            RecordKind::TxPut { txn, key, value } => {
                let candidate = Effective { sequence: record.sequence, generation: record.generation, ordinal: record.ordinal, key: key.clone(), value: Some(value.clone()) };
                let slot = prepared.entry((txn.clone(), key.clone())).or_insert_with(|| candidate.clone());
                if (candidate.sequence, candidate.ordinal) > (slot.sequence, slot.ordinal) {
                    *slot = candidate;
                }
            }
            RecordKind::TxDelete { txn, key } => {
                let candidate = Effective { sequence: record.sequence, generation: record.generation, ordinal: record.ordinal, key: key.clone(), value: None };
                let slot = prepared.entry((txn.clone(), key.clone())).or_insert_with(|| candidate.clone());
                if (candidate.sequence, candidate.ordinal) > (slot.sequence, slot.ordinal) {
                    *slot = candidate;
                }
            }
            RecordKind::Commit { .. } | RecordKind::Abort { .. } => {}
        }
    }
    for ((txn, _), mut operation) in prepared {
        if let Some(Some(commit_sequence)) = terminal.get(&txn) {
            operation.sequence = *commit_sequence;
            out.push(operation);
        }
    }
    Ok(out)
}

fn build_view(name: String, sequence: u64, operations: &[Effective]) -> View {
    let mut newest: BTreeMap<String, (u64, u64, usize, Option<String>)> = BTreeMap::new();
    for operation in operations.iter().filter(|record| record.sequence <= sequence) {
        let order = (operation.sequence, operation.generation, operation.ordinal);
        let replace = newest
            .get(&operation.key)
            .map(|current| order > (current.0, current.1, current.2))
            .unwrap_or(true);
        if replace {
            newest.insert(operation.key.clone(), (order.0, order.1, order.2, operation.value.clone()));
        }
    }
    let entries = newest
        .into_iter()
        .filter_map(|(key, (_, _, _, value))| value.map(|value| (key, value)))
        .collect();
    View { name, sequence, entries }
}

pub fn recover(store: &Path) -> Result<Recovered, String> {
    let durable = durable_epochs(store)?;
    let manifest = load_manifests(store)?
        .into_iter()
        .filter(|manifest| durable.contains(&(manifest.epoch, manifest.seal.clone())))
        .max_by_key(|manifest| manifest.epoch)
        .ok_or_else(|| "no durable manifest epoch".to_string())?;

    let mut records = Vec::new();
    let mut segment_ids = HashSet::new();
    for reference in manifest.segments.iter().filter(|segment| segment.status == "active") {
        if !segment_ids.insert(reference.id.clone()) {
            return Err(format!("manifest repeats segment {}", reference.id));
        }
        let path = store.join("segments").join(format!("{}.seg", reference.id));
        let segment = load_segment(&path)?;
        if segment.id != reference.id || segment.generation != reference.generation || segment.seal != reference.seal {
            return Err(format!("segment {} does not match its manifest record", reference.id));
        }
        for mut record in segment.records {
            record.ordinal = records.len();
            records.push(record);
        }
    }
    let operations = effective_records(&records)?;
    let mut views = Vec::new();
    for snapshot in &manifest.snapshots {
        if snapshot.sequence > manifest.checkpoint || snapshot.name == "current" {
            return Err(format!("invalid snapshot {}", snapshot.name));
        }
        views.push(build_view(snapshot.name.clone(), snapshot.sequence, &operations));
    }
    views.push(build_view("current".into(), manifest.checkpoint, &operations));
    Ok(Recovered { epoch: manifest.epoch, checkpoint: manifest.checkpoint, views })
}

pub fn render(recovered: &Recovered) -> String {
    let mut output = String::from("quarry-state-v1\n");
    output.push_str(&format!("epoch {}\ncheckpoint {}\n", recovered.epoch, recovered.checkpoint));
    for view in &recovered.views {
        output.push_str(&format!("view {} {}\n", view.name, view.sequence));
        for (key, value) in &view.entries {
            output.push_str(&format!("put {key} {value}\n"));
        }
        output.push_str("endview\n");
    }
    output.push_str("end\n");
    output
}
