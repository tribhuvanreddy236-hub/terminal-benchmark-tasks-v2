use crate::model::{JournalEvent, JournalKind, Manifest, Record, RecordKind, Segment, SegmentRef, Snapshot};
use std::fs;
use std::path::{Path, PathBuf};

fn valid_hex(value: &str) -> bool {
    value.len() % 2 == 0 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn lines(path: &Path) -> Result<Vec<String>, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !text.ends_with('\n') {
        return Err(format!("{}: missing final newline", path.display()));
    }
    let mut out = Vec::new();
    for (number, line) in text.lines().enumerate() {
        if line.is_empty() || line.trim() != line {
            return Err(format!("{}:{}: malformed whitespace", path.display(), number + 1));
        }
        out.push(line.to_string());
    }
    Ok(out)
}

fn number(value: &str, path: &Path, line: usize) -> Result<u64, String> {
    value
        .parse()
        .map_err(|_| format!("{}:{line}: invalid integer", path.display()))
}

pub fn load_manifest(path: PathBuf) -> Result<Manifest, String> {
    let source = lines(&path)?;
    if source.first().map(String::as_str) != Some("quarry-manifest-v2") || source.last().map(String::as_str) != Some("end") {
        return Err(format!("{}: invalid manifest envelope", path.display()));
    }
    let mut epoch = None;
    let mut checkpoint = None;
    let mut segments = Vec::new();
    let mut snapshots = Vec::new();
    let mut seal = None;
    for (index, line) in source[1..source.len() - 1].iter().enumerate() {
        let line_no = index + 2;
        let fields: Vec<_> = line.split(' ').collect();
        match fields.as_slice() {
            ["epoch", value] => epoch = Some(number(value, &path, line_no)?),
            ["checkpoint", value] => checkpoint = Some(number(value, &path, line_no)?),
            ["segment", id, generation, status, token] if *status == "active" || *status == "candidate" => {
                segments.push(SegmentRef { id: (*id).into(), generation: number(generation, &path, line_no)?, status: (*status).into(), seal: (*token).into() });
            }
            ["snapshot", name, sequence] => snapshots.push(Snapshot { name: (*name).into(), sequence: number(sequence, &path, line_no)? }),
            ["seal", token] => seal = Some((*token).into()),
            _ => return Err(format!("{}:{line_no}: unknown manifest record", path.display())),
        }
    }
    Ok(Manifest {
        epoch: epoch.ok_or_else(|| format!("{}: epoch missing", path.display()))?,
        checkpoint: checkpoint.ok_or_else(|| format!("{}: checkpoint missing", path.display()))?,
        segments,
        snapshots,
        seal: seal.ok_or_else(|| format!("{}: seal missing", path.display()))?,
    })
}

pub fn load_manifests(store: &Path) -> Result<Vec<Manifest>, String> {
    let directory = store.join("manifests");
    let mut paths = fs::read_dir(&directory)
        .map_err(|e| format!("{}: {e}", directory.display()))?
        .map(|entry| entry.map(|e| e.path()).map_err(|e| e.to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    paths.retain(|path| path.extension().and_then(|v| v.to_str()) == Some("qmf"));
    paths.sort();
    paths.into_iter().map(load_manifest).collect()
}

pub fn load_journal(store: &Path) -> Result<Vec<JournalEvent>, String> {
    let path = store.join("journal.log");
    let source = lines(&path)?;
    if source.first().map(String::as_str) != Some("quarry-journal-v1") || source.last().map(String::as_str) != Some("end") {
        return Err(format!("{}: invalid journal envelope", path.display()));
    }
    let mut events = Vec::new();
    for (index, line) in source[1..source.len() - 1].iter().enumerate() {
        let line_no = index + 2;
        let fields: Vec<_> = line.split(' ').collect();
        let (epoch, kind) = match fields.as_slice() {
            ["prepare", epoch, seal] => (number(epoch, &path, line_no)?, JournalKind::Prepare((*seal).into())),
            ["sync", epoch, domain] if *domain == "metadata" || *domain == "segments" => (number(epoch, &path, line_no)?, JournalKind::Sync((*domain).into())),
            ["activate", epoch, seal] => (number(epoch, &path, line_no)?, JournalKind::Activate((*seal).into())),
            _ => return Err(format!("{}:{line_no}: unknown journal record", path.display())),
        };
        events.push(JournalEvent { epoch, kind });
    }
    Ok(events)
}

pub fn load_segment(path: &Path) -> Result<Segment, String> {
    let source = lines(path)?;
    if source.first().map(String::as_str) != Some("quarry-segment-v2") || source.last().map(String::as_str) != Some("end") {
        return Err(format!("{}: invalid segment envelope", path.display()));
    }
    let mut id = None;
    let mut generation = None;
    let mut seal = None;
    let mut raw = Vec::new();
    for (index, line) in source[1..source.len() - 1].iter().enumerate() {
        let line_no = index + 2;
        let fields: Vec<_> = line.split(' ').collect();
        match fields.as_slice() {
            ["id", value] => id = Some((*value).into()),
            ["generation", value] => generation = Some(number(value, path, line_no)?),
            ["put", seq, key, value] if valid_hex(value) => raw.push((number(seq, path, line_no)?, RecordKind::Put { key: (*key).into(), value: (*value).into() })),
            ["del", seq, key] => raw.push((number(seq, path, line_no)?, RecordKind::Delete { key: (*key).into() })),
            ["txput", txn, seq, key, value] if valid_hex(value) => raw.push((number(seq, path, line_no)?, RecordKind::TxPut { txn: (*txn).into(), key: (*key).into(), value: (*value).into() })),
            ["txdel", txn, seq, key] => raw.push((number(seq, path, line_no)?, RecordKind::TxDelete { txn: (*txn).into(), key: (*key).into() })),
            ["commit", txn, seq] => raw.push((number(seq, path, line_no)?, RecordKind::Commit { txn: (*txn).into() })),
            ["abort", txn, seq] => raw.push((number(seq, path, line_no)?, RecordKind::Abort { txn: (*txn).into() })),
            ["seal", token] => seal = Some((*token).into()),
            _ => return Err(format!("{}:{line_no}: unknown segment record", path.display())),
        }
    }
    let generation = generation.ok_or_else(|| format!("{}: generation missing", path.display()))?;
    let records = raw
        .into_iter()
        .enumerate()
        .map(|(ordinal, (sequence, kind))| Record { sequence, generation, ordinal, kind })
        .collect();
    Ok(Segment {
        id: id.ok_or_else(|| format!("{}: id missing", path.display()))?,
        generation,
        records,
        seal: seal.ok_or_else(|| format!("{}: seal missing", path.display()))?,
    })
}
