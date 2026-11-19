#[derive(Clone, Debug)]
pub struct SegmentRef {
    pub id: String,
    pub generation: u64,
    pub status: String,
    pub seal: String,
}

#[derive(Clone, Debug)]
pub struct Snapshot {
    pub name: String,
    pub sequence: u64,
}

#[derive(Clone, Debug)]
pub struct Manifest {
    pub epoch: u64,
    pub checkpoint: u64,
    pub segments: Vec<SegmentRef>,
    pub snapshots: Vec<Snapshot>,
    pub seal: String,
}

#[derive(Clone, Debug)]
pub enum JournalKind {
    Prepare(String),
    Sync(String),
    Activate(String),
}

#[derive(Clone, Debug)]
pub struct JournalEvent {
    pub epoch: u64,
    pub kind: JournalKind,
}

#[derive(Clone, Debug)]
pub enum RecordKind {
    Put { key: String, value: String },
    Delete { key: String },
    TxPut { txn: String, key: String, value: String },
    TxDelete { txn: String, key: String },
    Commit { txn: String },
    Abort { txn: String },
}

#[derive(Clone, Debug)]
pub struct Record {
    pub sequence: u64,
    pub generation: u64,
    pub ordinal: usize,
    pub kind: RecordKind,
}

#[derive(Clone, Debug)]
pub struct Segment {
    pub id: String,
    pub generation: u64,
    pub records: Vec<Record>,
    pub seal: String,
}

#[derive(Clone, Debug)]
pub struct View {
    pub name: String,
    pub sequence: u64,
    pub entries: Vec<(String, String)>,
}

#[derive(Clone, Debug)]
pub struct Recovered {
    pub epoch: u64,
    pub checkpoint: u64,
    pub views: Vec<View>,
}
