#!/usr/bin/env bash
set -euo pipefail

cd /app

mkdir -p /app/src /app/bin /app/output

# Cargo manifest. No external dependencies; the implementation uses only the
# Rust standard library so the build does not need network access.
cat > /app/Cargo.toml <<'TOMLEOF'
[package]
name = "analyzer"
version = "0.1.0"
edition = "2021"

[[bin]]
name = "analyzer"
path = "src/main.rs"

[profile.release]
opt-level = 3
codegen-units = 1
lto = false
TOMLEOF

# Makefile drives the build and the run.
cat > /app/Makefile <<'MAKEEOF'
SHELL := /bin/bash

BIN_DIR := /app/bin
ANALYZER_BIN := $(BIN_DIR)/analyzer
OUT_DIR := /app/output
REPORT := $(OUT_DIR)/kmemleak_report.json

CARGO ?= cargo
CARGO_FLAGS ?= --release --manifest-path /app/Cargo.toml

.PHONY: all build run clean

all: build

build: $(BIN_DIR)
	$(CARGO) build $(CARGO_FLAGS)
	cp /app/target/release/analyzer $(ANALYZER_BIN)

run: build
	mkdir -p $(OUT_DIR)
	$(ANALYZER_BIN)

clean:
	rm -rf /app/target $(ANALYZER_BIN) $(REPORT)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)
MAKEEOF

# Drop in a single-file working analyzer over the stub.
cat > /app/src/main.rs <<'RUSTEOF'
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;

const LEAKS_PATH: &str = "/app/data/leaks.ndjson";
const MODULES_PATH: &str = "/app/data/modules.ndjson";
const KERNELS_PATH: &str = "/app/data/kernels.json";
const SUPPRESSIONS_PATH: &str = "/app/config/suppressions.yaml";
const REPORT_PATH: &str = "/app/output/kmemleak_report.json";

#[derive(Clone)]
enum J {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Arr(Vec<J>),
    Obj(Vec<(String, J)>),
}

struct P<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> P<'a> {
    fn new(s: &'a str) -> Self {
        P { b: s.as_bytes(), p: 0 }
    }
    fn ws(&mut self) {
        while self.p < self.b.len() {
            match self.b[self.p] {
                b' ' | b'\t' | b'\n' | b'\r' => self.p += 1,
                _ => return,
            }
        }
    }
    fn val(&mut self) -> J {
        self.ws();
        match self.b[self.p] {
            b'{' => self.obj(),
            b'[' => self.arr(),
            b'"' => J::Str(self.s()),
            b't' => {
                self.p += 4;
                J::Bool(true)
            }
            b'f' => {
                self.p += 5;
                J::Bool(false)
            }
            b'n' => {
                self.p += 4;
                J::Null
            }
            _ => self.num(),
        }
    }
    fn obj(&mut self) -> J {
        self.p += 1;
        let mut o = Vec::new();
        loop {
            self.ws();
            if self.b[self.p] == b'}' {
                self.p += 1;
                return J::Obj(o);
            }
            let k = self.s();
            self.ws();
            self.p += 1;
            let v = self.val();
            o.push((k, v));
            self.ws();
            if self.b[self.p] == b',' {
                self.p += 1;
            }
        }
    }
    fn arr(&mut self) -> J {
        self.p += 1;
        let mut o = Vec::new();
        loop {
            self.ws();
            if self.b[self.p] == b']' {
                self.p += 1;
                return J::Arr(o);
            }
            o.push(self.val());
            self.ws();
            if self.b[self.p] == b',' {
                self.p += 1;
            }
        }
    }
    fn s(&mut self) -> String {
        self.p += 1;
        let mut out = String::new();
        while self.b[self.p] != b'"' {
            if self.b[self.p] == b'\\' {
                self.p += 1;
                match self.b[self.p] {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'/' => out.push('/'),
                    b'n' => out.push('\n'),
                    b't' => out.push('\t'),
                    b'r' => out.push('\r'),
                    b'b' => out.push('\u{0008}'),
                    b'f' => out.push('\u{000C}'),
                    b'u' => {
                        let h = std::str::from_utf8(&self.b[self.p + 1..self.p + 5]).unwrap();
                        let cp = u32::from_str_radix(h, 16).unwrap_or(0);
                        out.push(char::from_u32(cp).unwrap_or('?'));
                        self.p += 4;
                    }
                    c => out.push(c as char),
                }
                self.p += 1;
            } else {
                let st = self.p;
                while self.p < self.b.len() && self.b[self.p] != b'"' && self.b[self.p] != b'\\' {
                    self.p += 1;
                }
                out.push_str(std::str::from_utf8(&self.b[st..self.p]).unwrap());
            }
        }
        self.p += 1;
        out
    }
    fn num(&mut self) -> J {
        let st = self.p;
        if self.b[self.p] == b'-' {
            self.p += 1;
        }
        let mut is_float = false;
        while self.p < self.b.len() {
            match self.b[self.p] {
                b'0'..=b'9' => self.p += 1,
                b'.' | b'e' | b'E' => {
                    is_float = true;
                    self.p += 1;
                }
                b'+' | b'-' => self.p += 1,
                _ => break,
            }
        }
        let s = std::str::from_utf8(&self.b[st..self.p]).unwrap();
        if is_float {
            J::Float(s.parse().unwrap_or(0.0))
        } else {
            J::Int(s.parse().unwrap_or(0))
        }
    }
}

fn parse_json(s: &str) -> J {
    P::new(s).val()
}

impl J {
    fn as_str(&self) -> &str {
        if let J::Str(s) = self { s } else { "" }
    }
    fn as_int(&self) -> i64 {
        match self {
            J::Int(i) => *i,
            J::Float(f) => *f as i64,
            _ => 0,
        }
    }
    fn as_float(&self) -> f64 {
        match self {
            J::Float(f) => *f,
            J::Int(i) => *i as f64,
            _ => 0.0,
        }
    }
    fn arr_ref(&self) -> &[J] {
        if let J::Arr(a) = self { a } else { &[] }
    }
    fn get(&self, k: &str) -> J {
        if let J::Obj(o) = self {
            for (kk, v) in o.iter() {
                if kk == k {
                    return v.clone();
                }
            }
        }
        J::Null
    }
    fn is_null(&self) -> bool {
        matches!(self, J::Null)
    }
}

struct Frame {
    addr: u64,
    symbol: String,
}

struct Leak {
    leak_id: String,
    size_bytes: i64,
    age_sec: f64,
    backtrace: Vec<Frame>,
}

struct Module {
    name: String,
    start: u64,
    end: u64,
    builtin: bool,
}

fn parse_hex(s: &str) -> u64 {
    let s = s.trim();
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    u64::from_str_radix(s, 16).unwrap_or(0)
}

fn load_leaks(path: &str) -> Vec<Leak> {
    let txt = fs::read_to_string(path).expect("read leaks");
    let mut out = Vec::new();
    for line in txt.lines() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        let v = parse_json(t);
        let bt: Vec<Frame> = v
            .get("backtrace")
            .arr_ref()
            .iter()
            .map(|f| Frame {
                addr: parse_hex(f.get("addr").as_str()),
                symbol: f.get("symbol").as_str().to_string(),
            })
            .collect();
        out.push(Leak {
            leak_id: v.get("leak_id").as_str().to_string(),
            size_bytes: v.get("size_bytes").as_int(),
            age_sec: v.get("age_sec").as_float(),
            backtrace: bt,
        });
    }
    out
}

fn load_modules(path: &str) -> Vec<Module> {
    let txt = fs::read_to_string(path).expect("read modules");
    let mut out = Vec::new();
    for line in txt.lines() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        let v = parse_json(t);
        out.push(Module {
            name: v.get("module_name").as_str().to_string(),
            start: parse_hex(v.get("text_start").as_str()),
            end: parse_hex(v.get("text_end").as_str()),
            builtin: matches!(v.get("builtin"), J::Bool(true)),
        });
    }
    out
}

fn load_kernel_info(path: &str) -> (String, i64) {
    let txt = fs::read_to_string(path).expect("read kernels");
    let v = parse_json(&txt);
    let a = v.get("kernels");
    let arr = a.arr_ref();
    if arr.is_empty() {
        return ("".into(), 0);
    }
    (
        arr[0].get("host").as_str().to_string(),
        arr[0].get("scan_ts").as_int(),
    )
}

fn load_suppressions(path: &str) -> (HashSet<String>, Vec<String>, f64, usize) {
    let txt = fs::read_to_string(path).expect("read suppressions");
    let mut frames = HashSet::new();
    let mut prefixes: Vec<String> = Vec::new();
    let mut min_age_sec = 0.0_f64;
    let mut max_backtrace_depth: usize = usize::MAX;
    let mut section = String::new();
    for line in txt.lines() {
        let raw = match line.find('#') {
            Some(i) => &line[..i],
            None => line,
        };
        let trimmed = raw.trim_end();
        if trimmed.trim().is_empty() {
            continue;
        }
        let indent = trimmed.len() - trimmed.trim_start().len();
        let t = trimmed.trim();
        if indent == 0 {
            if t.ends_with(':') {
                section = t.trim_end_matches(':').to_string();
            } else if let Some((k, v)) = t.split_once(':') {
                let key = k.trim();
                let value = v.trim();
                if key == "min_age_sec" {
                    min_age_sec = value.parse::<f64>().unwrap_or(0.0);
                } else if key == "max_backtrace_depth" {
                    max_backtrace_depth = value.parse::<usize>().unwrap_or(usize::MAX);
                }
                section.clear();
            }
        } else if t.starts_with("- ") {
            let item = t.trim_start_matches("- ").trim().to_string();
            if section == "allocator_frames" {
                frames.insert(item);
            } else if section == "suppressed_prefixes" {
                prefixes.push(item);
            }
        }
    }
    (frames, prefixes, min_age_sec, max_backtrace_depth)
}

fn is_suppressed(symbol: &str, frames: &HashSet<String>, prefixes: &[String]) -> bool {
    if frames.contains(symbol) {
        return true;
    }
    for p in prefixes {
        if symbol.starts_with(p.as_str()) {
            return true;
        }
    }
    false
}

fn module_for_addr(addr: u64, modules: &[Module]) -> Option<&Module> {
    modules.iter().find(|m| addr >= m.start && addr < m.end)
}

fn json_str_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn format_float(f: f64) -> String {
    if f.is_finite() && f.fract() == 0.0 {
        format!("{}.0", f as i64)
    } else {
        format!("{}", f)
    }
}

fn main() {
    let leaks = load_leaks(LEAKS_PATH);
    let modules = load_modules(MODULES_PATH);
    let (host, scan_ts) = load_kernel_info(KERNELS_PATH);
    let (suppressed, suppressed_prefixes, min_age_sec, max_depth) =
        load_suppressions(SUPPRESSIONS_PATH);
    let leaks: Vec<Leak> = leaks
        .into_iter()
        .filter(|l| l.age_sec >= min_age_sec)
        .map(|mut l| {
            if l.backtrace.len() > max_depth {
                l.backtrace.truncate(max_depth);
            }
            l
        })
        .collect();

    struct Classified {
        leak_id: String,
        size_bytes: i64,
        age_sec: f64,
        module: String,
        signature: String,
        top_frame: Option<String>,
    }

    let mut classified: Vec<Classified> = Vec::with_capacity(leaks.len());
    for l in &leaks {
        let top = l
            .backtrace
            .iter()
            .find(|f| !is_suppressed(&f.symbol, &suppressed, &suppressed_prefixes));
        let (module_name, top_frame) = match top {
            Some(f) => match module_for_addr(f.addr, &modules) {
                Some(m) => (m.name.clone(), Some(f.symbol.clone())),
                None => ("unattributable".to_string(), Some(f.symbol.clone())),
            },
            None => ("unattributable".to_string(), None),
        };
        let signature = l
            .backtrace
            .iter()
            .map(|f| f.symbol.as_str())
            .collect::<Vec<_>>()
            .join(";");
        classified.push(Classified {
            leak_id: l.leak_id.clone(),
            size_bytes: l.size_bytes,
            age_sec: l.age_sec,
            module: module_name,
            signature,
            top_frame,
        });
    }

    struct Group {
        module: String,
        signature: String,
        top_frame: Option<String>,
        leak_count: i64,
        total_bytes: i64,
        max_age_sec: f64,
        leak_ids: Vec<String>,
    }

    let mut groups_map: HashMap<String, Group> = HashMap::new();
    for c in &classified {
        let g = groups_map.entry(c.signature.clone()).or_insert(Group {
            module: c.module.clone(),
            signature: c.signature.clone(),
            top_frame: c.top_frame.clone(),
            leak_count: 0,
            total_bytes: 0,
            max_age_sec: 0.0,
            leak_ids: Vec::new(),
        });
        g.leak_count += 1;
        g.total_bytes += c.size_bytes;
        if c.age_sec > g.max_age_sec {
            g.max_age_sec = c.age_sec;
        }
        g.leak_ids.push(c.leak_id.clone());
    }

    for g in groups_map.values_mut() {
        g.leak_ids.sort();
    }

    let mut groups: Vec<Group> = groups_map.into_values().collect();
    groups.sort_by(|a, b| {
        b.total_bytes
            .cmp(&a.total_bytes)
            .then_with(|| a.module.cmp(&b.module))
            .then_with(|| a.signature.cmp(&b.signature))
    });

    let mut builtin_of: BTreeMap<String, bool> = BTreeMap::new();
    for m in &modules {
        builtin_of.insert(m.name.clone(), m.builtin);
    }
    builtin_of.insert("unattributable".to_string(), false);

    let mut module_leaks: BTreeMap<String, i64> = BTreeMap::new();
    let mut module_bytes: BTreeMap<String, i64> = BTreeMap::new();
    let mut module_sigs: BTreeMap<String, HashSet<String>> = BTreeMap::new();

    let mut total_bytes: i64 = 0;
    let mut total_leaks: i64 = 0;
    let mut unattributed_leaks: i64 = 0;
    let mut all_sigs: HashSet<String> = HashSet::new();

    for c in &classified {
        *module_leaks.entry(c.module.clone()).or_insert(0) += 1;
        *module_bytes.entry(c.module.clone()).or_insert(0) += c.size_bytes;
        module_sigs
            .entry(c.module.clone())
            .or_default()
            .insert(c.signature.clone());
        total_bytes += c.size_bytes;
        total_leaks += 1;
        if c.module == "unattributable" {
            unattributed_leaks += 1;
        }
        all_sigs.insert(c.signature.clone());
    }

    let unique_signatures: i64 = all_sigs.len() as i64;

    let mut buf = String::new();
    buf.push_str("{\n");
    buf.push_str("  \"summary\": {\n");
    buf.push_str(&format!("    \"host\": {},\n", json_str_escape(&host)));
    buf.push_str(&format!("    \"scan_ts\": {},\n", scan_ts));
    buf.push_str(&format!("    \"total_leaks\": {},\n", total_leaks));
    buf.push_str(&format!("    \"total_bytes\": {},\n", total_bytes));
    buf.push_str(&format!(
        "    \"unique_signatures\": {},\n",
        unique_signatures
    ));
    buf.push_str(&format!(
        "    \"unattributed_leaks\": {}\n",
        unattributed_leaks
    ));
    buf.push_str("  },\n");

    buf.push_str("  \"modules\": [\n");
    let mod_names: Vec<&String> = module_leaks.keys().collect();
    for (i, name) in mod_names.iter().enumerate() {
        let leaks = module_leaks.get(*name).copied().unwrap_or(0);
        let bytes = module_bytes.get(*name).copied().unwrap_or(0);
        let sigs = module_sigs.get(*name).map(|s| s.len()).unwrap_or(0) as i64;
        let builtin = *builtin_of.get(*name).unwrap_or(&false);
        buf.push_str(&format!(
            "    {{\"module_name\": {}, \"builtin\": {}, \"leaks\": {}, \"bytes\": {}, \"signatures\": {}}}{}\n",
            json_str_escape(name), builtin, leaks, bytes, sigs,
            if i + 1 == mod_names.len() { "" } else { "," }
        ));
    }
    buf.push_str("  ],\n");

    buf.push_str("  \"groups\": [\n");
    for (i, g) in groups.iter().enumerate() {
        let group_id = i + 1;
        let leak_ids_str = g
            .leak_ids
            .iter()
            .map(|s| json_str_escape(s))
            .collect::<Vec<_>>()
            .join(", ");
        let top_frame_json = match &g.top_frame {
            Some(s) => json_str_escape(s),
            None => "null".to_string(),
        };
        buf.push_str(&format!(
            "    {{\"group_id\": {}, \"module_name\": {}, \"signature\": {}, \"top_frame\": {}, \"leak_count\": {}, \"total_bytes\": {}, \"max_age_sec\": {}, \"leak_ids\": [{}]}}{}\n",
            group_id,
            json_str_escape(&g.module),
            json_str_escape(&g.signature),
            top_frame_json,
            g.leak_count,
            g.total_bytes,
            format_float(g.max_age_sec),
            leak_ids_str,
            if i + 1 == groups.len() { "" } else { "," }
        ));
    }
    buf.push_str("  ]\n");
    buf.push_str("}\n");

    fs::create_dir_all("/app/output").expect("mkdir output");
    fs::write(REPORT_PATH, buf).expect("write report");
}
RUSTEOF

make clean || true
make build
make run

wc -l /app/output/kmemleak_report.json
head -n 5 /app/output/kmemleak_report.json || true
