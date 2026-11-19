use std::fs;

const REPORT_PATH: &str = "/app/output/kmemleak_report.json";

fn main() {
    let placeholder = "{\n  \"summary\": {},\n  \"modules\": [],\n  \"groups\": []\n}\n";
    fs::create_dir_all("/app/output").expect("mkdir output");
    fs::write(REPORT_PATH, placeholder).expect("write report");
}
