mod model;
mod parse;
mod recover;

use std::env;
use std::fs;
use std::path::Path;

fn usage() -> ! {
    eprintln!("usage: qrecover recover <store-dir> <output-file>");
    std::process::exit(2);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 || args[1] != "recover" {
        usage();
    }
    let recovered = recover::recover(Path::new(&args[2])).unwrap_or_else(|message| {
        eprintln!("qrecover: {message}");
        std::process::exit(1);
    });
    let rendered = recover::render(&recovered);
    let destination = Path::new(&args[3]);
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).unwrap_or_else(|e| {
            eprintln!("qrecover: {}: {e}", parent.display());
            std::process::exit(1);
        });
    }
    fs::write(destination, rendered).unwrap_or_else(|e| {
        eprintln!("qrecover: {}: {e}", destination.display());
        std::process::exit(1);
    });
    println!("recovered epoch {} through sequence {}", recovered.epoch, recovered.checkpoint);
}
