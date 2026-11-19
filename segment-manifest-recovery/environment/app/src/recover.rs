use crate::model::Recovered;
use std::path::Path;

pub fn recover(_store: &Path) -> Result<Recovered, String> {
    Err("the recovery planner is absent from this checkout".into())
}

pub fn render(_recovered: &Recovered) -> String {
    String::new()
}
