//! The committed JSON Schema must match the report model. Changing the model
//! therefore shows up in review; regenerate with
//! `UPDATE_SCHEMA=1 cargo test --test schema`.

use std::path::Path;

#[test]
fn committed_schema_is_current() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/schema/whiff-1.schema.json");
    let generated = serde_json::to_string_pretty(&schemars::schema_for!(whiff::Report)).unwrap() + "\n";
    if std::env::var_os("UPDATE_SCHEMA").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &generated).unwrap();
        return;
    }
    let committed = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        committed == generated,
        "docs/schema/whiff-1.schema.json is out of date; run `UPDATE_SCHEMA=1 cargo test --test schema` \
         and check the change is additive (renames/removals need schema whiff/2)"
    );
}
