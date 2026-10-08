pub mod advisory;
pub mod db;
pub mod feeds;
pub mod matcher;
pub mod version;
// scanner (PURL + version-range matching against advisories) is not implemented yet;
// see BEDROCK_SPEC.md Phase 2. The previous version-compare stub did a lexicographic
// string comparison, which is wrong for version numbers ("5.10" < "5.9") and worse
// than no check, so it was deleted rather than kept as dead code.

pub use advisory::{Advisory, Severity};
pub use db::VulnerabilityDb;
