pub mod advisory;
pub mod db;
pub mod feeds;
pub mod matcher;
pub mod version;
pub use advisory::{Advisory, Severity};
pub use db::VulnerabilityDb;
