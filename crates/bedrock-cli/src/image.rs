//! Helpers shared by every command that analyses an image's contents.
use crate::fs::{FileInventory, SizeLimits};
use crate::oci::Manifest;
use crate::sbom::{self, Package};
use anyhow::{Context, Result};
use std::path::PathBuf;

/// Applies every layer of `manifest` in order, producing the merged file view.
pub fn build_inventory(
    manifest: &Manifest,
    blob_path: &dyn Fn(&str) -> Result<PathBuf>,
    limits: SizeLimits,
) -> Result<FileInventory> {
    let mut inventory = FileInventory::with_limits(limits);
    for layer in &manifest.layers {
        let path = blob_path(&layer.digest)?;
        inventory
            .apply_layer(&path, &layer.digest)
            .with_context(|| format!("failed to apply layer {}", layer.digest))?;
    }
    Ok(inventory)
}

/// Runs every SBOM parser we have over `inventory`, collecting whatever each
/// one finds. A parser failing (a malformed dpkg status file, say) is
/// reported on stderr and doesn't stop the others from running, but it is
/// always reported, never silently dropped.
pub fn parse_all_packages(
    inventory: &FileInventory,
    resolver: impl Fn(&str) -> Option<PathBuf> + Copy,
) -> Vec<Package> {
    type Parser<F> = fn(&FileInventory, F) -> Result<Vec<Package>>;
    let parsers: [(&str, Parser<_>); 6] = [
        ("dpkg database", sbom::dpkg::parse_dpkg),
        ("apk database", sbom::apk::parse_apk),
        ("rpm database", sbom::rpm::parse_rpm),
        ("node_modules", sbom::node::parse_node),
        ("Python packages", sbom::python::parse_python),
        ("Go and Rust binaries", sbom::binaries::parse_binaries),
    ];
    let mut packages = Vec::new();
    for (what, parse) in parsers {
        match parse(inventory, resolver) {
            Ok(found) => packages.extend(found),
            // {:#} prints the whole context chain on one line.
            Err(e) => eprintln!(
                "Warning: failed to parse {what}: {}",
                crate::escape_control(&format!("{e:#}"))
            ),
        }
    }
    packages
}
