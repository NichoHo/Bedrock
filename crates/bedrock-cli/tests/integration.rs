mod support;

use assert_cmd::Command;
use predicates::prelude::*;
use support::LayoutBuilder;

#[test]
fn sbom_reports_real_apk_package_and_version() {
    let dir = tempfile::tempdir().unwrap();
    let builder = LayoutBuilder::new(dir.path());
    let apk_db = b"P:musl\nV:1.2.4-r2\nA:x86_64\n\n";
    let layer = builder.layer(&[("lib/apk/db/installed", apk_db)]);
    builder.finish(&[layer]);

    Command::cargo_bin("bedrock")
        .unwrap()
        .arg("sbom")
        .arg(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("musl"))
        .stdout(predicate::str::contains("1.2.4-r2"))
        .stdout(predicate::str::contains("SPDXRef-DOCUMENT"))
        .stdout(predicate::str::contains("pkg:apk/alpine/musl@1.2.4-r2"));
}

#[test]
fn sbom_reports_real_dpkg_and_python_packages() {
    let dir = tempfile::tempdir().unwrap();
    let builder = LayoutBuilder::new(dir.path());
    let status =
        b"Package: python3\nStatus: install ok installed\nArchitecture: amd64\nVersion: 3.9.2-3\n\n\
          Package: gone\nStatus: deinstall ok config-files\nArchitecture: amd64\nVersion: 1.0\n\n";
    let metadata = b"Metadata-Version: 2.1\nName: requests\nVersion: 2.25.1\n";
    let layer = builder.layer(&[
        ("var/lib/dpkg/status", status),
        ("usr/lib/python3.9/site-packages/requests-2.25.1.dist-info/METADATA", metadata),
    ]);
    builder.finish(&[layer]);

    Command::cargo_bin("bedrock")
        .unwrap()
        .arg("sbom")
        .arg(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("python3"))
        .stdout(predicate::str::contains("3.9.2-3"))
        .stdout(predicate::str::contains("requests"))
        // The real METADATA version, not the "unknown" placeholder the old
        // parser fell back to.
        .stdout(predicate::str::contains("2.25.1"))
        // The deinstalled "gone" package must not be reported as installed.
        .stdout(predicate::str::contains("gone").not());
}

#[test]
fn sbom_reports_real_node_package_version() {
    let dir = tempfile::tempdir().unwrap();
    let builder = LayoutBuilder::new(dir.path());
    let pkg_json = br#"{"name": "express", "version": "4.17.1"}"#;
    let layer = builder.layer(&[("usr/src/app/node_modules/express/package.json", pkg_json)]);
    builder.finish(&[layer]);

    Command::cargo_bin("bedrock")
        .unwrap()
        .arg("sbom")
        .arg(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("express"))
        .stdout(predicate::str::contains("pkg:npm/express@4.17.1"));
}

#[test]
fn inspect_reports_file_and_directory_breakdown() {
    let dir = tempfile::tempdir().unwrap();
    let builder = LayoutBuilder::new(dir.path());
    let layer = builder.layer(&[("etc/foo", b"data"), ("etc/bar", b"more data")]);
    builder.finish(&[layer]);

    Command::cargo_bin("bedrock")
        .unwrap()
        .arg("inspect")
        .arg(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("Files: 2"));
}

#[test]
fn inspect_rejects_directory_without_oci_layout_marker() {
    let dir = tempfile::tempdir().unwrap();
    // No LayoutBuilder used: an ordinary empty directory must not be mistaken
    // for an OCI layout.
    Command::cargo_bin("bedrock").unwrap().arg("inspect").arg(dir.path()).assert().failure();
}

#[test]
fn not_implemented_commands_exit_4() {
    Command::cargo_bin("bedrock").unwrap().args(["scan", "whatever"]).assert().failure().code(4);
}
