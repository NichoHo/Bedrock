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
fn sbom_finds_apk_db_in_merged_usr_layout() {
    // Wolfi and Chainguard make /lib a symlink to usr/lib, so the database's
    // tar path is usr/lib/apk/db/installed.
    let dir = tempfile::tempdir().unwrap();
    let builder = LayoutBuilder::new(dir.path());
    let apk_db = b"P:glibc\nV:2.39-r5\nA:x86_64\n\n";
    let layer = builder.layer_with_symlinks(
        &[("usr/lib/apk/db/installed", apk_db), ("etc/os-release", b"ID=wolfi\n")],
        &[("lib", "usr/lib")],
    );
    builder.finish(&[layer]);

    Command::cargo_bin("bedrock")
        .unwrap()
        .arg("sbom")
        .arg(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("pkg:apk/wolfi/glibc@2.39-r5"));
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
fn sbom_reads_distro_through_os_release_symlink() {
    // Debian and Ubuntu ship /etc/os-release as a symlink to ../usr/lib/os-release.
    let dir = tempfile::tempdir().unwrap();
    let builder = LayoutBuilder::new(dir.path());
    let status =
        b"Package: apt\nStatus: install ok installed\nArchitecture: amd64\nVersion: 2.8.3\n\n";
    let os_release = b"ID=ubuntu\nVERSION_ID=\"24.04\"\n";
    let layer = builder.layer_with_symlinks(
        &[("var/lib/dpkg/status", status), ("usr/lib/os-release", os_release)],
        &[("etc/os-release", "../usr/lib/os-release")],
    );
    builder.finish(&[layer]);

    Command::cargo_bin("bedrock").unwrap().arg("sbom").arg(dir.path()).assert().success().stdout(
        predicate::str::contains("pkg:deb/ubuntu/apt@2.8.3?arch=amd64&distro=ubuntu-24.04"),
    );
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
    Command::cargo_bin("bedrock").unwrap().args(["slim", "whatever"]).assert().failure().code(4);
}

#[test]
fn inspect_refuses_an_image_built_for_another_platform() {
    let dir = tempfile::tempdir().unwrap();
    let builder = LayoutBuilder::new(dir.path());
    let layer = builder.layer(&[("etc/foo", b"data")]);
    builder.finish_with_config(&[layer], br#"{"os":"linux","architecture":"arm64"}"#);

    Command::cargo_bin("bedrock")
        .unwrap()
        .args(["inspect", "--platform", "linux/amd64"])
        .arg(dir.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("arm64"));
    Command::cargo_bin("bedrock")
        .unwrap()
        .args(["inspect", "--platform", "linux/arm64"])
        .arg(dir.path())
        .assert()
        .success();
}

#[test]
fn inspect_escapes_control_characters_in_setuid_paths() {
    let dir = tempfile::tempdir().unwrap();
    let builder = LayoutBuilder::new(dir.path());
    let layer = builder.layer_with_modes(&[("bin/evil\x1b[2J", b"x", 0o4755)]);
    builder.finish(&[layer]);

    Command::cargo_bin("bedrock")
        .unwrap()
        .arg("inspect")
        .arg(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("bin/evil\\u{1b}[2J"))
        .stdout(predicate::str::contains('\x1b').not());
}

#[test]
fn inspect_reads_a_docker_save_archive() {
    fn tar_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for (name, data) in entries {
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, name, *data).unwrap();
        }
        b.into_inner().unwrap()
    }
    let layer = tar_of(&[("etc/foo", b"data"), ("etc/bar", b"more")]);
    let manifest = br#"[{"Config":"cfg.json","RepoTags":["t:1"],"Layers":["l0/layer.tar"]}]"#;
    let image = tar_of(&[
        ("manifest.json", manifest),
        ("cfg.json", br#"{"os":"linux","architecture":"amd64"}"#),
        ("l0/layer.tar", &layer),
    ]);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("image.tar");
    std::fs::write(&path, image).unwrap();

    Command::cargo_bin("bedrock")
        .unwrap()
        .args(["inspect", "--platform", "linux/amd64"])
        .arg(&path)
        .assert()
        .success()
        .stdout(predicate::str::contains("Files: 2"));
}

/// A Debian 12 image with a vulnerable libssl3 (binary of source `openssl`),
/// a patched zlib, and a vulnerable PyPI package; plus a snapshot to scan it with.
fn scan_fixture() -> (tempfile::TempDir, tempfile::TempDir) {
    use bedrock::vuln::advisory::{Advisory, Affected, Range, Severity};
    let img = tempfile::tempdir().unwrap();
    let builder = LayoutBuilder::new(img.path());
    let status = b"Package: libssl3\nStatus: install ok installed\nArchitecture: amd64\nSource: openssl\nVersion: 3.0.9-1\n\n\
                   Package: zlib1g\nStatus: install ok installed\nArchitecture: amd64\nSource: zlib\nVersion: 1:1.2.13.dfsg-1+deb12u1\n\n";
    let metadata = b"Metadata-Version: 2.1\nName: requests\nVersion: 2.25.1\n";
    let layer = builder.layer(&[
        ("etc/os-release", b"ID=debian\nVERSION_ID=\"12\"\n"),
        ("var/lib/dpkg/status", status),
        ("usr/lib/python3.9/site-packages/requests-2.25.1.dist-info/METADATA", metadata),
    ]);
    builder.finish(&[layer]);

    let adv = |id: &str, sev, eco: &str, name: &str, fixed: &str| Advisory {
        id: id.into(),
        aliases: vec![],
        severity: Some(sev),
        cvss: None,
        affected: vec![Affected {
            ecosystem: eco.into(),
            name: name.into(),
            ranges: vec![Range::up_to(Some(fixed))],
            versions: vec![],
        }],
    };
    let db_dir = tempfile::tempdir().unwrap();
    let db = bedrock::vuln::VulnerabilityDb::at(db_dir.path().into()).unwrap();
    db.replace(vec![
        (
            "debian".into(),
            vec![
                adv("CVE-2024-0001", Severity::High, "Debian:12", "openssl", "3.0.11-1~deb12u2"),
                adv(
                    "CVE-2024-0002",
                    Severity::Critical,
                    "Debian:12",
                    "zlib",
                    "1:1.2.13.dfsg-1+deb12u1",
                ),
            ],
        ),
        (
            "osv-PyPI".into(),
            vec![adv("CVE-2024-0003", Severity::Low, "PyPI", "requests", "2.31.0")],
        ),
    ])
    .unwrap();
    (img, db_dir)
}

#[test]
fn scan_without_a_snapshot_exits_4() {
    let (img, _db) = scan_fixture();
    let empty = tempfile::tempdir().unwrap();
    Command::cargo_bin("bedrock")
        .unwrap()
        .env("BEDROCK_DB_DIR", empty.path())
        .arg("scan")
        .arg(img.path())
        .assert()
        .failure()
        .code(4)
        .stderr(predicate::str::contains("bedrock db update"));
}

#[test]
fn scan_reports_backport_aware_findings_and_gates_with_fail_on() {
    let (img, db) = scan_fixture();
    let run = |args: &[&str]| {
        Command::cargo_bin("bedrock")
            .unwrap()
            .env("BEDROCK_DB_DIR", db.path())
            .arg("scan")
            .arg(img.path())
            .args(args)
            .assert()
    };

    let out = run(&["--format", "json"]).success().get_output().stdout.clone();
    let report: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(report["schema_version"], "1");
    let ids: Vec<&str> =
        report["findings"].as_array().unwrap().iter().map(|f| f["id"].as_str().unwrap()).collect();
    // zlib carries the +deb12u1 backport, so CVE-2024-0002 must not appear.
    assert_eq!(ids, ["CVE-2024-0001", "CVE-2024-0003"]);
    assert_eq!(report["input"]["findings_by_severity"]["high"], 1);
    assert_eq!(report["findings"][0]["fixed_package"], "openssl");

    run(&["--fail-on", "high"]).failure().code(1);
    run(&["--fail-on", "critical"]).success();

    let out = run(&["--format", "sarif"]).success().get_output().stdout.clone();
    let sarif: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(sarif["version"], "2.1.0");
    assert_eq!(sarif["runs"][0]["results"].as_array().unwrap().len(), 2);
    assert_eq!(sarif["runs"][0]["results"][0]["level"], "error");
}

/// Traces a tiny image built from the host's own dash and libc, so the test
/// needs no network or registry. Skips where ptrace or user namespaces are
/// unavailable (exit 4), e.g. a locked-down CI container.
#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
#[test]
fn trace_records_opened_files_and_the_static_closure() {
    let host = |p: &str| std::fs::read(p).ok();
    let (Some(dash), Some(libc)) = (host("/bin/dash"), host("/lib/x86_64-linux-gnu/libc.so.6"))
    else {
        eprintln!("skipping: host lacks /bin/dash and x86-64 glibc");
        return;
    };
    let Some(ld) = host("/lib64/ld-linux-x86-64.so.2") else { return };
    let dir = tempfile::tempdir().unwrap();
    let builder = LayoutBuilder::new(dir.path());
    let layer = builder.layer_with_modes(&[
        ("bin/dash", &dash, 0o755),
        ("lib/x86_64-linux-gnu/libc.so.6", &libc, 0o755),
        ("lib64/ld-linux-x86-64.so.2", &ld, 0o755),
        ("etc/used.conf", b"echo from-config\n", 0o644),
        ("etc/unused.conf", b"never read\n", 0o644),
    ]);
    builder.finish_with_config(
        &[layer],
        br#"{"architecture":"amd64","os":"linux","config":{"Entrypoint":["/bin/dash","-c",". /etc/used.conf"]}}"#,
    );

    let out = Command::cargo_bin("bedrock")
        .unwrap()
        .args(["trace", "--workload-duration", "5s", "--platform", "linux/amd64"])
        .arg(dir.path())
        .output()
        .unwrap();
    if out.status.code() == Some(4) {
        eprintln!("skipping: {}", String::from_utf8_lossy(&out.stderr));
        return;
    }
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let reach: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let paths: Vec<&str> =
        reach["paths"].as_array().unwrap().iter().map(|p| p["path"].as_str().unwrap()).collect();
    let origin = |p: &str| {
        reach["paths"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["path"] == p)
            .map(|e| e["origin"].as_str().unwrap().to_string())
    };

    assert_eq!(origin("/etc/used.conf").as_deref(), Some("dynamic"));
    assert!(!paths.contains(&"/etc/unused.conf"), "{paths:?}");
    assert!(origin("/bin/dash").is_some());
    // The loader is named by PT_INTERP and libc by DT_NEEDED: found statically
    // even when the kernel, not the process, did the mapping.
    assert!(origin("/lib64/ld-linux-x86-64.so.2").is_some(), "{paths:?}");
    assert!(origin("/lib/x86_64-linux-gnu/libc.so.6").is_some(), "{paths:?}");
    assert_eq!(reach["workload"]["entrypoint_code"], 0);
    assert_eq!(reach["workload"]["stopped_by_bedrock"], false);
}

#[test]
fn trace_without_a_workload_is_a_usage_error() {
    Command::cargo_bin("bedrock")
        .unwrap()
        .args(["trace", "whatever"])
        .assert()
        .failure()
        .code(3)
        .stderr(predicate::str::contains("exactly one of --workload"));
}
