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
    Command::cargo_bin("bedrock").unwrap().args(["scan", "whatever"]).assert().failure().code(4);
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
