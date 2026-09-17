use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn test_sbom_alpine_fixture() {
    let mut cmd = Command::cargo_bin("bedrock").unwrap();
    // The fixture is at root tests/fixtures/alpine-hello
    let fixture_path = "../../tests/fixtures/alpine-hello";
    cmd.arg("sbom").arg(fixture_path);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("musl"))
        .stdout(predicate::str::contains("SPDXRef-DOCUMENT"));
}
