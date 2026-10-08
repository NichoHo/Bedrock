//! Property tests on the package database parsers (BEDROCK_SPEC.md Phase 1).
//! Round trips check that what a parser reads back is what was written;
//! the arbitrary-bytes cases check that hostile input is an error, never a
//! panic. The fuzz targets in `fuzz/` cover the second kind more deeply, but
//! need nightly; these run on every `cargo test`.
use bedrock::sbom::{apk, dpkg, rpm, OsRelease};
use proptest::prelude::*;

/// (name, version, arch) triples shaped like real package metadata.
fn packages() -> impl Strategy<Value = Vec<(String, String, String)>> {
    prop::collection::vec(
        (
            "[a-z0-9][a-z0-9+.-]{0,20}",
            "[0-9]{1,3}(\\.[0-9]{1,3}){0,2}-r?[0-9]{1,2}",
            "(amd64|arm64|all)",
        ),
        0..20,
    )
}

proptest! {
    #[test]
    fn dpkg_status_round_trips(pkgs in packages()) {
        let text: String = pkgs
            .iter()
            .map(|(n, v, a)| {
                format!("Package: {n}\nStatus: install ok installed\nVersion: {v}\nArchitecture: {a}\nDescription: x\n continuation: line\n\n")
            })
            .collect();
        let parsed = dpkg::parse_status(&text, "debian", None);
        let got: Vec<_> = parsed
            .iter()
            .map(|p| (p.name.clone(), p.version.clone(), p.architecture.clone().unwrap()))
            .collect();
        prop_assert_eq!(got, pkgs);
    }

    #[test]
    fn apk_db_round_trips(pkgs in packages()) {
        let text: String =
            pkgs.iter().map(|(n, v, a)| format!("P:{n}\nV:{v}\nA:{a}\nF:usr/bin\nR:{n}\n\n")).collect();
        let parsed = apk::parse_status(&text, "alpine", None);
        prop_assert_eq!(parsed.len(), pkgs.len());
        for (p, (n, v, _)) in parsed.iter().zip(&pkgs) {
            prop_assert_eq!(&p.name, n);
            prop_assert_eq!(&p.version, v);
            prop_assert_eq!(p.files[0].to_str().unwrap(), format!("usr/bin/{n}"));
        }
    }

    #[test]
    fn text_parsers_never_panic(text in "(?s).{0,2000}") {
        let _ = dpkg::parse_status(&text, "debian", None);
        let _ = apk::parse_status(&text, "alpine", None);
    }

    #[test]
    fn rpm_ndb_garbage_is_an_error_not_a_panic(tail in prop::collection::vec(any::<u8>(), 0..10_000)) {
        let mut db = b"RpmP".to_vec();
        db.extend(tail);
        let _ = rpm::parse_db(&db, None, &OsRelease::default());
    }

    #[test]
    fn rpm_bdb_garbage_is_an_error_not_a_panic(
        mut db in prop::collection::vec(any::<u8>(), 64..20_000),
        page_size in prop::sample::select(vec![512u32, 1024, 4096]),
    ) {
        // Valid magic and page size so parsing gets past the metadata check
        // into the page walk, where the interesting bounds checks are.
        db[12..16].copy_from_slice(&0x061561u32.to_le_bytes());
        db[20..24].copy_from_slice(&page_size.to_le_bytes());
        db[24] = 0;
        let _ = rpm::parse_db(&db, None, &OsRelease::default());
    }
}
