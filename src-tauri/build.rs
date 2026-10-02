use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

const REVIEWED_CORE_MANIFEST_SHA256: &str =
    "4d674ca38c1d3719764fbd3ed2dd73b492495d0b9ef0b5b06f88921366d6606f";

fn verify_embedded_core(core: &Path) {
    let manifest = fs::read(core.join("SOURCE-MANIFEST.sha256"))
        .expect("missing reviewed credential core manifest");
    assert_eq!(
        format!("{:x}", Sha256::digest(&manifest)),
        REVIEWED_CORE_MANIFEST_SHA256,
        "credential core manifest changed without review"
    );
    let mut listed = BTreeSet::new();
    for line in std::str::from_utf8(&manifest)
        .expect("invalid credential core manifest")
        .lines()
    {
        let (expected, relative) = line
            .split_once("  ")
            .expect("invalid credential core manifest record");
        assert!(
            relative == "helper-Info.plist"
                || (relative.starts_with("src/")
                    && relative.len() > 4
                    && !relative[4..].contains('/')),
            "invalid credential core source path"
        );
        assert!(
            listed.insert(relative.to_owned()),
            "duplicate credential core source"
        );
        let path = core.join(relative);
        let metadata = fs::symlink_metadata(&path).expect("missing credential core source");
        assert!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "credential core source is not a regular file"
        );
        let actual = format!(
            "{:x}",
            Sha256::digest(fs::read(path).expect("unreadable credential core source"))
        );
        assert_eq!(
            actual, expected,
            "credential core source changed without review"
        );
    }
    let observed: BTreeSet<String> = fs::read_dir(core.join("src"))
        .expect("missing credential core source directory")
        .map(|entry| {
            format!(
                "src/{}",
                entry
                    .expect("invalid credential core source")
                    .file_name()
                    .to_string_lossy()
            )
        })
        .chain(std::iter::once("helper-Info.plist".to_owned()))
        .collect();
    assert_eq!(listed, observed, "credential core source inventory changed");
    let gate = fs::read_to_string(core.join("src/execution_gate.h"))
        .expect("missing credential execution gate");
    assert!(
        gate.lines()
            .any(|line| line == "#define PRODUCT_EXECUTION_ALLOWED 1"),
        "reviewed credential execution gate must be enabled"
    );
    let pins =
        fs::read_to_string(core.join("src/pins.h")).expect("missing credential identity pins");
    for reviewed_pin in [
        "PRODUCT_MAIN_CERTIFICATE_PIN[32] = {0x80, 0xa6, 0xf7, 0x14, 0xa6, 0x6b, 0x97, 0x16, 0x01, 0x82, 0xb8, 0x8d, 0x30, 0x4b, 0x0a, 0x74, 0x61, 0x2f, 0xfc, 0x05, 0xb2, 0x26, 0x93, 0x63, 0x3f, 0x86, 0x6d, 0x38, 0x7d, 0x65, 0xdc, 0x9c}",
        "PRODUCT_HELPER_CERTIFICATE_PIN[32] = {0x80, 0xa6, 0xf7, 0x14, 0xa6, 0x6b, 0x97, 0x16, 0x01, 0x82, 0xb8, 0x8d, 0x30, 0x4b, 0x0a, 0x74, 0x61, 0x2f, 0xfc, 0x05, 0xb2, 0x26, 0x93, 0x63, 0x3f, 0x86, 0x6d, 0x38, 0x7d, 0x65, 0xdc, 0x9c}",
        "PRODUCT_HELPER_CDHASH_PIN[20] = {0x7a, 0x98, 0x9c, 0xe7, 0x09, 0x94, 0x3e, 0xac, 0x72, 0xb2, 0x07, 0x93, 0x53, 0xb4, 0x27, 0xac, 0xfb, 0xfd, 0xd6, 0x2a}",
        "PRODUCT_HELPER_CDHASH_PIN[20] = {0x25, 0xf1, 0x65, 0x90, 0xb8, 0xd5, 0xd6, 0x84, 0x7f, 0xb1, 0x27, 0x69, 0xe6, 0xdb, 0x09, 0x94, 0x34, 0xba, 0xb0, 0xf3}",
        "#if defined(__APPLE__) && defined(__aarch64__)",
        "#elif defined(__APPLE__) && defined(__x86_64__)",
        "#error Unsupported credential helper target architecture",
    ] {
        assert!(pins.contains(reviewed_pin), "credential identity pins changed without review");
    }
}

fn build_macos_credential_client() {
    let core = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("native/credential-core");
    verify_embedded_core(&core);
    println!("cargo:rerun-if-changed={}", core.display());
    let sources = core.join("src");
    let mut client = cc::Build::new();
    client
        .include(&sources)
        .std("c11")
        // C objects must not carry build-host source paths into release assets.
        .debug(false)
        .flag("-g0")
        .flag("-fblocks")
        .flag("-mmacosx-version-min=11.0")
        .flag("-Werror")
        .flag("-Wpedantic")
        .flag("-Wno-deprecated-declarations");
    for name in [
        "client.c",
        "credential_location.c",
        "identity.c",
        "policy.c",
        "entitlements.c",
        "credential_policy.c",
        "credential_protocol.c",
        "xpc_credential.c",
    ] {
        client.file(sources.join(name));
    }
    client.compile("slg_credential_client");
    println!("cargo:rustc-link-lib=framework=Security");
    println!("cargo:rustc-link-lib=framework=CoreFoundation");
}

fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let manifest =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("windows-app-manifest.xml");
        println!("cargo:rerun-if-changed=windows-app-manifest.xml");
        // Cargo's unqualified link argument also reaches the lib unit-test harness.
        println!("cargo:rustc-link-arg=/MANIFEST:EMBED");
        println!("cargo:rustc-link-arg=/MANIFESTINPUT:{}", manifest.display());
        println!("cargo:rustc-link-arg=/WX");

        // Tauri's default manifest is embedded by tauri-winres in binaries only.
        // The matching XML is linked above for both the app and its test executables.
        let attributes = tauri_build::Attributes::new()
            .windows_attributes(tauri_build::WindowsAttributes::new_without_app_manifest());
        tauri_build::try_build(attributes).expect("failed to run Tauri build script");
    } else {
        if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
            build_macos_credential_client();
        }
        tauri_build::build();
    }
}
