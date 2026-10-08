//! `efivar-store` end-to-end contracts on a real formatted store image: the CLI
//! round-trips through the durable writer, the Boot Loader Interface one-shot
//! encoding is exact, and two concurrent writers both land.

use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

use efivar_store::{Guid, Layout, Store, StoreMut};

/// `4a67b082-0a4c-41cf-b6c7-440b29bb8c4f` in on-disk (mixed-endian) GUID order.
const GUID: Guid = [
    0x82, 0xb0, 0x67, 0x4a, 0x4c, 0x0a, 0xcf, 0x41, 0xb6, 0xc7, 0x44, 0x0b, 0x29, 0xbb, 0x8c, 0x4f,
];
const GUID_TEXT: &str = "4a67b082-0a4c-41cf-b6c7-440b29bb8c4f";
const ONESHOT_NAME: &str = "LoaderEntryOneShot";

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_efivar-store")
}

/// A fresh temp directory holding a 1 MiB authenticated store image.
fn scenario() -> (PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "efivar-store-cli-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let image = dir.join("efivar-store.img");
    let mut bytes = vec![0u8; 1 << 20];
    StoreMut::format(&mut bytes, Layout::Authenticated, 4096).expect("formatting the store");
    std::fs::write(&image, &bytes).expect("writing the store image");
    (dir, image)
}

fn run(args: &[&str]) -> Output {
    Command::new(binary())
        .args(args)
        .output()
        .expect("running efivar-store")
}

/// Asserts success and returns stdout.
fn ok(output: &Output) -> String {
    assert!(
        output.status.success(),
        "efivar-store failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn name(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}

#[test]
fn set_get_roundtrip_and_delete() {
    let (dir, image) = scenario();
    let image = image.to_str().expect("utf-8 path").to_owned();
    let data = dir.join("value.bin");
    std::fs::write(&data, b"entry-a").expect("writing the value file");
    let data = data.to_str().expect("utf-8 path").to_owned();

    let inspected = ok(&run(&["--image", image.as_str(), "inspect"]));
    assert!(inspected.contains("layout: authenticated"), "{inspected}");
    assert!(inspected.contains("live variables: 0"), "{inspected}");

    let written = ok(&run(&[
        "--image",
        image.as_str(),
        "set",
        "--name",
        "LoaderEntryDefault",
        "--guid",
        GUID_TEXT,
        "--attributes",
        "0x7",
        "--data-file",
        data.as_str(),
    ]));
    assert!(written.contains("written"), "{written}");

    // Read back through the CLI, which reads the backing store, not a cache.
    let got = ok(&run(&[
        "--image",
        image.as_str(),
        "get",
        "--name",
        "LoaderEntryDefault",
        "--guid",
        GUID_TEXT,
    ]));
    assert!(got.contains("attributes: 0x00000007"), "{got}");
    assert!(got.contains("data: 656e7472792d61"), "{got}");

    let listed = ok(&run(&["--image", image.as_str(), "list"]));
    assert!(listed.contains(GUID_TEXT), "{listed}");
    assert!(listed.contains("LoaderEntryDefault"), "{listed}");

    // The same value twice is a no-op, and the store still holds it.
    let again = ok(&run(&[
        "--image",
        image.as_str(),
        "set",
        "--name",
        "LoaderEntryDefault",
        "--guid",
        GUID_TEXT,
        "--attributes",
        "0x7",
        "--data-file",
        data.as_str(),
    ]));
    assert!(again.contains("unchanged"), "{again}");

    let removed = ok(&run(&[
        "--image",
        image.as_str(),
        "delete",
        "--name",
        "LoaderEntryDefault",
        "--guid",
        GUID_TEXT,
    ]));
    assert!(removed.contains("deleted"), "{removed}");

    let missing = run(&[
        "--image",
        image.as_str(),
        "get",
        "--name",
        "LoaderEntryDefault",
        "--guid",
        GUID_TEXT,
    ]);
    assert!(
        !missing.status.success(),
        "deleted value was still readable"
    );
    assert!(
        String::from_utf8_lossy(&missing.stderr).contains("EFI_NOT_FOUND"),
        "{}",
        String::from_utf8_lossy(&missing.stderr)
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn oneshot_uses_the_boot_loader_interface_encoding() {
    let (dir, image) = scenario();
    let image_path = image.to_str().expect("utf-8 path").to_owned();

    let written = ok(&run(&[
        "--image",
        image_path.as_str(),
        "oneshot",
        "entry-b",
    ]));
    assert!(written.contains("written"), "{written}");

    let bytes = std::fs::read(&image).expect("reading the store image");
    let store = Store::parse(&bytes).expect("parsing the store image");
    let variable = store
        .get(&name(ONESHOT_NAME), &GUID)
        .expect("the one-shot entry is stored");
    assert_eq!(variable.attributes, 0x7);
    let mut expected: Vec<u8> = "entry-b"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    expected.extend_from_slice(&[0, 0]);
    assert_eq!(variable.data, expected.as_slice());

    // `get --out` returns exactly those bytes.
    let out_file = dir.join("oneshot.bin");
    ok(&run(&[
        "--image",
        image_path.as_str(),
        "get",
        "--name",
        "LoaderEntryOneShot",
        "--guid",
        GUID_TEXT,
        "--out",
        out_file.to_str().expect("utf-8 path"),
    ]));
    assert_eq!(std::fs::read(&out_file).unwrap(), expected);

    let cleared = ok(&run(&[
        "--image",
        image_path.as_str(),
        "oneshot",
        "--clear",
    ]));
    assert!(cleared.contains("cleared"), "{cleared}");
    let bytes = std::fs::read(&image).expect("reading the store image");
    let store = Store::parse(&bytes).expect("parsing the store image");
    assert!(store.get(&name(ONESHOT_NAME), &GUID).is_none());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rejected_change_reports_a_clear_error_and_writes_nothing() {
    let (dir, image) = scenario();
    let image_path = image.to_str().expect("utf-8 path").to_owned();
    let before = std::fs::read(&image).expect("reading the store image");
    let data = dir.join("value.bin");
    std::fs::write(&data, b"value").expect("writing the value file");

    // Authenticated-write attributes are refused by the store format.
    let refused = run(&[
        "--image",
        image_path.as_str(),
        "set",
        "--name",
        "LoaderEntryDefault",
        "--guid",
        GUID_TEXT,
        "--attributes",
        "0x27",
        "--data-file",
        data.to_str().expect("utf-8 path"),
    ]);
    assert!(
        !refused.status.success(),
        "an authenticated write was accepted"
    );
    assert_eq!(std::fs::read(&image).unwrap(), before);

    // So is a GUID that is not a GUID.
    let bad_guid = run(&[
        "--image",
        image_path.as_str(),
        "get",
        "--name",
        "LoaderEntryDefault",
        "--guid",
        "not-a-guid",
    ]);
    assert!(!bad_guid.status.success());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn concurrent_writers_both_land() {
    let (dir, image) = scenario();
    let image_path = image.to_str().expect("utf-8 path").to_owned();
    let values: Vec<PathBuf> = ["a-value", "b-value"]
        .into_iter()
        .enumerate()
        .map(|(index, value)| {
            let path = dir.join(format!("value-{index}.bin"));
            std::fs::write(&path, value).expect("writing a value file");
            path
        })
        .collect();

    let children: Vec<_> = ["KeyA", "KeyB"]
        .into_iter()
        .zip(&values)
        .map(|(key, value)| {
            Command::new(binary())
                .args([
                    "--image",
                    image_path.as_str(),
                    "set",
                    "--name",
                    key,
                    "--guid",
                    GUID_TEXT,
                    "--attributes",
                    "0x7",
                    "--data-file",
                    value.to_str().expect("utf-8 path"),
                ])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawning efivar-store")
        })
        .collect();
    for child in children {
        let output = child.wait_with_output().expect("waiting for efivar-store");
        assert!(
            output.status.success(),
            "a concurrent writer failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let bytes = std::fs::read(&image).expect("reading the store image");
    let store = Store::parse(&bytes).expect("parsing the store image");
    assert_eq!(store.get(&name("KeyA"), &GUID).unwrap().data, b"a-value");
    assert_eq!(store.get(&name("KeyB"), &GUID).unwrap().data, b"b-value");

    let _ = std::fs::remove_dir_all(&dir);
}

/// The image format check the CLI reports must match the crate's own view.
#[test]
fn inspect_reports_the_true_free_space() {
    let (dir, image) = scenario();
    let image_path = image.to_str().expect("utf-8 path").to_owned();
    let bytes = std::fs::read(&image).unwrap();
    let free = Store::parse(&bytes).unwrap().free_space();
    let inspected = ok(&run(&["--image", image_path.as_str(), "inspect"]));
    assert!(
        inspected.contains(&format!("free space: {free} bytes")),
        "{inspected}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// `init` creates the image the other commands edit: one standalone NV FV, no FTW area, and it never
/// overwrites an existing image or formats a device.
#[test]
fn init_writes_a_standalone_store_image() {
    let dir = std::env::temp_dir().join(format!(
        "efivar-store-init-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let image = dir.join("fresh.img");
    let image_path = image.to_str().expect("utf-8 path").to_owned();

    let created = ok(&run(&[
        "--image",
        image_path.as_str(),
        "init",
        "--size",
        "262144",
        "--block",
        "4096",
        "--layout",
        "normal",
    ]));
    assert!(created.contains("initialised"), "{created}");

    let bytes = std::fs::read(&image).expect("reading the store image");
    assert_eq!(bytes.len(), 262144);
    let store = Store::parse(&bytes).expect("parsing the created image");
    assert_eq!(store.layout(), Layout::Normal);
    // Standalone FV: 72 byte volume header + 28 byte store header, nothing reserved.
    assert_eq!(store.capacity(), 262144 - 72 - 28);
    assert_eq!(store.free_space(), store.capacity());
    assert_eq!(store.list().count(), 0);

    let inspected = ok(&run(&["--image", image_path.as_str(), "inspect"]));
    assert!(inspected.contains("layout: normal"), "{inspected}");

    // An existing image is never replaced without --force.
    let refused = run(&["--image", image_path.as_str(), "init", "--size", "262144"]);
    assert!(!refused.status.success(), "init replaced an existing image");
    assert_eq!(std::fs::read(&image).unwrap(), bytes);

    ok(&run(&[
        "--image",
        image_path.as_str(),
        "init",
        "--size",
        "4096",
        "--force",
    ]));
    assert_eq!(std::fs::read(&image).unwrap().len(), 4096);

    // `init` formats an image file, never a device.
    let device = run(&["--device", image_path.as_str(), "init", "--size", "4096"]);
    assert!(!device.status.success(), "init accepted a --device");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn efvs_cli_roundtrip_compact_and_import() {
    let (dir, old) = scenario();
    let image = dir.join("efvs.img");
    let path = image.to_str().unwrap();
    ok(&run(&[
        "init", "--efvs", "--image", path, "--size", "1048576",
    ]));
    let inspect = ok(&run(&["--image", path, "inspect"]));
    assert!(inspect.contains("format: EFVS v1"));
    assert!(inspect.contains("tier: 0"));
    let mut damaged = std::fs::read(&image).unwrap();
    damaged[..4096].fill(0xa5);
    std::fs::write(&image, damaged).unwrap();
    assert!(ok(&run(&["--image", path, "inspect"])).contains("header offset: 4096"));
    let data = dir.join("data");
    std::fs::write(&data, b"first").unwrap();
    ok(&run(&[
        "--image",
        path,
        "set",
        "--name",
        "key",
        "--guid",
        GUID_TEXT,
        "--attributes",
        "7",
        "--data-file",
        data.to_str().unwrap(),
    ]));
    std::fs::write(&data, b"second").unwrap();
    ok(&run(&[
        "--image",
        path,
        "set",
        "--name",
        "key",
        "--guid",
        GUID_TEXT,
        "--attributes",
        "47",
        "--data-file",
        data.to_str().unwrap(),
    ]));
    let got = dir.join("got");
    ok(&run(&[
        "--image",
        path,
        "get",
        "--name",
        "key",
        "--guid",
        GUID_TEXT,
        "--out",
        got.to_str().unwrap(),
    ]));
    assert_eq!(std::fs::read(&got).unwrap(), b"firstsecond");
    assert!(ok(&run(&["--image", path, "list"])).contains("key"));
    ok(&run(&["--image", path, "compact"]));
    let once = std::fs::read(&image).unwrap();
    ok(&run(&["--image", path, "compact"]));
    assert_eq!(std::fs::read(&image).unwrap(), once);
    ok(&run(&[
        "--image", path, "delete", "--name", "key", "--guid", GUID_TEXT,
    ]));
    assert!(
        !run(&["--image", path, "get", "--name", "key", "--guid", GUID_TEXT])
            .status
            .success()
    );
    ok(&run(&["--image", path, "oneshot", "linux.conf"]));
    ok(&run(&["--image", path, "oneshot", "--clear"]));
    ok(&run(&[
        "import-edk2",
        "--from",
        old.to_str().unwrap(),
        "--image",
        path,
        "--size",
        "1048576",
        "--force",
    ]));
    assert!(ok(&run(&["--image", path, "inspect"])).contains("live variables: 0"));
    std::fs::remove_dir_all(dir).unwrap();
}
