//! `efivar-store` — inspect and update an edk2 NV variable store.
//!
//! Reads and writes always go to the named backing store (a partition, a block
//! device, or a store image file), never to an `efivarfs` snapshot. Mutations go
//! through [`efivar_store::persist::unix::Device::transaction`], which takes a
//! blocking `flock(LOCK_EX)`, reloads the store under that lock, writes the
//! ordered edk2 phases with an `fsync` after each, verifies the readback and
//! releases the lock. Nothing here reclaims a live store: a full store fails
//! and says so.
//!
//! `init` creates a standalone image from scratch. Creating a partition,
//! choosing its size and GUID and reserving FTW space stay with the consumer
//! (a provisioning tool, a firmware installer), never with this command.

mod efvs;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::fs;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;
use std::vec::Vec;

use efivar_store::persist::Outcome;
use efivar_store::persist::unix::Device;
use efivar_store::{Guid, Layout, Store, StoreMut, Variable};

const USAGE: &str = "\
efivar-store — inspect and update an edk2 NV variable store

usage:
  efivar-store init --image PATH --size BYTES [--efvs --checkpoint BYTES] [--block BYTES] [--layout normal|auth] [--force]
  efivar-store import-edk2 --from PATH --image PATH --size BYTES [--checkpoint BYTES] [--force]
  efivar-store --image PATH compact
  efivar-store (--device PATH | --image PATH) inspect
  efivar-store (--device PATH | --image PATH) list
  efivar-store (--device PATH | --image PATH) get --name N --guid G [--out FILE]
  efivar-store (--device PATH | --image PATH) set --name N --guid G --attributes HEX --data-file FILE
  efivar-store (--device PATH | --image PATH) delete --name N --guid G
  efivar-store (--device PATH | --image PATH) oneshot ENTRY-ID
  efivar-store (--device PATH | --image PATH) oneshot --clear
  efivar-store help

options:
  --device PATH      block device or partition holding the store (read-write)
  --image PATH       store image file; same format and same commands
  --size BYTES       `init`: image size, a multiple of --block
  --block BYTES      `init`: physical write unit for EFVS, erase block for edk2 (default 4096)
  --layout LAYOUT    `init`: normal or auth (default auth)
  --force            `init`: overwrite an existing image file
  --efvs             `init`: EFVS v1 live container (otherwise edk2 interop FV)
  --checkpoint BYTES EFVS capacity per checkpoint slot (default 131072; two slots)
  --from PATH        `import-edk2`: source edk2 image
  --name N           variable name; UTF-8 here, UTF-16LE on disk
  --guid G           EFI GUID in UUID text form, e.g. 4a67b082-0a4c-41cf-b6c7-440b29bb8c4f
  --attributes HEX   EFI attributes, e.g. 0x7 = NV|BS|RT; NV|BS are required
  --data-file FILE   raw little-endian value; an empty file deletes the key
  --out FILE         `get`: write the raw value instead of hex
  --clear            `oneshot`: delete LoaderEntryOneShot instead of setting it
  -h, --help         this text

commands:
  init      create a standalone NV variable FV image: no FTW area, no partition
  inspect   layout, size, free space and live variable count
  list      GUID, name, attributes and size of every live variable
  get       attributes and hex value of one variable, read from the backing store
  set       replace one variable through the durable phase sequence
  delete    delete one variable through the same sequence
  oneshot   set (or delete) the systemd Boot Loader Interface LoaderEntryOneShot

`init` writes a fresh image file and refuses to replace an existing one unless
`--force` is given; it never formats a `--device`.
`inspect`, `list` and `get` open the backing store read-only and take no lock.
`set`, `delete` and `oneshot` take the exclusive advisory lock and flush every
phase, so two cooperative writers cannot interleave.
";

/// The systemd Boot Loader Interface one-shot entry variable, on disk.
const ONESHOT_GUID: Guid = [
    0x82, 0xb0, 0x67, 0x4a, 0x4c, 0x0a, 0xcf, 0x41, 0xb6, 0xc7, 0x44, 0x0b, 0x29, 0xbb, 0x8c, 0x4f,
];
const ONESHOT_NAME: &str = "LoaderEntryOneShot";
/// NV | BS | RT, the attributes systemd writes.
const ONESHOT_ATTRIBUTES: u32 = 0x7;

/// Options that always take one value.
const OPTIONS: [&str; 12] = [
    "--device",
    "--image",
    "--size",
    "--block",
    "--layout",
    "--name",
    "--guid",
    "--attributes",
    "--data-file",
    "--out",
    "--checkpoint",
    "--from",
];
/// Flags that never take a value.
const SWITCHES: [&str; 5] = ["--force", "--clear", "--help", "-h", "--efvs"];

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    match parse(&argv).and_then(|args| run(&args)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(Failure::Usage(message)) => {
            eprintln!("efivar-store: {message}\n\n{USAGE}");
            ExitCode::from(2)
        }
        Err(Failure::Run(message)) => {
            eprintln!("efivar-store: error: {message}");
            ExitCode::FAILURE
        }
    }
}

enum Failure {
    Usage(String),
    Run(String),
}

/// Renders any error value as a one-line CLI failure.
fn fail(error: impl std::fmt::Display) -> Failure {
    Failure::Run(error.to_string())
}

fn parse(argv: &[String]) -> Result<Args, Failure> {
    let mut args = Args::default();
    let mut rest = argv.iter();
    while let Some(token) = rest.next() {
        if let Some(option) = OPTIONS.iter().find(|option| *option == token) {
            let value = rest
                .next()
                .ok_or_else(|| Failure::Usage(format!("{option} needs a value")))?;
            args.values.insert((*option).to_owned(), value.clone());
        } else if SWITCHES.contains(&token.as_str()) {
            args.switches.push(token.clone());
        } else if token.starts_with('-') {
            return Err(Failure::Usage(format!("unknown option `{token}`")));
        } else {
            args.positional.push(token.clone());
        }
    }
    Ok(args)
}

#[derive(Default)]
struct Args {
    positional: Vec<String>,
    values: HashMap<String, String>,
    switches: Vec<String>,
}

impl Args {
    fn value(&self, name: &str) -> Option<&str> {
        self.values.get(name).map(String::as_str)
    }

    fn has(&self, name: &str) -> bool {
        self.switches.iter().any(|switch| switch == name)
    }

    fn required(&self, name: &str) -> Result<&str, Failure> {
        self.value(name)
            .ok_or_else(|| Failure::Usage(format!("{name} is required")))
    }

    /// Exactly one backing store, from `--device` or `--image`.
    fn backing(&self) -> Result<PathBuf, Failure> {
        match (self.value("--device"), self.value("--image")) {
            (Some(path), None) | (None, Some(path)) => Ok(PathBuf::from(path)),
            (Some(_), Some(_)) => Err(Failure::Usage(
                "give either --device or --image, not both".to_owned(),
            )),
            (None, None) => Err(Failure::Usage(
                "give --device PATH or --image PATH".to_owned(),
            )),
        }
    }

    /// The command word, i.e. the first positional argument.
    fn command(&self) -> Result<&str, Failure> {
        match self.positional.first() {
            Some(command) => Ok(command.as_str()),
            None => Err(Failure::Usage("no command given".to_owned())),
        }
    }

    /// Positional operands after the command word.
    fn operands(&self) -> &[String] {
        self.positional.get(1..).unwrap_or_default()
    }

    /// The (name, GUID) key, requiring both options.
    fn key(&self) -> Result<(Vec<u16>, Guid), Failure> {
        let name = self
            .required("--name")?
            .encode_utf16()
            .collect::<Vec<u16>>();
        if name.is_empty() {
            return Err(Failure::Usage("--name must not be empty".to_owned()));
        }
        let guid = guid_from_text(self.required("--guid")?)?;
        Ok((name, guid))
    }

    /// The `--device`/`--image` path, opened read-write for a mutation.
    fn writable(&self) -> Result<Device, Failure> {
        Device::open(&self.backing()?).map_err(fail)
    }
}

fn run(args: &Args) -> Result<(), Failure> {
    let command = args.command()?;
    if args.has("--help") || args.has("-h") || command == "help" {
        println!("{USAGE}");
        return Ok(());
    }
    if command == "import-edk2" || (command == "init" && args.has("--efvs")) {
        return efvs::create(args);
    }
    if command != "init" && efvs::detect(args)? {
        return efvs::run(args);
    }
    match command {
        "init" => init(args),
        "inspect" => inspect(args),
        "list" => list(args),
        "get" => get(args),
        "set" => set(args),
        "delete" => delete(args),
        "oneshot" => oneshot(args),
        other => Err(Failure::Usage(format!("unknown command `{other}`"))),
    }
}

/// Creates a standalone store image: `--size` bytes, `--block`-aligned, in the
/// chosen layout. The image is one NV FV with no FTW area, no partition
/// identity and no mirror, exactly what [`StoreMut::format`] writes.
fn init(args: &Args) -> Result<(), Failure> {
    let path = match (args.value("--image"), args.value("--device")) {
        (Some(path), None) => PathBuf::from(path),
        (Some(_), Some(_)) => {
            return Err(Failure::Usage(
                "`init` creates an image file; give --image, not --device".to_owned(),
            ));
        }
        (None, _) => {
            return Err(Failure::Usage(
                "`init` needs --image PATH; this tool does not format a partition".to_owned(),
            ));
        }
    };
    if !args.operands().is_empty() {
        return Err(Failure::Usage(
            "`init` takes its geometry from options only".to_owned(),
        ));
    }
    let size: usize = args
        .required("--size")?
        .parse()
        .map_err(|_| Failure::Usage("`--size` must be a byte count".to_owned()))?;
    let block: u32 = match args.value("--block") {
        Some(text) => text
            .parse()
            .map_err(|_| Failure::Usage("`--block` must be a byte count".to_owned()))?,
        None => 4096,
    };
    let layout = match args.value("--layout") {
        Some("normal") => Layout::Normal,
        Some("auth") => Layout::Authenticated,
        Some(other) => {
            return Err(Failure::Usage(format!(
                "`--layout {other}`: expected `normal` or `auth`"
            )));
        }
        None => Layout::Authenticated,
    };
    let mut image = vec![0u8; size];
    StoreMut::format(&mut image, layout, block).map_err(|error| {
        Failure::Run(format!(
            "cannot format a {size} byte image with {block} byte blocks: {error}"
        ))
    })?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .create_new(!args.has("--force"))
        .truncate(true)
        .open(&path)
        .map_err(fail)?;
    file.write_all(&image).map_err(fail)?;
    file.sync_all().map_err(fail)?;
    println!(
        "initialised {}: {size} bytes, {block} byte blocks, {} layout",
        path.display(),
        layout_name(layout)
    );
    Ok(())
}

/// Reads the backing store and validates it without the advisory lock.
fn read_store<'a>(device: &'a mut Device) -> Result<(usize, Store<'a>), Failure> {
    device.load().map_err(fail)?;
    let len = device.image().len();
    let store = Store::parse(device.image()).map_err(fail)?;
    Ok((len, store))
}

fn inspect(args: &Args) -> Result<(), Failure> {
    let mut device = Device::open_read_only(&args.backing()?).map_err(fail)?;
    let (len, store) = read_store(&mut device)?;
    println!("layout: {}", layout_name(store.layout()));
    println!("size: {len} bytes");
    println!("free space: {} bytes", store.free_space());
    println!("live variables: {}", store.list().count());
    Ok(())
}

fn list(args: &Args) -> Result<(), Failure> {
    let mut device = Device::open_read_only(&args.backing()?).map_err(fail)?;
    let (_, store) = read_store(&mut device)?;
    let mut count = 0usize;
    for variable in store.list() {
        println!(
            "{}  {}  0x{:08x}  {} bytes",
            guid_text(&variable.guid),
            variable_name(&variable),
            variable.attributes,
            variable.data.len()
        );
        count += 1;
    }
    eprintln!("efivar-store: {count} live variable(s)");
    Ok(())
}

fn get(args: &Args) -> Result<(), Failure> {
    let (name, guid) = args.key()?;
    let mut device = Device::open_read_only(&args.backing()?).map_err(fail)?;
    let (_, store) = read_store(&mut device)?;
    let Some(variable) = store.get(&name, &guid) else {
        return Err(missing(&name, &guid));
    };
    match args.value("--out") {
        Some(path) => {
            fs::write(path, variable.data).map_err(fail)?;
            println!(
                "attributes: 0x{:08x}\nsize: {} bytes\nwrote: {path}",
                variable.attributes,
                variable.data.len()
            );
        }
        None => {
            println!(
                "attributes: 0x{:08x}\nsize: {} bytes\ndata: {}",
                variable.attributes,
                variable.data.len(),
                hex(variable.data)
            );
        }
    }
    Ok(())
}

fn set(args: &Args) -> Result<(), Failure> {
    let (name, guid) = args.key()?;
    let attributes = parse_attributes(args.required("--attributes")?)?;
    let data = fs::read(args.required("--data-file")?).map_err(fail)?;
    let mut device = args.writable()?;
    let outcome = device
        .transaction(|tx| tx.set(&name, &guid, attributes, &data))
        .map_err(fail)?;
    report(outcome, &name, &guid)
}

fn delete(args: &Args) -> Result<(), Failure> {
    let (name, guid) = args.key()?;
    let mut device = args.writable()?;
    let outcome = device
        .transaction(|tx| tx.delete(&name, &guid))
        .map_err(fail)?;
    match outcome {
        Outcome::Absent => Err(missing(&name, &guid)),
        _ => {
            println!("deleted `{}`", name_text(&name));
            Ok(())
        }
    }
}

fn oneshot(args: &Args) -> Result<(), Failure> {
    // The Boot Loader Interface name and GUID are fixed; only the value varies.
    let name = ONESHOT_NAME.encode_utf16().collect::<Vec<u16>>();
    let guid = ONESHOT_GUID;
    let mut device = args.writable()?;
    if args.has("--clear") {
        if !args.operands().is_empty() {
            return Err(Failure::Usage(
                "`oneshot --clear` takes no entry id".to_owned(),
            ));
        }
        let outcome = device
            .transaction(|tx| tx.delete(&name, &guid))
            .map_err(fail)?;
        return match outcome {
            Outcome::Absent => Err(missing(&name, &guid)),
            _ => {
                println!("cleared {ONESHOT_NAME}");
                Ok(())
            }
        };
    }
    let entry = match args.operands() {
        [entry] => entry,
        [] => {
            return Err(Failure::Usage(
                "`oneshot` needs an entry id or --clear".to_owned(),
            ));
        }
        _ => {
            return Err(Failure::Usage(
                "`oneshot` takes exactly one entry id".to_owned(),
            ));
        }
    };
    if entry.is_empty() {
        return Err(Failure::Usage("the entry id must not be empty".to_owned()));
    }
    // A Boot Loader Interface entry value is the entry id plus a UTF-16 NUL.
    let mut data = Vec::new();
    for unit in entry.encode_utf16().chain(std::iter::once(0)) {
        data.extend_from_slice(&unit.to_le_bytes());
    }
    let outcome = device
        .transaction(|tx| tx.set(&name, &guid, ONESHOT_ATTRIBUTES, &data))
        .map_err(fail)?;
    report(outcome, &name, &guid)
}

/// Prints the mutation outcome, mapping `Absent` to `EFI_NOT_FOUND`.
fn report(outcome: Outcome, name: &[u16], guid: &Guid) -> Result<(), Failure> {
    match outcome {
        Outcome::Written => println!("written `{}`", name_text(name)),
        Outcome::Unchanged => println!("unchanged `{}`", name_text(name)),
        Outcome::Deleted => println!("deleted `{}`", name_text(name)),
        Outcome::Absent => return Err(missing(name, guid)),
    }
    Ok(())
}

fn missing(name: &[u16], guid: &Guid) -> Failure {
    Failure::Run(format!(
        "no variable `{}` {{{}}} (EFI_NOT_FOUND)",
        name_text(name),
        guid_text(guid)
    ))
}

fn layout_name(layout: Layout) -> &'static str {
    match layout {
        Layout::Normal => "normal",
        Layout::Authenticated => "authenticated",
    }
}

fn name_text(name: &[u16]) -> String {
    String::from_utf16_lossy(name)
}

/// The on-disk UTF-16 name of a live variable, as text.
fn variable_name(variable: &Variable<'_>) -> String {
    name_text(&variable.name.units().collect::<Vec<u16>>())
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(out, "{byte:02x}").expect("writing a String");
    }
    out
}

/// Parses `0x7`, `07` or `7` as a hexadecimal attribute word.
fn parse_attributes(text: &str) -> Result<u32, Failure> {
    let digits = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .unwrap_or(text);
    if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Failure::Usage(format!(
            "`{text}` is not a hexadecimal attribute word"
        )));
    }
    u32::from_str_radix(digits, 16).map_err(|_| Failure::Usage(format!("`{text}` overflows u32")))
}

/// Parses a UUID in text order into an EFI GUID in on-disk (mixed-endian) order.
fn guid_from_text(text: &str) -> Result<Guid, Failure> {
    let digits: String = text.chars().filter(|c| *c != '-').collect();
    if digits.len() != 32 || !digits.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Failure::Usage(format!(
            "`{text}` is not a 32-digit hexadecimal GUID"
        )));
    }
    let mut raw = [0u8; 16];
    for (slot, pair) in raw.iter_mut().zip(digits.as_bytes().chunks(2)) {
        let pair = std::str::from_utf8(pair).expect("ascii digits");
        *slot = u8::from_str_radix(pair, 16).expect("validated hex digits");
    }
    let mut wire = [0u8; 16];
    wire[0] = raw[3];
    wire[1] = raw[2];
    wire[2] = raw[1];
    wire[3] = raw[0];
    wire[4] = raw[5];
    wire[5] = raw[4];
    wire[6] = raw[7];
    wire[7] = raw[6];
    wire[8..].copy_from_slice(&raw[8..]);
    Ok(wire)
}

/// Renders on-disk GUID bytes in canonical UUID text order.
fn guid_text(wire: &Guid) -> String {
    let data1 = u32::from_le_bytes(wire[0..4].try_into().expect("four bytes"));
    let data2 = u16::from_le_bytes(wire[4..6].try_into().expect("two bytes"));
    let data3 = u16::from_le_bytes(wire[6..8].try_into().expect("two bytes"));
    format!(
        "{data1:08x}-{data2:04x}-{data3:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        wire[8], wire[9], wire[10], wire[11], wire[12], wire[13], wire[14], wire[15]
    )
}
