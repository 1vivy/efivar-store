use super::{
    Args, Failure, ONESHOT_GUID, ONESHOT_NAME, fail, guid_text, hex, missing, parse_attributes,
};
use efivar_store::efvs::*;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::FileExt;
fn number(args: &Args, key: &str, default: Option<usize>) -> Result<usize, Failure> {
    match args.value(key) {
        Some(s) => s
            .parse()
            .map_err(|_| Failure::Usage(format!("{key} must be a byte count"))),
        None => default.ok_or_else(|| Failure::Usage(format!("{key} is required"))),
    }
}
pub fn detect(args: &Args) -> Result<bool, Failure> {
    let mut f = File::open(args.backing()?).map_err(fail)?;
    let mut magic = [0; 4];
    f.read_exact(&mut magic).map_err(fail)?;
    Ok(magic == *b"EFVS")
}
pub fn create(args: &Args) -> Result<(), Failure> {
    if args.value("--device").is_some() {
        return Err(Failure::Usage("EFVS creation only supports --image".into()));
    }
    let path = args.required("--image")?;
    let size = number(args, "--size", None)?;
    let capacity = number(args, "--checkpoint", Some(PHONE_CHECKPOINT_CAPACITY))?;
    let mut image = vec![0; size];
    if args.command()? == "import-edk2" {
        let source = std::fs::read(args.required("--from")?).map_err(fail)?;
        let mut scratch = vec![0; capacity];
        let count = efivar_store::migrate::import_edk2(&source, &mut image, capacity, &mut scratch)
            .map_err(fail)?;
        println!("imported {count} variables (policy filtering occurs at replay)");
    } else {
        initialize(&mut image, capacity).map_err(fail)?;
    }
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false) // Resize only after acquiring the cooperative-writer lock.
        .create_new(!args.has("--force"))
        .open(path)
        .map_err(fail)?;
    file.lock().map_err(fail)?;
    file.set_len(size as u64).map_err(fail)?;
    file.write_all_at(&image, 0).map_err(fail)?;
    file.sync_all().map_err(fail)?;
    println!(
        "initialised {path}: {size} bytes, EFVS v1, checkpoint {capacity}, tier 0, SecureBoot=0"
    );
    Ok(())
}
fn wire_name(name: &[u16]) -> Vec<u8> {
    name.iter().flat_map(|u| u.to_le_bytes()).collect()
}
fn text(name: &[u8]) -> String {
    String::from_utf16_lossy(
        &name
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| u16::from_le_bytes(*b))
            .collect::<Vec<_>>(),
    )
}
pub fn run(args: &Args) -> Result<(), Failure> {
    let command = args.command()?;
    let mutation = matches!(command, "set" | "delete" | "oneshot" | "compact");
    if command == "compact" && args.value("--device").is_some() {
        return Err(Failure::Usage(
            "compact is offline/firmware-only: use --image".into(),
        ));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .write(mutation)
        .open(args.backing()?)
        .map_err(fail)?;
    if mutation {
        file.lock().map_err(fail)?;
    }
    let size = usize::try_from(file.seek(SeekFrom::End(0)).map_err(fail)?).map_err(fail)?;
    let mut image = vec![0; size];
    file.read_exact_at(&mut image, 0).map_err(fail)?;
    let header = Header::decode(&image).map_err(fail)?;
    let cp =
        Checkpoint::decode(&image[header.checkpoint_offset..header.log_offset]).map_err(fail)?;
    let mut scratch = vec![0; header.checkpoint_capacity];
    let mut replay = replay(&image, &mut scratch, &mut PolicyNone, 0).map_err(fail)?;
    match command {
        "inspect" => {
            println!(
                "format: EFVS v1\nsize: {size} bytes\ncheckpoint capacity: {}\ncheckpoint used: {}\ncheckpoint variables: {}\ncheckpoint next sequence: {}\ncheckpoint authenticated count: {}\ncheckpoint SHA-256: {}\nlog offset: {}\nlog capacity: {}\nlog used: {}\nlog end: {:?}\naccepted records: {}\nrejected records: {}\nlive variables: {}\ntier: 0\nSecureBoot: 0\nanchor: NONE",
                header.checkpoint_capacity,
                cp.used,
                cp.count,
                cp.next_sequence,
                cp.authenticated_count,
                hex(&cp.hash),
                header.log_offset,
                header.log_capacity,
                replay.log_bytes,
                replay.end,
                replay.accepted,
                replay.rejected,
                replay.state.variables().count()
            );
        }
        "list" => {
            for v in replay.state.variables() {
                println!(
                    "{}  {}  0x{:08x}  {} bytes",
                    guid_text(&v.guid),
                    text(v.name),
                    v.attributes,
                    v.data.len()
                );
            }
        }
        "get" => {
            let (name, guid) = args.key()?;
            let wire = wire_name(&name);
            let v = replay
                .state
                .get(&wire, &guid)
                .ok_or_else(|| missing(&name, &guid))?;
            if let Some(out) = args.value("--out") {
                std::fs::write(out, v.data).map_err(fail)?;
            } else {
                println!(
                    "attributes: 0x{:08x}\nsize: {} bytes\ndata: {}",
                    v.attributes,
                    v.data.len(),
                    hex(v.data)
                );
            }
        }
        "compact" => {
            let value = compact(&mut image, &replay.state).map_err(fail)?;
            // Crash during checkpoint rewrite is not append-atomic; this command is offline.
            file.write_all_at(
                &image[header.checkpoint_offset..header.log_offset],
                header.checkpoint_offset as u64,
            )
            .map_err(fail)?;
            file.sync_all().map_err(fail)?;
            file.write_all_at(&image[header.log_offset..], header.log_offset as u64)
                .map_err(fail)?;
            file.sync_all().map_err(fail)?;
            commit_anchor(&mut NoneAnchor::new(), value).map_err(fail)?;
            println!("compacted: authenticated count {value}, tier 0");
        }
        "set" | "delete" | "oneshot" => {
            let (name, guid) = if command == "oneshot" {
                (ONESHOT_NAME.encode_utf16().collect(), ONESHOT_GUID)
            } else {
                args.key()?
            };
            let wire = wire_name(&name);
            let deleting = command == "delete" || command == "oneshot" && args.has("--clear");
            let data = if deleting {
                Vec::new()
            } else if command == "oneshot" {
                let [entry] = args.operands() else {
                    return Err(Failure::Usage("oneshot needs one entry id".into()));
                };
                if entry.is_empty() {
                    return Err(Failure::Usage("entry id is empty".into()));
                }
                entry
                    .encode_utf16()
                    .chain(core::iter::once(0))
                    .flat_map(|u| u.to_le_bytes())
                    .collect()
            } else {
                std::fs::read(args.required("--data-file")?).map_err(fail)?
            };
            if command == "oneshot" && deleting && !args.operands().is_empty() {
                return Err(Failure::Usage("oneshot --clear takes no entry id".into()));
            }
            let attributes = if deleting {
                replay
                    .state
                    .get(&wire, &guid)
                    .ok_or_else(|| missing(&name, &guid))?
                    .attributes
            } else if command == "oneshot" {
                7
            } else {
                parse_attributes(args.required("--attributes")?)?
            };
            let operation = if attributes & ATTR_APPEND != 0 {
                Operation::Append
            } else if deleting || data.is_empty() {
                Operation::Delete
            } else {
                Operation::Set
            };
            let range = append(
                &mut image,
                RecordInput {
                    name: &wire,
                    guid,
                    attributes,
                    operation,
                    data: &data,
                },
                &mut replay.state,
                &mut PolicyNone,
            )
            .map_err(fail)?;
            file.write_all_at(&image[range.clone()], range.start as u64)
                .map_err(fail)?;
            file.sync_all().map_err(fail)?;
            let mut check = vec![0; range.len()];
            file.read_exact_at(&mut check, range.start as u64)
                .map_err(fail)?;
            if check != image[range] {
                return Err(Failure::Run("EFVS append readback mismatch".into()));
            }
            println!(
                "appended {:?} `{}`",
                operation,
                String::from_utf16_lossy(&name)
            );
        }
        _ => {
            return Err(Failure::Usage(format!(
                "unsupported EFVS command `{command}`"
            )));
        }
    }
    Ok(())
}
