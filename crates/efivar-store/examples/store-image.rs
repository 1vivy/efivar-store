//! Host image init/inspect/edit example; GUID arguments use EFI wire-order hex.
use efivar_store::{Guid, Layout, Store, StoreMut};
use std::{env, error::Error, fmt::Write, fs};

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(out, "{byte:02x}").expect("writing a String");
    }
    out
}

fn unhex(text: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    if !text.is_ascii() || !text.len().is_multiple_of(2) {
        return Err("invalid hex".into());
    }
    (0..text.len())
        .step_by(2)
        .map(|i| Ok(u8::from_str_radix(&text[i..i + 2], 16)?))
        .collect()
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = env::args().skip(1).collect();
    match args.as_slice() {
        [op, path] if op == "inspect" => {
            let image = fs::read(path)?;
            for variable in Store::parse(&image)?.list() {
                println!(
                    "{}\t{}\t{:08x}\t{}",
                    hex(variable.name.as_bytes()),
                    hex(&variable.guid),
                    variable.attributes,
                    hex(variable.data)
                );
            }
        }
        [op, path, size, block, layout] if op == "init" => {
            let layout = match layout.as_str() {
                "normal" => Layout::Normal,
                "auth" => Layout::Authenticated,
                _ => return Err("layout must be normal or auth".into()),
            };
            let mut image = vec![0; size.parse()?];
            StoreMut::format(&mut image, layout, block.parse()?)?;
            fs::write(path, image)?;
        }
        [op, input, output, rest @ ..] if matches!(op.as_str(), "set" | "delete" | "reclaim") => {
            let mut image = fs::read(input)?;
            let mut store = StoreMut::parse(&mut image)?;
            match (op.as_str(), rest) {
                ("reclaim", []) => {
                    let mut scratch = vec![0; store.reclaim_scratch_size()];
                    store.reclaim(&mut scratch)?;
                }
                ("set", [name, guid, attr, data]) => {
                    let guid: Guid = unhex(guid)?
                        .try_into()
                        .map_err(|_| "GUID must be 16 bytes")?;
                    store.set(
                        &name.encode_utf16().collect::<Vec<_>>(),
                        &guid,
                        u32::from_str_radix(attr, 16)?,
                        &unhex(data)?,
                    )?;
                }
                ("delete", [name, guid]) => {
                    let guid: Guid = unhex(guid)?
                        .try_into()
                        .map_err(|_| "GUID must be 16 bytes")?;
                    store.delete(&name.encode_utf16().collect::<Vec<_>>(), &guid)?;
                }
                _ => return Err("invalid edit arguments".into()),
            }
            fs::write(output, image)?;
        }
        _ => {
            return Err(concat!(
                "usage: store-image inspect FILE | init OUT SIZE BLOCK normal|auth | ",
                "set IN OUT NAME GUID_WIRE_HEX ATTR_HEX DATA_HEX | ",
                "delete IN OUT NAME GUID_WIRE_HEX | reclaim IN OUT"
            )
            .into());
        }
    }
    Ok(())
}
