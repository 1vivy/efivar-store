//! Explicit EFVS backing selection: provision a file-backed store, select an
//! existing file or partition, and inspect the selection on an ESP.
use super::{Args, Failure, fail, guid_from_text, guid_text};
use efivar_store::efvs::*;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

fn number(args: &Args, key: &str, default: Option<u64>) -> Result<u64, Failure> {
    match args.value(key) {
        Some(text) => text
            .parse()
            .map_err(|_| Failure::Usage(format!("`{key}` must be a byte count"))),
        None => default.ok_or_else(|| Failure::Usage(format!("{key} is required"))),
    }
}

fn uuid(args: &Args, key: &str) -> Result<Guid, Failure> {
    guid_from_text(args.required(key)?)
}

fn esp(args: &Args) -> Result<PathBuf, Failure> {
    let path = PathBuf::from(args.required("--esp")?);
    if !path.is_dir() {
        return Err(Failure::Run(format!(
            "{} is not the root of a mounted ESP",
            path.display()
        )));
    }
    fs::canonicalize(&path).map_err(fail)
}

fn config_path(esp: &Path) -> PathBuf {
    esp.join(BACKING_CONFIG_PATH)
}

fn write_config(
    esp: &Path,
    descriptor: BackingDescriptor,
    replace: bool,
) -> Result<PathBuf, Failure> {
    let path = config_path(esp);
    let parent = path.parent().expect("the selection has a parent");
    fs::create_dir_all(parent).map_err(fail)?;
    inside_esp(esp, parent)?;
    let mut bytes = [0; BACKING_DESCRIPTOR_SIZE];
    descriptor.encode(&mut bytes).map_err(fail)?;
    if replace {
        let temporary = parent.join(format!(".store.cfg.{}.tmp", std::process::id()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(fail)?;
        file.write_all(&bytes).map_err(fail)?;
        file.sync_all().map_err(fail)?;
        fs::rename(&temporary, &path).map_err(fail)?;
        sync_directories(esp, parent)?;
    } else {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| {
                Failure::Run(format!(
                    "{} already exists; refusing to replace an explicit selection without --replace: {error}",
                    path.display()
                ))
            })?;
        file.write_all(&bytes).map_err(fail)?;
        file.sync_all().map_err(fail)?;
        sync_directories(esp, parent)?;
    }
    Ok(path)
}

fn inside_esp(esp: &Path, target: &Path) -> Result<(), Failure> {
    let target = fs::canonicalize(target).map_err(fail)?;
    if !target.starts_with(esp) {
        return Err(Failure::Run(format!(
            "{} resolves outside the selected ESP {}",
            target.display(),
            esp.display()
        )));
    }
    Ok(())
}

/// Flush a newly created directory chain through the ESP, not only its leaf,
/// before publishing anything that refers to the new entry.
fn sync_directories(esp: &Path, leaf: &Path) -> Result<(), Failure> {
    let mut directory = fs::canonicalize(leaf).map_err(fail)?;
    if !directory.starts_with(esp) {
        return Err(Failure::Run(format!(
            "{} resolves outside the selected ESP {}",
            directory.display(),
            esp.display()
        )));
    }
    loop {
        File::open(&directory)
            .and_then(|handle| handle.sync_all())
            .map_err(fail)?;
        if directory.as_path() == esp {
            return Ok(());
        }
        let parent = directory
            .parent()
            .ok_or_else(|| Failure::Run("the selected ESP is not an ancestor".into()))?
            .to_path_buf();
        directory = parent;
    }
}

fn store_len(descriptor: BackingDescriptor) -> Result<usize, Failure> {
    if descriptor.store_size > BACKING_MAX_STORE_SIZE {
        return Err(Failure::Run(format!(
            "the descriptor names {} bytes, above the {BACKING_MAX_STORE_SIZE}-byte bound",
            descriptor.store_size
        )));
    }
    usize::try_from(descriptor.store_size)
        .map_err(|_| Failure::Run("the store size does not fit this host".into()))
}

fn validate_image(
    target: &Path,
    image: &[u8],
    descriptor: BackingDescriptor,
) -> Result<(), Failure> {
    let header = Header::decode(image).map_err(|error| {
        Failure::Run(format!(
            "{} is not a valid EFVS image: {error}",
            target.display()
        ))
    })?;
    if header.block_size < descriptor.write_unit as usize {
        return Err(Failure::Run(format!(
            "{} has {}-byte blocks, below the selected {}-byte write unit",
            target.display(),
            header.block_size,
            descriptor.write_unit
        )));
    }
    Ok(())
}

fn verify_file(esp: &Path, descriptor: BackingDescriptor) -> Result<PathBuf, Failure> {
    let target = esp.join(descriptor.path());
    inside_esp(esp, &target)?;
    let metadata = fs::metadata(&target).map_err(fail)?;
    if !metadata.is_file() {
        return Err(Failure::Run(format!(
            "{} is not a regular file",
            target.display()
        )));
    }
    if metadata.len() != descriptor.store_size {
        return Err(Failure::Run(format!(
            "{} is {} bytes; the descriptor requires exactly {}",
            target.display(),
            metadata.len(),
            descriptor.store_size
        )));
    }
    let len = store_len(descriptor)?;
    let mut image = vec![0; len];
    File::open(&target)
        .and_then(|mut file| file.read_exact(&mut image))
        .map_err(fail)?;
    validate_image(&target, &image, descriptor)?;
    Ok(target)
}

fn verify_partition(device: &Path, descriptor: BackingDescriptor) -> Result<(), Failure> {
    let mut file = File::open(device).map_err(fail)?;
    let len = file.seek(SeekFrom::End(0)).map_err(fail)?;
    if len != descriptor.store_size {
        return Err(Failure::Run(format!(
            "{} is {len} bytes; the descriptor requires exactly {}",
            device.display(),
            descriptor.store_size
        )));
    }
    let mut image = vec![0; store_len(descriptor)?];
    file.seek(SeekFrom::Start(0)).map_err(fail)?;
    file.read_exact(&mut image).map_err(fail)?;
    validate_image(device, &image, descriptor)
}

/// Create a fixed-size EFVS image below the ESP, then write the selection.
fn provision(args: &Args) -> Result<(), Failure> {
    let esp = esp(args)?;
    let path = args.required("--path")?;
    let size = number(args, "--size", None)?;
    let block = number(args, "--block", Some(4096))?;
    let checkpoint = number(args, "--checkpoint", Some(PHONE_CHECKPOINT_CAPACITY as u64))?;
    let write_unit =
        u32::try_from(block).map_err(|_| Failure::Usage("`--block` must fit in 32 bits".into()))?;
    let descriptor = BackingDescriptor::file(
        uuid(args, "--store-uuid")?,
        uuid(args, "--esp-uuid")?,
        size,
        write_unit,
        path,
    )
    .map_err(|error| Failure::Usage(format!("invalid selection: {error}")))?;
    if config_path(&esp).exists() {
        return Err(Failure::Run(format!(
            "{} already selects a store; refusing to overwrite it",
            config_path(&esp).display()
        )));
    }
    let size = usize::try_from(size)
        .map_err(|_| Failure::Usage("`--size` must fit in memory for provisioning".into()))?;
    let checkpoint = usize::try_from(checkpoint)
        .map_err(|_| Failure::Usage("`--checkpoint` must fit in memory".into()))?;
    let mut image = vec![0; size];
    initialize_with_block(&mut image, checkpoint, block as usize).map_err(fail)?;
    let target = esp.join(descriptor.path());
    let parent = target.parent().expect("the store path has a parent");
    fs::create_dir_all(parent).map_err(fail)?;
    inside_esp(&esp, parent)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&target)
        .map_err(|error| {
            Failure::Run(format!(
                "{} already exists; refusing to replace a store: {error}",
                target.display()
            ))
        })?;
    file.lock().map_err(fail)?;
    file.set_len(size as u64).map_err(fail)?;
    file.write_all_at(&image, 0).map_err(fail)?;
    file.sync_all().map_err(fail)?;
    sync_directories(&esp, parent)?;
    let selected = write_config(&esp, descriptor, false)?;
    println!(
        "provisioned {}: {} bytes, EFVS v1, {} byte blocks, store {}",
        target.display(),
        size,
        block,
        guid_text(&descriptor.store_uuid)
    );
    println!("selected {}", selected.display());
    Ok(())
}

/// Select an existing file-backed or whole-partition store.
fn select(args: &Args) -> Result<(), Failure> {
    let esp = esp(args)?;
    let size = number(args, "--size", None)?;
    let block = number(args, "--block", None)?;
    let write_unit =
        u32::try_from(block).map_err(|_| Failure::Usage("`--block` must fit in 32 bits".into()))?;
    let descriptor = match args.required("--kind")? {
        "file" => BackingDescriptor::file(
            uuid(args, "--store-uuid")?,
            uuid(args, "--esp-uuid")?,
            size,
            write_unit,
            args.required("--path")?,
        ),
        "partition" => {
            let partition = uuid(args, "--partition-uuid")?;
            let store = match args.value("--store-uuid") {
                Some(_) => uuid(args, "--store-uuid")?,
                None => partition,
            };
            BackingDescriptor::partition(store, partition, size, write_unit)
        }
        other => {
            return Err(Failure::Usage(format!(
                "`--kind {other}`: expected `file` or `partition`"
            )));
        }
    }
    .map_err(|error| Failure::Usage(format!("invalid selection: {error}")))?;
    match descriptor.kind {
        BackingKind::File => {
            let target = verify_file(&esp, descriptor)?;
            println!("verified {}", target.display());
        }
        BackingKind::Partition => {
            let device = args.required("--device")?;
            verify_partition(Path::new(device), descriptor)?;
        }
    }
    let selected = write_config(&esp, descriptor, args.has("--replace"))?;
    println!(
        "selected {}: {:?} store {} on {}",
        selected.display(),
        descriptor.kind,
        guid_text(&descriptor.store_uuid),
        guid_text(&descriptor.partition_uuid)
    );
    Ok(())
}

fn inspect(args: &Args) -> Result<(), Failure> {
    let esp = esp(args)?;
    let path = config_path(&esp);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            println!(
                "selection: unconfigured ({} is absent); unique bdsvars discovery applies",
                path.display()
            );
            return Ok(());
        }
        Err(error) => return Err(fail(error)),
    };
    let descriptor = match bytes.len() {
        BACKING_DESCRIPTOR_SIZE => BackingDescriptor::decode(&bytes).map_err(|error| {
            Failure::Run(format!(
                "{} is not a valid backing descriptor: {error}",
                path.display()
            ))
        })?,
        len => {
            return Err(Failure::Run(format!(
                "{} is {len} bytes; a backing descriptor is exactly {BACKING_DESCRIPTOR_SIZE}",
                path.display()
            )));
        }
    };
    println!("selection: {}", path.display());
    println!(
        "kind: {}",
        match descriptor.kind {
            BackingKind::Partition => "partition",
            BackingKind::File => "file",
        }
    );
    println!("store uuid: {}", guid_text(&descriptor.store_uuid));
    println!(
        "{} uuid: {}",
        match descriptor.kind {
            BackingKind::Partition => "partition",
            BackingKind::File => "esp",
        },
        guid_text(&descriptor.partition_uuid)
    );
    println!("size: {} bytes", descriptor.store_size);
    println!("write unit: {} bytes", descriptor.write_unit);
    match descriptor.kind {
        BackingKind::File => {
            println!("path: {}", descriptor.path());
            let target = verify_file(&esp, descriptor)?;
            println!("target: verified {}", target.display());
        }
        BackingKind::Partition => match args.value("--device") {
            Some(device) => {
                verify_partition(Path::new(device), descriptor)?;
                println!("target: verified {device}");
            }
            None => println!("target: not checked (pass --device to verify it)"),
        },
    }
    Ok(())
}

pub fn run(args: &Args) -> Result<(), Failure> {
    match args.operands() {
        [command] => match command.as_str() {
            "provision" => provision(args),
            "select" => select(args),
            "inspect" => inspect(args),
            other => Err(Failure::Usage(format!(
                "unknown backing command `{other}`; expected provision, select or inspect"
            ))),
        },
        _ => Err(Failure::Usage(
            "`backing` takes exactly one command: provision, select or inspect".into(),
        )),
    }
}
