#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""EFVS VM set/update/delete/reboot, offline firmware compaction and torn-tail reread.

Inputs must be built against the SAME kernel output. Trimmed GKI uses esu's
production relocating loader; ordinary insmod remains a diagnostic option.
"""
import argparse
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile

GUID = "7a5e4b1c-0d3f-4e62-9b8a-1c2d3e4f5a6b"


def archive(files: dict[str, tuple[bytes, int]]) -> bytes:
    result = bytearray()
    for ino, (name, (data, mode)) in enumerate(files.items(), 1):
        encoded = name.encode() + b"\0"
        fields = [ino, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(encoded), 0]
        result += b"070701" + b"".join(f"{n:08x}".encode() for n in fields) + encoded
        result += b"\0" * (-len(result) % 4)
        result += data + b"\0" * (-len(data) % 4)
    encoded = b"TRAILER!!!\0"
    fields = [0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, len(encoded), 0]
    result += b"070701" + b"".join(f"{n:08x}".encode() for n in fields) + encoded
    result += b"\0" * (-len(result) % 512)
    return bytes(result)


def init_script(phase: str, transports: list[str], relocating: bool) -> bytes:
    loads = "\n".join(f"/bin/busybox insmod /lib/{name} || fail transport-{name}" for name in transports)
    loader = "/bin/relocating-insmod" if relocating else "/bin/busybox insmod"
    blank = f"""
{loader} /lib/efivar_store.ko dev="$dev" && fail blank-accepted
echo EFIVAR_QEMU_PASS-blank
/bin/busybox poweroff -f
while :; do :; done
""" if phase == "blank" else ""
    actions = r"""
/bin/busybox printf '\007\000\000\000first' > "$keep" || fail set
/bin/busybox printf '\007\000\000\000first' > /expected
/bin/busybox cmp /expected "$keep" || fail immediate-get
/bin/busybox printf '\007\000\000\000second' > "$keep" || fail replace
/bin/busybox printf '\007\000\000\000gone' > "$deleted" || fail create-delete
/bin/busybox rm "$deleted" || fail delete
/bin/busybox test ! -e "$deleted" || fail delete-visible
""" if phase == "write" else r"""
/bin/busybox printf '\007\000\000\000second' > /expected
/bin/busybox cmp /expected "$keep" || fail reboot-get
/bin/busybox test ! -e "$deleted" || fail reboot-delete
/bin/busybox test ! -e /efivars/Torn-""" + GUID + r""" || fail torn-visible
"""
    return (f"""#!/bin/busybox sh
export PATH=/bin
fail() {{ echo EFIVAR_QEMU_FAIL-$1; /bin/busybox dmesg; /bin/busybox poweroff -f; while :; do :; done; }}
/bin/busybox mkdir -p /proc /sys /dev /efivars /lib
/bin/busybox mount -t proc proc /proc || fail proc
/bin/busybox mount -t sysfs sysfs /sys || fail sysfs
{loads}
/bin/busybox test -e /sys/class/block/vda/dev || fail virtio-device
dev=$(/bin/busybox cat /sys/class/block/vda/dev)
major=${{dev%:*}}; minor=${{dev#*:}}
/bin/busybox mknod /dev/vda b "$major" "$minor" || fail block-node
{loader} /lib/efivarfs.ko || fail frontend-insertion
{blank}
{loader} /lib/efivar_store.ko dev="$dev" || fail backend-insertion
/bin/busybox mount -t efivarfs -o rw efivarfs /efivars || fail mount-rw
keep=/efivars/Roundtrip-{GUID}
deleted=/efivars/Deleted-{GUID}
{actions}
/bin/busybox sync
echo EFIVAR_QEMU_PASS-{phase}
/bin/busybox poweroff -f
while :; do :; done
""").encode()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel-out", type=Path, required=True)
    parser.add_argument("--backend", type=Path, required=True)
    parser.add_argument("--frontend", type=Path, required=True)
    parser.add_argument("--busybox", type=Path, required=True)
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--work", type=Path)
    parser.add_argument("--loader", type=Path, help="Static esuinit relocating-insmod example for trimmed GKI")
    args = parser.parse_args()
    work = args.work or Path(tempfile.mkdtemp(prefix="efivar-qemu-", dir="/var/tmp"))
    if args.work:
        work.mkdir(parents=True, exist_ok=False)
    image = work / "store.img"
    subprocess.run([str(args.cli.resolve()), "init", "--efvs", "--image", str(image), "--size", "1048576"], check=True)
    files = {"bin": (b"", stat.S_IFDIR | 0o755), "lib": (b"", stat.S_IFDIR | 0o755),
             "bin/busybox": (args.busybox.read_bytes(), stat.S_IFREG | 0o755),
             "lib/efivar_store.ko": (args.backend.read_bytes(), stat.S_IFREG | 0o644),
             "lib/efivarfs.ko": (args.frontend.read_bytes(), stat.S_IFREG | 0o644)}
    if args.loader:
        files["bin/relocating-insmod"] = (args.loader.read_bytes(), stat.S_IFREG | 0o755)
    transports = []
    for relative in ["drivers/virtio/virtio_pci_legacy_dev.ko", "drivers/virtio/virtio_pci_modern_dev.ko", "drivers/virtio/virtio_pci.ko", "drivers/block/virtio_blk.ko"]:
        path = args.kernel_out / relative
        if path.exists():
            files[f"lib/{path.name}"] = (path.read_bytes(), stat.S_IFREG | 0o644)
            transports.append(path.name)
    qemu = shutil.which("qemu-system-aarch64")
    if qemu is None:
        raise SystemExit("qemu-system-aarch64 is missing")
    for phase in ["write", "read", "compact", "torn", "blank"]:
        if phase == "blank":
            image = work / "blank.img"
            image.write_bytes(bytes(1048576))
        if phase == "compact":
            subprocess.run([str(args.cli.resolve()), "compact", "--image", str(image)], check=True)
        if phase == "torn":
            value = work / "torn-value"
            value.write_bytes(b"must-not-be-visible")
            subprocess.run([str(args.cli.resolve()), "set", "--image", str(image),
                            "--name", "Torn", "--guid", GUID, "--attributes", "7",
                            "--data-file", str(value)], check=True)
            raw = bytearray(image.read_bytes())
            log_offset = int.from_bytes(raw[32:40], "little")
            length = int.from_bytes(raw[log_offset + 4:log_offset + 8], "little")
            # Truncate the last record's bytes, retaining the fixed block-device size.
            raw[log_offset + length - 16:] = bytes(len(raw) - log_offset - length + 16)
            image.write_bytes(raw)
        files["init"] = (init_script(phase, transports, args.loader is not None), stat.S_IFREG | 0o755)
        initrd = work / f"{phase}.cpio"
        initrd.write_bytes(archive(files))
        command = [qemu, "-machine", "virt", "-cpu", "max", "-m", "1024", "-smp", "2", "-nographic", "-no-reboot",
                   "-kernel", str(args.kernel_out / "arch/arm64/boot/Image"), "-initrd", str(initrd),
                   "-append", "console=ttyAMA0 earlycon=pl011,0x9000000 rdinit=/init panic=-1 nokaslr",
                   "-drive", f"if=none,file={image},format=raw,id=store", "-device", "virtio-blk-pci,drive=store"]
        try:
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
            text = result.stdout
        except subprocess.TimeoutExpired as error:
            text = error.stdout or b""
        log = work / f"{phase}.log"
        log.write_bytes(text)
        print(f"{phase}: {log}")
        if f"EFIVAR_QEMU_PASS-{phase}".encode() not in text or b"EFIVAR_QEMU_FAIL-" in text:
            print(text.decode(errors="replace"))
            raise SystemExit(f"VM {phase} gate failed; exact console evidence: {log}")
        if phase == "blank" and image.read_bytes() != bytes(1048576):
            raise SystemExit("Blank store was modified by the kernel")
    print(f"PASS: immediate read, update, delete, reboot, firmware compaction, torn-tail reread and blank refusal without writes; image: {work / 'store.img'}")


if __name__ == "__main__":
    main()
