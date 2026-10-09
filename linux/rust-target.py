#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Extend the pinned compiler's softfloat target with the kernel's x86 mitigations."""
import argparse
import json
import subprocess
from pathlib import Path


def target_for_kernel(base: dict, config: str) -> dict:
    enabled = {line.split("=", 1)[0] for line in config.splitlines() if line.endswith("=y")}
    if "CONFIG_X86_64" not in enabled:
        raise ValueError("efivar_store x86 target requires CONFIG_X86_64=y")
    target = dict(base)
    features = target["features"].split(",")
    # Match scripts/generate_rust_target.rs and arch/x86/Makefile. LLVM-only
    # features belong in the target spec, not unsupported -Ctarget-feature flags.
    if "CONFIG_MITIGATION_RETPOLINE" in enabled:
        features += ["+retpoline-external-thunk", "+retpoline-indirect-branches",
                     "+retpoline-indirect-calls"]
    if "CONFIG_MITIGATION_SLS" in enabled:
        features += ["+harden-sls-ijmp", "+harden-sls-ret"]
    target["features"] = ",".join(features)
    target["code-model"] = "kernel"
    # Kernel modules resolve direct PLT32 calls; they have no userspace GOT.
    # The bare-metal base's no-PLT default makes LLVM libcalls use GOTPCREL.
    target["plt-by-default"] = True
    target["disable-redzone"] = True
    target["emit-debug-gdb-scripts"] = False
    target["frame-pointer"] = "may-omit"
    target["stack-probes"] = {"kind": "none"}
    return target


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rustc", required=True)
    parser.add_argument("--toolchain", required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    base = json.loads(subprocess.check_output(
        [args.rustc, "+" + args.toolchain, "-Z", "unstable-options", "--print",
         "target-spec-json", "--target", "x86_64-unknown-none"], text=True))
    content = json.dumps(target_for_kernel(base, args.config.read_text()), indent=2) + "\n"
    # Avoid needless Cargo target invalidation; flags/config changes still rebuild.
    if not args.output.exists() or args.output.read_text() != content:
        args.output.write_text(content)


if __name__ == "__main__":
    main()
