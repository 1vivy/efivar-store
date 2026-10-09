#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Select the kernel-backed runtime descriptor without modifying codegen flags."""
import os
import sys


def compiler_arguments(arguments: list[str]) -> list[str]:
    crate = None
    for index, argument in enumerate(arguments):
        if argument == "--crate-name" and index + 1 < len(arguments):
            crate = arguments[index + 1]
        elif argument.startswith("--crate-name="):
            crate = argument.split("=", 1)[1]
    if crate != "compiler_builtins":
        return arguments
    # Mirror the kernel's own designated runtime construction, without any
    # panic/no-op replacements. Helpers must resolve to real kernel symbols;
    # Kbuild and the normal ELF/import/CRC admission gate enforce that boundary.
    # Replace only the crate root, preserving sanitizer metadata and target ABI.
    from pathlib import Path
    roots = [index for index, argument in enumerate(arguments) if argument.endswith(".rs")]
    if len(roots) != 1:
        raise ValueError("compiler_builtins requires exactly one Rust crate root")
    result = arguments.copy()
    result[roots[0]] = str(Path(__file__).with_name("compiler-builtins.rs").resolve(strict=True))
    return result


if __name__ == "__main__":
    # Cargo supplies the actual rustc executable as the wrapper's first argument.
    executable = sys.argv[1]
    os.execvp(executable, [executable, *compiler_arguments(sys.argv[2:])])
