# SPDX-License-Identifier: GPL-2.0-only
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("efvs_rustc_wrapper", Path(__file__).with_name("rustc-wrapper.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class CompilerRuntimeArguments(unittest.TestCase):
    def test_missing_or_ambiguous_root_fails_closed(self):
        for roots in ([], ["one.rs", "two.rs"]):
            with self.assertRaises(ValueError):
                module.compiler_arguments(["--crate-name", "compiler_builtins", *roots])


if __name__ == "__main__":
    unittest.main()
