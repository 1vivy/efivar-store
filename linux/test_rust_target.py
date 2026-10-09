# SPDX-License-Identifier: GPL-2.0-only
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("efvs_rust_target", Path(__file__).with_name("rust-target.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class RustKernelTarget(unittest.TestCase):
    def test_kernel_abi_and_mitigation_features(self):
        base = {"features": "-sse,-sse2,+soft-float", "stack-probes": {"kind": "inline"}}
        result = module.target_for_kernel(base, "CONFIG_X86_64=y\nCONFIG_MITIGATION_RETPOLINE=y\nCONFIG_MITIGATION_SLS=y\n")
        self.assertEqual(result["features"].split(","), ["-sse", "-sse2", "+soft-float",
            "+retpoline-external-thunk", "+retpoline-indirect-branches",
            "+retpoline-indirect-calls", "+harden-sls-ijmp", "+harden-sls-ret"])
        self.assertTrue(result["disable-redzone"])
        self.assertEqual(result["code-model"], "kernel")
        self.assertEqual(result["stack-probes"], {"kind": "none"})

    def test_disabled_features_are_not_implied(self):
        result = module.target_for_kernel({"features": "-sse,+soft-float"}, "CONFIG_X86_64=y\n# CONFIG_MITIGATION_RETPOLINE is not set\n")
        self.assertEqual(result["features"], "-sse,+soft-float")

    def test_other_architecture_is_refused(self):
        with self.assertRaises(ValueError):
            module.target_for_kernel({"features": ""}, "CONFIG_ARM64=y\n")


if __name__ == "__main__":
    unittest.main()
