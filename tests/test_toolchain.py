import json
from pathlib import Path
import tempfile
import unittest

from ducapk.toolchain import resolve_toolchain


class ToolchainTests(unittest.TestCase):
    def test_portable_ghidra_jdk_take_priority_over_system_paths(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            ghidra = root / "tools/ghidra/ghidra_test"
            jdk = root / "tools/jdk/jdk-test"
            for path in (ghidra / "support/analyzeHeadless.bat", jdk / "bin/java.exe"):
                path.parent.mkdir(parents=True)
                path.touch()
            paths = resolve_toolchain(root, {"JAVA_HOME": "C:/another-java", "PATH": ""})
            self.assertEqual(paths["ghidra"], ghidra)
            self.assertEqual(paths["java_home"], jdk)

    def test_config_relative_paths_and_environment_overrides(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "tool_paths.json").write_text(json.dumps({"cpp2il": "custom/Cpp2IL.dll", "ghidra": "custom/ghidra"}))
            paths = resolve_toolchain(root, {"DUCAPK_GHIDRA": "override/ghidra", "PATH": ""})
            self.assertEqual(paths["cpp2il"], root / "custom/Cpp2IL.dll")
            self.assertEqual(paths["ghidra"], root / "override/ghidra")


if __name__ == "__main__":
    unittest.main()
