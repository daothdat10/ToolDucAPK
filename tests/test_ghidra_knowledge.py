import subprocess
import tempfile
import unittest
from pathlib import Path

from ducapk.ghidra_knowledge import _create_index, search_ghidra_source


class GhidraKnowledgeTests(unittest.TestCase):
    def test_ghidra_source_index_is_searchable(self):
        with tempfile.TemporaryDirectory() as temp:
            tmp_path = Path(temp)
            repo = tmp_path / "repo"
            source = repo / "Ghidra" / "Features" / "Decompiler" / "src" / "main" / "java"
            source.mkdir(parents=True)
            (source / "Flow.java").write_text(
                "package ghidra.test;\n// Function body decompilation flow\nclass Flow {}\n",
                encoding="utf-8",
            )
            (source.parent / "generated.bin").write_bytes(b"\x00\x01")
            subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.name", "DucAPK test"], cwd=repo, check=True)
            subprocess.run(["git", "add", "."], cwd=repo, check=True)
            subprocess.run(["git", "commit", "-qm", "fixture"], cwd=repo, check=True)

            db = tmp_path / "knowledge" / "ghidra.sqlite3"
            report = _create_index(repo, db)
            results = search_ghidra_source(db, "decompilation flow")

            self.assertEqual(report["indexed_files"], 1)
            self.assertEqual(len(results), 1)
            self.assertTrue(results[0]["path"].endswith("Flow.java"))
            self.assertEqual(results[0]["line"], 2)
            self.assertIn("decompilation", results[0]["excerpt"].casefold())
