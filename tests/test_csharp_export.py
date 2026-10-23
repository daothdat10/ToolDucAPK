import tempfile
import unittest
from pathlib import Path

from ducapk.csharp_export import export_c_tree, render_csharp_reference


class CSharpReferenceExportTests(unittest.TestCase):
    def test_render_translates_field_access_and_uses_managed_names(self):
        source = (
            "/* IL2CPP class: Game-Logic */\n\n"
            "/* Move | RVA: 0x12345\n"
            "   System.Void Game::Move(System.Int32 count)\n"
            "*/\n"
            "void IL2CPP_Game__Move_12345(long param_1, undefined4 param_2)\n"
            "{\n"
            "  *(undefined4 *)(param_1 + 0x10) = param_2;\n"
            "  return;\n"
            "}\n"
            "/* Ready | RVA: 0x12346\n"
            "   bool Game::Ready()\n"
            "*/\n"
            "undefined1 IL2CPP_Game__Ready_12346(long param_1)\n"
            "{\n"
            "  return *(undefined1 *)(param_1 + 0x44);\n"
            "}\n"
        )
        rendered, stats = render_csharp_reference(source, "Game.c")
        self.assertEqual(stats["methods_translated"], 2)
        self.assertEqual(stats["methods_stubbed"], 0)
        self.assertIn("public static unsafe class Game_Logic", rendered)
        self.assertIn("Move | native RVA 0x12345", rendered)
        self.assertIn("public static void Move_RVA_12345(long param_1, uint param_2)", rendered)
        self.assertIn("*((uint*)((byte*)param_1 + 0x10)) = param_2;", rendered)
        self.assertIn("public static bool Ready_RVA_12346(long param_1)", rendered)
        self.assertIn("return *((byte*)((byte*)param_1 + 0x44)) != 0;", rendered)
        self.assertNotIn("NotImplementedException", rendered)

    def test_export_tree_keeps_relative_paths_and_reports_counts(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "classes_c"
            (source / "game_logic").mkdir(parents=True)
            (source / "game_logic" / "Player.c").write_text(
                "/* IL2CPP class: Player */\n"
                "/* Tick | RVA: 0x123456\n int Player__Tick();\n*/\n"
                "int IL2CPP_Player__Tick_123456(long param_1) { return *(int *)(param_1 + 4); }\n",
                encoding="utf-8")
            original_text = (source / "game_logic" / "Player.c").read_text(encoding="utf-8")
            output = root / "classes_csharp_reference"
            messages = []
            report = export_c_tree(source, output, messages.append)
            self.assertEqual((report["files_found"], report["files_written"],
                              report["methods_translated"], report["files_failed"]),
                             (1, 1, 1, 0))
            generated = output / "game_logic" / "Player.cs"
            self.assertTrue(generated.is_file())
            self.assertIn("public static unsafe class Player", generated.read_text(encoding="utf-8"))
            self.assertTrue((output / "translation_report.json").is_file())
            self.assertEqual((source / "game_logic" / "Player.c").read_text(encoding="utf-8"),
                             original_text)
            self.assertEqual(list(output.rglob("*.c")), [])
            self.assertEqual(len(messages), 1)


if __name__ == "__main__":
    unittest.main()
