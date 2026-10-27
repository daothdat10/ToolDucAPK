import json
import tempfile
import unittest
from pathlib import Path

from ducapk.level_model import LEVEL_MODEL_FILE, write_level_model


def _write_job(job: Path, levels: list[dict]) -> None:
    entries = []
    for number, level in enumerate(levels, start=1):
        relative = f"levels/pack/Level {number}.json"
        (job / relative).parent.mkdir(parents=True, exist_ok=True)
        (job / relative).write_text(json.dumps(level), encoding="utf-8")
        entries.append({"name": f"Level {number}", "file": relative})
    (job / "levels.json").write_text(json.dumps({"groups": [{"name": "pack", "levels": entries}]}),
                                     encoding="utf-8")


class LevelModelTests(unittest.TestCase):
    def test_model_is_inferred_from_json_when_game_class_is_unknown(self):
        with tempfile.TemporaryDirectory() as temp:
            job = Path(temp)
            _write_job(job, [
                {"SizeX": 13, "Speed": 1, "ColorData": [{"ColorIndex": 2, "CubeDataIds": [8, 7]}],
                 "Hidden": {"Ids": []}, "Seed": 5000000000, "Name": "a"},
                {"SizeX": 9, "Speed": 1.5, "ColorData": [], "Hidden": None, "Seed": 1, "Name": "b"},
            ])
            output = write_level_model(job, lambda message: None)
            self.assertEqual(output, job / LEVEL_MODEL_FILE)
            text = output.read_text(encoding="utf-8")
            self.assertIn("public class LevelModel", text)
            self.assertIn("public int SizeX;", text)
            self.assertIn("public float Speed;", text)
            self.assertIn("public long Seed;", text)
            self.assertIn("public string Name;", text)
            self.assertIn("public ColorDataItem[] ColorData;", text)
            self.assertIn("public int[] CubeDataIds;", text)
            self.assertIn("public Hidden Hidden;", text)
            self.assertIn("public object[] Ids;", text)

    def test_game_class_is_used_and_extra_json_keys_are_added(self):
        with tempfile.TemporaryDirectory() as temp:
            job = Path(temp)
            _write_job(job, [{"LevelDifficulty": 1, "SizeX": 13, "SizeY": 13,
                              "ColorData": [{"ColorIndex": 2, "CubeDataIds": [1], "Extra": True}],
                              "NewThing": [1, 2]}])
            types = job / "cpp2il_types" / "DiffableCs" / "Assembly-CSharp" / "Core" / "GamePlay"
            types.mkdir(parents=True)
            (types / "GameLevel.cs").write_text(
                "namespace Core.GamePlay;\n\npublic class GameLevel\n{\n"
                "\tpublic LevelDifficulty LevelDifficulty; //Field offset: 0x10\n"
                "\tpublic int SizeX; //Field offset: 0x14\n\tpublic int SizeY; //Field offset: 0x18\n"
                "\tpublic ColorWrapData[] ColorData; //Field offset: 0x20\n"
                "\tpublic int Unused; //Field offset: 0x28\n}\n", encoding="utf-8")
            (types / "ColorWrapData.cs").write_text(
                "namespace Core.GamePlay;\n\npublic class ColorWrapData\n{\n"
                "\tpublic int ColorIndex; //Field offset: 0x10\n"
                "\tpublic int[] CubeDataIds; //Field offset: 0x18\n}\n", encoding="utf-8")
            (types / "LevelDifficulty.cs").write_text(
                "namespace Core.GamePlay;\n\npublic enum LevelDifficulty\n{\n"
                "\tNormal = 0,\n\tHard = 1\n}\n", encoding="utf-8")

            text = write_level_model(job, lambda message: None).read_text(encoding="utf-8")
            self.assertIn("public class GameLevel", text)
            self.assertIn("public LevelDifficulty LevelDifficulty;", text)
            self.assertIn("public ColorWrapData[] ColorData;", text)
            self.assertIn("public enum LevelDifficulty", text)
            self.assertIn("public bool Extra;", text)
            self.assertIn("public int[] NewThing;", text)
            self.assertIn("// Không xuất hiện trong level nào đã trích.\n        public int Unused;", text)

    def test_no_levels_writes_nothing(self):
        with tempfile.TemporaryDirectory() as temp:
            self.assertIsNone(write_level_model(Path(temp), lambda message: None))
            self.assertFalse((Path(temp) / LEVEL_MODEL_FILE).exists())


if __name__ == "__main__":
    unittest.main()
