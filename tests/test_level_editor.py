import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from ducapk import level_editor


LEVEL_DATA = '''using System;
using System.Collections.Generic;
using UnityEngine;
using Newtonsoft.Json;

namespace MyGame.Levels
{
    [Serializable]
    public class LevelData
    {
        [Header("Thông tin")]
        [Tooltip("Số thứ tự level")]
        public int levelId = 1;
        public string levelName = "New {level}";
        [Range(3, 12)] public int width = 6, height = 8;
        [SerializeField] private float timeLimit = 60.5f;
        private int notSerialized;
        public static int Counter;
        public const int Max = 3;
        public TileType[] tiles;
        public List<Piece> pieces = new List<Piece> { };
        public List<List<int>> layers;
        public Dictionary<string, int> goals;
        public Vector2Int spawn;
        public FruitElementType bonus = FruitElementType.Apple;
        public UnknownThing mystery;
        public int Moves { get; set; } = 25;
        public int Computed => width * height;
        [NonSerialized] public int cache;

        public int Area() { if (width > 0) { return width * height; } return 0; }

        [Serializable]
        public class Piece
        {
            public int x;
            public int y;
            public FruitElementType element;
            public bool locked;
        }
    }

    [Flags]
    public enum TileType
    {
        None = 0,
        Ice = 1 << 0,
        Rock = 1 << 1,
        Both = Ice | Rock,
    }
}
'''

DUMP = '''// Image 0: Assembly-CSharp.dll - 0

// Namespace: MyGame.Levels
[Serializable]
public class LevelData // TypeDefIndex: 10
{
	// Fields
	public int levelId; // 0x10
	public string levelName; // 0x18
	public int width; // 0x20
	public int height; // 0x24
	public TileType[] tiles; // 0x28
	public int stars; // 0x30

	// Methods
	// RVA: 0x1 Offset: 0x1 VA: 0x1
	public void .ctor() { }
}

// Namespace: MyGame
public enum FruitElementType // TypeDefIndex: 11
{
	// Fields
	public int value__; // 0x0
	public const FruitElementType Apple = 0;
	public const FruitElementType Banana = 1;
	public const FruitElementType Bomb = 7;
}

// Namespace: MyGame
public enum ObstacleType // TypeDefIndex: 12
{
	// Fields
	public int value__; // 0x0
	public const ObstacleType None = 0;
	public const ObstacleType Chain = 4;
}

// Namespace: UnityEngine
public enum RenderType // TypeDefIndex: 13
{
	public int value__; // 0x0
	public const RenderType A = 0;
	public const RenderType B = 1;
}
'''


class CSharpParserTests(unittest.TestCase):
    def test_fields_enums_nested_types_and_skipped_members(self):
        types = {t["key"]: t for t in level_editor.parse_csharp_types(LEVEL_DATA)}
        self.assertIn("MyGame.Levels.LevelData", types)
        self.assertIn("MyGame.Levels.LevelData.Piece", types)
        level = types["MyGame.Levels.LevelData"]
        names = [f["name"] for f in level["fields"]]
        self.assertEqual(names[:5], ["levelId", "levelName", "width", "height", "timeLimit"])
        self.assertIn("Moves", names)
        self.assertNotIn("Computed", names)
        self.assertNotIn("Area", names)
        moves = next(f for f in level["fields"] if f["name"] == "Moves")
        self.assertTrue(moves["property"])
        self.assertEqual(moves["default"], "25")
        name = next(f for f in level["fields"] if f["name"] == "levelName")
        self.assertEqual(name["default"], "New {level}")
        tile = types["MyGame.Levels.TileType"]
        self.assertEqual(tile["members"], [(0, "None"), (1, "Ice"), (2, "Rock"), (3, "Both")])

    def test_dump_enum_const_form(self):
        enums = [t for t in level_editor.parse_csharp_types(DUMP) if t["kind"] == "enum"]
        fruit = next(t for t in enums if t["name"] == "FruitElementType")
        self.assertEqual(fruit["members"], [(0, "Apple"), (1, "Banana"), (7, "Bomb")])


class BuildEditorTests(unittest.TestCase):
    def build(self, temporary: Path, root=None):
        source = temporary / "LevelData.cs"
        source.write_text(LEVEL_DATA, encoding="utf-8")
        job = temporary / "job"
        (job / "il2cppdumper").mkdir(parents=True)
        (job / "il2cppdumper" / "dump.cs").write_text(DUMP, encoding="utf-8")
        level_file = job / "levels" / "pack" / "Level 1.json"
        level_file.parent.mkdir(parents=True)
        level_file.write_text(json.dumps({"payload": {"LevelId": 9, "width": 4, "stars": 3}}), encoding="utf-8")
        (job / "levels.json").write_text(json.dumps({"groups": [{"name": "pack", "levels": [
            {"file": "levels/pack/Level 1.json"}]}]}), encoding="utf-8")
        (job / "job.json").write_text(json.dumps({"inputs": ["C:/games/my game.apk"]}), encoding="utf-8")
        output = temporary / "out" / "levelEditor.html"
        logs = []
        report = level_editor.build_level_editor(source, output, job, root, logs.append)
        html = output.read_text(encoding="utf-8")
        payload = re.search(r"const D = (.*?);\nconst \$", html, re.S).group(1)
        return report, json.loads(payload), html, logs

    def test_schema_uses_leveldata_and_resolves_missing_types_from_apk(self):
        with tempfile.TemporaryDirectory() as temporary:
            report, data, html, logs = self.build(Path(temporary))
        self.assertEqual(report["root"], "MyGame.Levels.LevelData")
        root = data["classes"][data["root"]]
        fields = {f["json"]: f for f in root["fields"]}
        self.assertNotIn("notSerialized", fields)
        self.assertNotIn("cache", fields)
        self.assertNotIn("Counter", fields)
        self.assertEqual(fields["width"]["range"], [3, 12])
        self.assertEqual(fields["levelId"]["tooltip"], "Số thứ tự level")
        self.assertEqual(fields["levelId"]["header"], "Thông tin")
        self.assertEqual(fields["timeLimit"]["default"], 60.5)
        self.assertEqual(fields["tiles"]["type"]["k"], "list")
        self.assertTrue(data["enums"][fields["tiles"]["type"]["of"]["ref"]]["flags"])
        self.assertEqual(fields["layers"]["type"]["of"]["k"], "list")
        self.assertEqual(fields["goals"]["type"]["k"], "dict")
        self.assertEqual(data["classes"][fields["spawn"]["type"]["ref"]]["src"], "unity")
        bonus = data["enums"][fields["bonus"]["type"]["ref"]]
        self.assertEqual(bonus["src"], "apk")
        self.assertEqual(fields["bonus"]["default"], 0)
        self.assertEqual(fields["mystery"]["type"]["k"], "raw")
        self.assertEqual(data["unresolved"][0]["type"], "UnknownThing")
        piece = data["classes"]["MyGame.Levels.LevelData.Piece"]
        self.assertEqual([f["json"] for f in piece["fields"]], ["x", "y", "element", "locked"])
        self.assertIn("MyGame.ObstacleType", data["mechanics"])
        self.assertNotIn("UnityEngine.RenderType", data["mechanics"])
        comparison = next(c for c in data["comparison"] if c["name"] == "LevelData")
        self.assertEqual(comparison["status"], "differs")
        self.assertIn("stars: int", comparison["missing_in_leveldata"])
        self.assertEqual(len(data["samples"]), 1)
        self.assertEqual(data["meta"]["apk"], "my game.apk")
        self.assertNotIn("/*__DUCAPK_DATA__*/", html)
        self.assertTrue(any(line.startswith("HOÀN TẤT LEVEL EDITOR") for line in logs))

    def test_embedded_data_cannot_close_script_tag(self):
        with tempfile.TemporaryDirectory() as temporary:
            temporary = Path(temporary)
            output = temporary / "editor.html"
            level_editor.write_editor_html({"meta": {"x": "</script><script>alert(1)</script>"}}, output)
            html = output.read_text(encoding="utf-8")
        self.assertEqual(html.count("</script>"), 1)

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_generated_script_is_valid_javascript(self):
        with tempfile.TemporaryDirectory() as temporary:
            temporary = Path(temporary)
            _, _, html, _ = self.build(temporary)
            script = re.search(r"<script>(.*)</script>", html, re.S).group(1)
            path = temporary / "editor.js"
            path.write_text(script, encoding="utf-8")
            result = subprocess.run(["node", "--check", str(path)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
