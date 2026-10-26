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


SNAKE_MODEL = '''using System.Collections.Generic;
[System.Serializable]
public class LevelModel
{
    public int width = 6;
    public int height = 8;
    public List<Coord> blockedCells = new List<Coord>();
    public List<HoleInfo> holeInfos = new List<HoleInfo>();
    public List<SnakeInfo> snakeInfos = new List<SnakeInfo>();
    public List<LinkInfo> links = new List<LinkInfo>();
}
[System.Serializable]
public class SnakeInfo
{
    public SnakeInfo() { colorID = new List<int>(); }
    public int Length { get { return bodyPosition.Count; } }
    public int id;
    public List<int> colorID;
    public List<Coord> bodyPosition;
    public List<MechanicInfo> mechanics;
}
[System.Serializable]
public class HoleInfo { public int id; public int colorID; public Coord position; public bool singleEntry; public List<MechanicInfo> mechanics; }
[System.Serializable]
public class LinkInfo { public LinkKind kind; public int sourceId; public int targetId; }
[System.Serializable]
public class MechanicInfo { public MechanicKind kind; public string payloadJson = "{}"; }
[System.Serializable]
public struct Coord { public int x; public int y; }
public enum LinkKind { Connected = 1, Tied = 2 }
public enum MechanicKind { StoneWall = 1, BombSnake = 11, StackedSnake = 7, TwoSidedHole = 26 }
'''

SNAKE_DUMP = '''// Namespace: Game
[Serializable]
public class BombSnakeLevelData // TypeDefIndex: 1
{
	// Fields
	public int timeToExplode; // 0x10
}

// Namespace: Game
[Serializable]
public class NestedSnakeLevelData // TypeDefIndex: 2
{
	// Fields
	public int[] insideSnakeCatalogIds; // 0x10
}

// Namespace: Game
public abstract class NestedSnakeLevelDataAdapterBase : LevelDataAdapterVersionOneBase // TypeDefIndex: 3
{
	// Methods
	// RVA: 0x1 Offset: 0x1 VA: 0x1
	protected NestedSnakeLevelData Parse(LevelComponentData _levelComponentData) { }
}

// Namespace: Game
public class StackedSnakeLevelDataAdapter : NestedSnakeLevelDataAdapterBase, ILevelLiveStateAdapter // TypeDefIndex: 4
{
	// Methods
	public override LevelDataKind GetKind() { }
}
'''


class BoardProfileTests(unittest.TestCase):
    def build(self, temporary: Path, profile=None):
        source = temporary / "LevelModel.cs"
        source.write_text(SNAKE_MODEL, encoding="utf-8")
        if profile is not None:
            (temporary / level_editor.PROFILE_FILE_NAME).write_text(json.dumps(profile), encoding="utf-8")
        job = temporary / "job"
        (job / "il2cppdumper").mkdir(parents=True, exist_ok=True)
        (job / "il2cppdumper" / "dump.cs").write_text(SNAKE_DUMP, encoding="utf-8")
        output = temporary / "editor.html"
        logs = []
        level_editor.build_level_editor(source, output, job, None, logs.append)
        html = output.read_text(encoding="utf-8")
        return json.loads(re.search(r"const D = (.*?);\nconst \$", html, re.S).group(1)), logs

    def test_mechanic_catalog_payloads_come_from_apk_classes(self):
        with tempfile.TemporaryDirectory() as temporary:
            data, logs = self.build(Path(temporary))
        self.assertIsNone(data["saved_profile"])
        catalog = {m["name"]: m for m in data["mechanic_catalogs"]["MechanicKind"]}
        self.assertEqual(catalog["BombSnake"]["target"], "snake")
        self.assertEqual(catalog["TwoSidedHole"]["target"], "hole")
        self.assertEqual(catalog["StoneWall"]["target"], "entity")
        bomb = data["classes"][catalog["BombSnake"]["payload"]]
        self.assertEqual([f["json"] for f in bomb["fields"]], ["timeToExplode"])
        # StackedSnake has no StackedSnakeLevelData; the adapter's base class parses NestedSnakeLevelData.
        self.assertEqual(catalog["StackedSnake"]["payload_class"], "Game.NestedSnakeLevelData")
        self.assertNotIn("payload", catalog["TwoSidedHole"])
        self.assertTrue(any("tự đoán bàn chơi" in line for line in logs))

    def test_saved_profile_next_to_leveldata_is_embedded(self):
        profile = {"version": 1, "grid": {"width": "width", "height": "height"},
                   "layers": [{"name": "Rắn", "list": "snakeInfos", "mode": "path", "path": "bodyPosition"}]}
        with tempfile.TemporaryDirectory() as temporary:
            data, logs = self.build(Path(temporary), profile)
        self.assertEqual(data["saved_profile"], profile)
        self.assertTrue(any("Dùng profile bàn chơi đã lưu" in line for line in logs))

    def test_invalid_saved_profile_is_reported(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(level_editor.LevelEditorError):
                self.build(Path(temporary), {"grid": {}})


INFER_DUMP = '''// Namespace: Game
public class LevelManager : MonoBehaviour // TypeDefIndex: 1
{
	public LevelDefinition current; // 0x18
	public List<LevelDefinition> all; // 0x20
}

// Namespace: Game
[Serializable]
public class LevelDefinition // TypeDefIndex: 2
{
	public int schemaVersion; // 0x10
	public LevelGridData[] grids; // 0x18
	public LevelSnakeData[] snakes; // 0x20
	[JsonProperty(DefaultValueHandling = 1)]
	public bool isBoardCapture; // 0x28
	[JsonProperty(NullValueHandling = 1)]
	public Nullable<int> typeShuffleSeed; // 0x2C
	public static int Count; // 0x0
}

// Namespace: Game
[Serializable]
public class LevelGridData // TypeDefIndex: 3
{
	public int width; // 0x10
	public int height; // 0x14
	public LevelGridKind kind; // 0x18
}

// Namespace: Game
[Serializable]
public class LevelSnakeData // TypeDefIndex: 4
{
	public int entityId; // 0x10
	public LevelGridPositionData[] segmentsHeadToTail; // 0x18
}

// Namespace: Game
[Serializable]
public class LevelGridPositionData // TypeDefIndex: 5
{
	public int x; // 0x10
	public int y; // 0x14
}

// Namespace: Game
public enum LevelGridKind // TypeDefIndex: 6
{
	public int value__; // 0x0
	public const LevelGridKind Main = 1;
	public const LevelGridKind ColorFloor = 2;
}
'''


class InferLevelDataTests(unittest.TestCase):
    def build(self, temporary: Path, root=None):
        job = temporary / "job"
        (job / "il2cppdumper").mkdir(parents=True)
        (job / "il2cppdumper" / "dump.cs").write_text(INFER_DUMP, encoding="utf-8")
        logs = []
        report = level_editor.build_level_editor(None, temporary / "levelEditor.html", job, root, logs.append)
        source = (job / level_editor.APK_LEVELDATA_DIR / "LevelData.cs").read_text(encoding="utf-8")
        return report, source, logs

    def test_level_class_is_found_in_apk_and_written_as_leveldata(self):
        with tempfile.TemporaryDirectory() as temporary:
            report, source, logs = self.build(Path(temporary))
        self.assertEqual(report["root"], "LevelEditorData.LevelDefinition")
        self.assertEqual(report["inferred_candidates"][0], "Game.LevelDefinition")
        self.assertNotIn("Game.LevelManager", report["inferred_candidates"][:1])
        self.assertIn("public LevelGridData[] grids;", source)
        self.assertIn("public LevelGridPositionData[] segmentsHeadToTail;", source)
        self.assertIn("public int? typeShuffleSeed;", source)
        self.assertIn("public enum LevelGridKind", source)
        self.assertNotIn("Count", source)
        # JsonProperty options are not JSON names
        self.assertNotIn("DefaultValueHandling", source)
        self.assertTrue(any("Khớp APK: LevelDefinition" in line for line in logs))
        self.assertFalse(any(line.startswith("Khác APK") for line in logs))

    def test_root_override_picks_another_apk_class(self):
        with tempfile.TemporaryDirectory() as temporary:
            report, source, logs = self.build(Path(temporary), "LevelSnakeData")
        self.assertEqual(report["root"], "LevelEditorData.LevelSnakeData")
        self.assertNotIn("class LevelDefinition", source)

    def test_without_leveldata_or_job_is_an_error(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(level_editor.LevelEditorError):
                level_editor.build_level_editor(None, Path(temporary) / "x.html", None)


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
