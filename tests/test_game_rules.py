import tempfile
import unittest
from pathlib import Path

from ducapk.game_rules import detect_game_rules, find_color_enum
from ducapk.level_editor import TypeLibrary

INT = {"k": "int", "min": -2 ** 31, "max": 2 ** 31 - 1}


def _list(of):
    return {"k": "list", "of": of}


def _field(name, kind):
    return {"name": name, "json": name, "cs": "", "type": kind}


CLASSES = {
    "LevelModel": {"name": "LevelModel", "ns": "", "src": "apk", "kind": "class", "fields": [
        _field("SizeX", INT), _field("SizeY", INT),
        _field("ColorData", _list({"k": "obj", "ref": "ColorWrapData"})),
        _field("PixelPipeData", _list({"k": "obj", "ref": "PixelPipeData"})),
        _field("Columns", _list({"k": "obj", "ref": "Column"}))]},
    "ColorWrapData": {"name": "ColorWrapData", "ns": "", "src": "apk", "kind": "class", "fields": [
        _field("ColorIndex", INT), _field("CubeDataIds", _list(INT))]},
    "PixelPipeData": {"name": "PixelPipeData", "ns": "", "src": "apk", "kind": "class", "fields": [
        _field("PipePositions", _list(INT)), _field("PipeColors", _list(INT))]},
    "Column": {"name": "Column", "ns": "", "src": "apk", "kind": "class", "fields": [
        _field("GunDatas", _list({"k": "obj", "ref": "GunData"})),
        _field("Spawners", _list({"k": "obj", "ref": "Spawner"}))]},
    "Spawner": {"name": "Spawner", "ns": "", "src": "apk", "kind": "class", "fields": [
        _field("GunDatas", _list({"k": "obj", "ref": "GunData"}))]},
    "GunData": {"name": "GunData", "ns": "", "src": "apk", "kind": "class", "fields": [
        _field("ColorIndex", INT), _field("BulletCount", INT), _field("IsHidden", {"k": "bool"})]},
}


def _level(width, height, picture, guns, pipes=()):
    """picture: {color: [(x, y), ...]} stored column-major (x * height + y)."""
    return {
        "SizeX": width, "SizeY": height,
        "ColorData": [{"ColorIndex": color, "CubeDataIds": [x * height + y for x, y in cells]}
                      for color, cells in picture.items()],
        "PixelPipeData": [{"PipePositions": [0], "PipeColors": list(pipe)} for pipe in pipes],
        "Columns": [{"GunDatas": [{"ColorIndex": c, "BulletCount": n, "IsHidden": False} for c, n in column],
                     "Spawners": []} for column in guns],
    }


def _stripes(width, height):
    """Horizontal bands: colour 1 on the bottom rows, colour 2 above."""
    half = height // 2
    return {1: [(x, y) for x in range(width) for y in range(half)],
            2: [(x, y) for x in range(width) for y in range(half, height)]}


class GameRuleTests(unittest.TestCase):
    def test_balance_rule_with_pipe_sources_and_column_order(self):
        levels = []
        for width, height in ((6, 4), (5, 8), (7, 3)):
            picture = _stripes(width, height)
            ones, twos = len(picture[1]), len(picture[2])
            levels.append(_level(width, height, picture, [[(1, ones + 2)], [(2, twos)]], pipes=[(1, 1)]))
        rules = detect_game_rules(CLASSES, "LevelModel", levels)
        self.assertEqual(len(rules), 1)
        rule = rules[0]
        self.assertEqual(rule["unit"], {"class": "GunData", "name": "GunData", "color": "ColorIndex",
                                        "count": "BulletCount", "hidden": "IsHidden"})
        self.assertEqual(rule["sources"][0]["colors"], "PipeColors")
        self.assertEqual(rule["columns"], {"list": "Columns", "units": "GunDatas"})
        self.assertEqual(rule["spawners"], {"field": "Spawners", "units": "GunDatas"})
        self.assertEqual(rule["evidence"]["matched"], 3)
        self.assertEqual(rule["cell_order"]["order"], "column")

    def test_rule_is_not_reported_when_levels_do_not_balance(self):
        levels = [_level(4, 6, _stripes(4, 6), [[(1, 1)], [(2, 1)]]) for _ in range(3)]
        self.assertEqual(detect_game_rules(CLASSES, "LevelModel", levels), [])

    def test_nested_game_colour_enum_beats_system_enum(self):
        with tempfile.TemporaryDirectory() as temp:
            system = Path(temp) / "ConsoleColor.cs"
            system.write_text("namespace System;\n\npublic enum ConsoleColor\n{\n\tBlack = 0,\n\tBlue = 1,\n"
                              "\tGreen = 2,\n\tRed = 3,\n\tYellow = 4,\n\tWhite = 5\n}\n", encoding="utf-8")
            game = Path(temp) / "ColorCubeGlobalConfig.cs"
            game.write_text("public class ColorCubeGlobalConfig\n{\n\tpublic enum ColorType : int\n\t{\n"
                            "\t\tYellow_1 = 0,\n\t\tOrange_1 = 1,\n\t\tRed_1 = 2,\n\t\tGreen_1 = 3,\n\t\tBlue_1 = 4,\n"
                            "\t\tPink_2 = 5,\n\t\tWhite_1 = 6\n\t}\n\tprivate string pathColorCube;\n}\n", encoding="utf-8")
            library = TypeLibrary("apk")
            library.add_file(system, "apk")
            library.add_file(game, "apk")
            found = find_color_enum(library)
        self.assertEqual(found["name"], "ColorType")
        self.assertEqual(found["members"][5], [5, "Pink_2"])


if __name__ == "__main__":
    unittest.main()
