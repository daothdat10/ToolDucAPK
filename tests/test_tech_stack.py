import json
import sqlite3
import tempfile
import unittest
import zipfile
from pathlib import Path

from ducapk.tech_stack import _shader_hints, _shader_owner, scan_tech_stack


def _make_job(root: Path) -> Path:
    apk = root / "game.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("lib/arm64-v8a/libunity.so", b"")
        archive.writestr("lib/arm64-v8a/libil2cpp.so", b"")
        archive.writestr("lib/arm64-v8a/libFirebaseCppApp-13_17_0.so", b"")
        archive.writestr("assets/aa/catalog.bin", b"")
        archive.writestr("classes.dex", b"dex\n035\0" + b"\0Lcom/applovin/sdk/AppLovinSdk;\0Lcom/acme/Main;\0")
    job = root / "job"
    job.mkdir()
    (job / "job.json").write_text(json.dumps({"inputs": [str(apk)], "package_name": "com.acme.roads"}),
                                  encoding="utf-8")
    database = sqlite3.connect(job / "methods.sqlite")
    database.execute("CREATE TABLE methods (id INTEGER PRIMARY KEY, export_index INTEGER, address INTEGER, "
                     "class_name TEXT NOT NULL, method_name TEXT NOT NULL, signature TEXT NOT NULL)")
    database.execute("CREATE TABLE class_assemblies (type_key TEXT PRIMARY KEY, assembly TEXT NOT NULL)")
    database.executemany("INSERT INTO class_assemblies VALUES (?,?)", [
        ("RoadBuilder", "Assembly-CSharp"),
        ("Dreamteck.Splines.SplineComputer", "Dreamteck.Splines"),
        ("Vendor.Toolkit.Thing", "Vendor.Toolkit"),
    ])
    database.executemany("INSERT INTO methods (export_index, address, class_name, method_name, signature) "
                         "VALUES (?,?,?,?,?)", [
        (1, 16, "RoadBuilder", "Build",
         "System.Void RoadBuilder::Build(Dreamteck.Splines.SplineComputer road, System.Int32 lanes)"),
        (2, 32, "Dreamteck.Splines.SplineComputer", "Evaluate", "System.Void Dreamteck.Splines.SplineComputer::Evaluate()"),
        (3, 48, "Vendor.Toolkit.Thing", "Run", "System.Void Vendor.Toolkit.Thing::Run()"),
    ])
    database.commit()
    database.close()
    return job


class TechStackTests(unittest.TestCase):
    def test_engine_sdks_and_game_usage(self):
        with tempfile.TemporaryDirectory() as temp:
            job = _make_job(Path(temp))
            result = scan_tech_stack(job, emit=lambda _: None)
            self.assertTrue((job / "tech_stack.json").is_file())
        self.assertEqual(result["engine"]["name"], "Unity")
        self.assertEqual(result["engine"]["scripting_backend"], "IL2CPP")
        techs = {tech["name"]: tech for tech in result["technologies"]}
        for name in ("Unity Addressables", "Firebase", "AppLovin MAX", "Dreamteck Splines"):
            self.assertIn(name, techs)
        splines = techs["Dreamteck Splines"]
        self.assertEqual(splines["usage"], [{"class": "RoadBuilder", "types": ["SplineComputer"]}])
        self.assertIn("Vendor.Toolkit", result["unrecognized_assemblies"])
        self.assertNotIn("Dreamteck.Splines", result["unrecognized_assemblies"])

    def test_shader_owner_and_hints(self):
        self.assertEqual(_shader_owner("Spine/Skeleton", set()), "Spine")
        # Generic hidden names belong to EPO only once EPO itself was found.
        self.assertIsNone(_shader_owner("Hidden/Outline", set()))
        self.assertEqual(_shader_owner("Hidden/Outline", {"Easy Performant Outline (EPO)"}),
                         "Easy Performant Outline (EPO)")
        hints = _shader_hints("Custom/StencilMask", ["_MainTex", "_StencilReadMask"])
        self.assertIn("Stencil: che / cắt vùng hiển thị", hints)
        self.assertIn("Mask (che bớt phần hình)", hints)
        # Boilerplate UI properties alone do not make a shader a mask.
        self.assertEqual(_shader_hints("UI/Plain", ["_StencilReadMask", "_ColorMask", "PixelSnap"]), [])


if __name__ == "__main__":
    unittest.main()
