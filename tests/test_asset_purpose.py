from pathlib import Path
import tempfile
import unittest

from ducapk.asset_purpose import Vocabulary, describe, features

MODEL = """
namespace LevelModels
{
    public class LevelModel
    {
        public GunData[] Guns;
        public CookieBlockerData[] CookieBlockers;
    }
    public class GunData
    {
        public int BulletCount;
        public bool IsHidden;
        public int IceHp;
        public GunObstacleType ObstacleType;
    }
    public class CookieBlockerData
    {
        public int[] PixelIds;
    }
    public enum GunObstacleType
    {
        None = 0,
        Dynamite = 1,
        Rock = 2
    }
}
"""


class AssetPurposeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        (Path(self.temp.name) / "LevelModel.cs").write_text(MODEL, encoding="utf-8")
        self.vocabulary = Vocabulary(Path(self.temp.name))

    def tearDown(self):
        self.temp.cleanup()

    def test_material_purpose_from_object_path_and_owner_script(self):
        uses = [{"via": "MeshRenderer", "object": "Gun/RootMoveOnStand/Ice/Root/Frozen_Box", "scripts": [],
                 "source": "Prefab Gun · resources.assets", "owner": "Core.GamePlay.IceGun"}]
        purpose = describe("FrozenBox_snow", uses, self.vocabulary)
        self.assertIn("GunData.IceHp", purpose["mechanics"])
        self.assertEqual(purpose["owners"], ["Core.GamePlay.IceGun"])
        self.assertFalse(purpose["guessed"])
        self.assertIn("IceGun", purpose["summary"])

    def test_unattached_material_is_guessed_from_name_and_ui_words_are_ignored(self):
        purpose = describe("Dynamite_Red", [], self.vocabulary)
        self.assertEqual(purpose["mechanics"], ["GunObstacleType.Dynamite"])
        self.assertTrue(purpose["guessed"])
        ui = [{"via": "Image.m_Material", "object": "ScreenInGame/Root/IceHpLabel", "scripts": [],
               "source": "Assets/UI/ScreenInGame.prefab", "owner": ""}]
        self.assertEqual(describe("Gray", ui, self.vocabulary)["mechanics"], [])

    def test_features_group_materials_by_mechanic_script_and_screen(self):
        rows = features({
            "Rock_1": [{"object": "Gun/Rock", "source": "Prefab Gun", "owner": "Core.Rock"}],
            "LockHue": [{"object": "ModalShop/Bg", "source": "Assets/UI/ModalShop.prefab", "owner": ""}],
        }, self.vocabulary)
        names = {(row["kind"], row["name"]) for row in rows}
        self.assertIn(("Cơ chế level", "GunObstacleType.Rock"), names)
        self.assertIn(("Script game", "Core.Rock"), names)
        self.assertIn(("Màn hình UI", "ModalShop"), names)


if __name__ == "__main__":
    unittest.main()
