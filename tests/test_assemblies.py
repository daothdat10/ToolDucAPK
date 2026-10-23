import tempfile
import unittest
from pathlib import Path

from ducapk.assemblies import (CategoryResolver, assembly_category, dump_assembly_map,
                               package_tokens, type_key)


DUMP = """// Image 0: Assembly-CSharp.dll - 0
// Image 1: mscorlib.dll - 3
// Image 2: ElephantUniTask.dll - 4
// Image 3: com.dalakgames.ecs.dll - 5

// Namespace: Game
public class SnakeSystem // TypeDefIndex: 0
{}
// Namespace: Voodoo.Sauce
public class Ads // TypeDefIndex: 1
{}
// Namespace:
private sealed class SnakeHelper.<>c // TypeDefIndex: 2
{}
// Namespace: System
public class Func<T, TResult> // TypeDefIndex: 3
{}
// Namespace: ElephantUniTask.Threading.Tasks
public struct UniTask // TypeDefIndex: 4
{}
// Namespace: Dalak.Ecs
public class ComponentPool<T> // TypeDefIndex: 5
{}
"""


class AssemblyTests(unittest.TestCase):
    def setUp(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "dump.cs"
            path.write_text(DUMP, encoding="utf-8")
            self.mapping = dump_assembly_map(path)
        names = ["Game.SnakeSystem", "Voodoo.Sauce.Ads", "SnakeHelper.<>c",
                 "System.Func<XRPassCreateInfo, object>", "ElephantUniTask.Threading.Tasks.UniTask",
                 "Dalak.Ecs.ComponentPool<ColorFloorComp>", "Unknown.Thing"]
        self.resolver = CategoryResolver(names, self.mapping, "com.dalakgames.slitherrush")

    def test_type_keys_drop_generic_arguments(self):
        self.assertEqual(type_key("Dalak.Ecs.ComponentPool<ColorFloorComp>"), "Dalak.Ecs.ComponentPool")
        self.assertEqual(type_key("UniTask.<>c<RectInt>"), "UniTask.<>c")

    def test_assembly_lookup_handles_generic_instances(self):
        self.assertEqual(self.resolver.assembly("System.Func<XRPassCreateInfo, object>"), "mscorlib")
        self.assertEqual(self.resolver.assembly("Dalak.Ecs.ComponentPool<ColorFloorComp>"),
                         "com.dalakgames.ecs")

    def test_categories_follow_assembly_with_known_sdk_override(self):
        category = self.resolver.category
        self.assertEqual(category("Game.SnakeSystem"), "game")
        self.assertEqual(category("SnakeHelper.<>c"), "game")
        self.assertEqual(category("Voodoo.Sauce.Ads"), "sdk")  # SDK source inside Assembly-CSharp
        self.assertEqual(category("ElephantUniTask.Threading.Tasks.UniTask"), "sdk")
        self.assertEqual(category("Dalak.Ecs.ComponentPool<ColorFloorComp>"), "game")  # studio's own DLL
        self.assertEqual(category("System.Func<XRPassCreateInfo, object>"), "unity")
        self.assertEqual(category("Unknown.Thing"), "game")  # no assembly: namespace fallback

    def test_assembly_categories(self):
        studio = package_tokens("com.Garawell.LoopSort")
        self.assertEqual(studio, {"garawell", "loopsort"})
        self.assertEqual(assembly_category("Game.Runtime", studio), "game")
        self.assertEqual(assembly_category("VoodooSauce", studio), "sdk")
        self.assertEqual(assembly_category("Assembly-CSharp-firstpass", studio), "sdk")
        self.assertEqual(assembly_category("UnityEngine.CoreModule", studio), "unity")
        self.assertEqual(assembly_category("GooglePlayGames", studio), "sdk")
        self.assertEqual(assembly_category("com.garawell.core", studio), "game")
        self.assertEqual(assembly_category("com.garawell.sdk", studio), "sdk")
        self.assertEqual(assembly_category("GarawellSDK", studio), "sdk")

    def test_studio_sdk_namespaces_are_sdk(self):
        from ducapk.categories import category_for_class
        self.assertEqual(category_for_class("DalakSDK.RollicTab"), "sdk")
        self.assertEqual(category_for_class("SDK.AdRuleHandler"), "sdk")
        self.assertEqual(category_for_class("Dalak.SDK.Ads.Banner"), "sdk")
        self.assertEqual(category_for_class("Game.SDKManager"), "game")
        self.assertEqual(category_for_class("Game.ElephantIAPService"), "sdk")

    def test_ads_iap_analytics_integration_is_sdk(self):
        from ducapk.categories import category_for_class
        for name in ("Game.NoAdsOfferSystem", "AdsModule", "AdBreakMonitor.<Run>d__3",
                     "RewardedVideoButton", "PurchasingModule", "AnalyticsModule",
                     "Dalak.Services.AdService"):
            self.assertEqual(category_for_class(name), "sdk", name)
        for name in ("Carrier.<AddBlock>d__116", "AdventurersGiftSystem", "LevelBuildSystem",
                     "Game.ReadyState", "HeaderInfo"):
            self.assertEqual(category_for_class(name), "game", name)


if __name__ == "__main__":
    unittest.main()
