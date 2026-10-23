import unittest

from ducapk.categories import category_for_class


class CategoryTests(unittest.TestCase):
    def test_common_sdk_namespaces_are_not_game_logic(self):
        for name in ("Voodoo.Sauce.Debugger.IAPDebugScreen", "Nakama.Client",
                     "Cysharp.Threading.Tasks.UniTask", "LitMotion.LMotion",
                     "MaxSdkBase.AdInfo", "VContainer.Unity.LifetimeScope"):
            self.assertEqual(category_for_class(name), "sdk", name)

    def test_game_classes_with_sdk_like_names_stay_game(self):
        for name in ("NakamaAccountProvider.Foo", "LoopSortConflictResolver", "LevelSheet.Row"):
            self.assertEqual(category_for_class(name), "game", name)
        # Game-side wrapper around the Voodoo SDK counts as SDK integration.
        self.assertEqual(category_for_class("VoodooSauceProvider.Bar"), "sdk")


if __name__ == "__main__":
    unittest.main()
