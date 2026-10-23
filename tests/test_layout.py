import unittest
from pathlib import PurePath

from ducapk.categories import category_for_class
from ducapk.layout import ClassLayout, split_type_name


NAMES = [
    "Carrier",
    "Carrier.<AddBlock>d__116",
    "GameWinState",
    "LevelSheet",
    "LevelSheet.<>c",
    "Cysharp.Threading.Tasks.Linq.CombineLatest",
    "CombineLatest._CombineLatest.<DisposeAsync>d__75<T1, T2, TResult>",
    "TMPro.TMP_ListPool<T>",
    "TMP_ListPool.<>c<T>",
    "<PrivateImplementationDetails>",
    "Voodoo.Sauce.Internal.DebugScreen.CodeStage.AdvancedFPSCounter.Utils.CachedNumbers",
]


class LayoutTests(unittest.TestCase):
    def setUp(self):
        self.layout = ClassLayout(NAMES)

    def folder(self, name):
        return PurePath(*self.layout.relative_path(name, ".c").parts[:-1]).as_posix()

    def test_split_ignores_dots_inside_generics(self):
        self.assertEqual(split_type_name("A.B<System.Int32>.C"), ["A", "B<System.Int32>", "C"])

    def test_global_game_classes_grouped_by_role_with_nested_types(self):
        self.assertEqual(self.folder("GameWinState"), "_NoNamespace/States")
        self.assertEqual(self.folder("LevelSheet.<>c"), "_NoNamespace/Data")
        self.assertEqual(self.folder("Carrier"), self.folder("Carrier.<AddBlock>d__116"))

    def test_nested_type_recovers_owner_namespace_and_category(self):
        name = "CombineLatest._CombineLatest.<DisposeAsync>d__75<T1, T2, TResult>"
        self.assertEqual(self.folder(name), "Cysharp/Threading/Tasks/Linq")
        self.assertEqual(category_for_class(self.layout.full_name(name)), "sdk")
        self.assertEqual(self.folder("TMP_ListPool.<>c<T>"), "TMPro")

    def test_compiler_generated_and_deep_namespaces(self):
        self.assertEqual(self.folder("<PrivateImplementationDetails>"), "_CompilerGenerated")
        deep = self.folder(NAMES[-1]).split("/")
        self.assertEqual(len(deep), 5)
        self.assertEqual(deep[-1], "CodeStage.AdvancedFPSCounter.Utils")


if __name__ == "__main__":
    unittest.main()
