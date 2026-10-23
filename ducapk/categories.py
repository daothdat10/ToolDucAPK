"""Conservative class-family classification for choosing IL2CPP decompilation scope."""

from __future__ import annotations

import re


CATEGORY_LABELS = {
    "game": "Logic game / project",
    "unity": "Unity and .NET framework",
    "sdk": "Third-party SDKs and libraries",
}
ALL_CATEGORIES = frozenset(CATEGORY_LABELS)
CATEGORY_DIRS = {
    "game": "game_logic",
    "unity": "unity_dotnet",
    "sdk": "third_party_sdk",
}

UNITY_PREFIXES = (
    "UnityEngine", "UnityEditor", "Unity.", "System", "Mono", "Microsoft", "MS.", "Interop+Sys",
    "UnityEngineInternal", "UnitySourceGeneratedAssemblyMonoScriptTypes_v1", "AOT",
)
SDK_PREFIXES = (
    "Newtonsoft", "Spine", "TMPro", "DG.", "Sirenix", "Coffee.",
    "NaughtyAttributes", "MoreMountains", "SharpJson", "Google.",
    "Firebase.", "Facebook.", "Lofelt", "SelfSDK.", "Playnexx.",
    "AppsFlyer", "Adjust.", "GameAnalytics", "OneSignal", "MaxSdk",
    "IronSource", "ByteBrew", "Tenjin", "Vibration.",
    # Ad/analytics/backend SDKs
    "Voodoo", "VoodooSauce", "Voodoo_ContextSDK", "Nakama", "Grpc", "Audiomob",
    "AudiomobExamples", "GooglePlayGames", "AdjustSdk", "GameAnalyticsSDK",
    "ConsentManagementProvider", "AppLovinMax", "MaxSdkBase", "MaxSdkCallbacks",
    "MaxSdkUtils", "MaxSdkAndroid", "MaxSdkiOS", "MaxSegmentCollection", "MaxEvents",
    "Nefta", "NeftaCustomAdapter", "AppHarbrSDK", "AppHarbrSdkCallbacks",
    "AppHarbrAndroid", "Uniject", "Elephant", "ElephantSDK", "ElephantSocial", "ElephantUniTask",
    "RollicGames", "Helpshift", "AmazonAds", "UniWebView", "UniWebViewExternal", "Usercentrics",
    "SRDebugger", "SRF", "NUlid",
    # Tooling, tweening, DI and UI libraries
    "Cysharp", "Freya", "LitMotion", "Dreamteck", "MessagePipe", "Lean", "Scellecs",
    "VContainer", "Febucci", "Cathei", "AssetKits", "StatefulUI", "StatefulUISupport",
    "UnityHFSM", "IngameDebugConsole", "Tayx", "PaperPlaneTools", "TriInspector", "CW",
    "LipingShare", "uPools", "Elendow", "ToonyColorsPro", "JetBrains", "TinyJson", "Graphy",
)


def category_for_class(class_name: str) -> str:
    """Return one conservative category; unknown namespaces stay with game code."""
    value = class_name.strip()
    if any(_matches_namespace(value, prefix) for prefix in UNITY_PREFIXES):
        return "unity"
    if any(_matches_namespace(value, prefix) for prefix in SDK_PREFIXES):
        return "sdk"
    # A namespace segment ending in SDK marks SDK code, also the studio's own
    # (SDK.Popups, DalakSDK.RollicTab, Studio.SDK.Ads); the class name itself is excluded.
    namespace = value.split("<", 1)[0].split("+", 1)[0].split(".")[:-1]
    if any(part.lower().endswith("sdk") for part in namespace):
        return "sdk"
    if _is_sdk_integration(value):
        return "sdk"
    return "game"


# Game classes that wire ads, in-app purchases, analytics or vendor services count as SDK
# integration (NoAdsOfferSystem, ElephantIAPService). Matched on whole CamelCase words.
SDK_INTEGRATION_WORDS = frozenset({
    "ad", "ads", "noads", "interstitial", "rewarded", "iap", "purchase", "purchases",
    "purchasing", "payment", "payments", "analytics", "crashlytics", "firebase", "consent",
    "gdpr", "attribution", "appsflyer", "applovin", "ironsource", "elephant", "rollic",
    "helpshift", "voodoo",
})
_WORD_RE = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+")


def _is_sdk_integration(class_name: str) -> bool:
    name = class_name
    while True:  # drop generic arguments and compiler-generated <...> parts
        stripped = re.sub(r"<[^<>]*>", "", name)
        if stripped == name:
            break
        name = stripped
    words = {word.lower() for part in name.replace("+", ".").split(".")
             for word in _WORD_RE.findall(part)}
    return bool(words & SDK_INTEGRATION_WORDS)


def _matches_namespace(class_name: str, prefix: str) -> bool:
    prefix = prefix.rstrip(".")
    return (class_name == prefix or class_name.startswith(prefix + ".")
            or class_name.startswith(prefix + "+"))


def count_methods_by_category(database_path) -> dict[str, int]:
    import sqlite3

    from .layout import ClassLayout

    connection = sqlite3.connect(f"file:{database_path}?mode=ro", uri=True)
    counts = {key: 0 for key in CATEGORY_LABELS}
    try:
        layout = ClassLayout(name for (name,) in connection.execute(
            "SELECT DISTINCT class_name FROM methods"))
        for (name,) in connection.execute("SELECT class_name FROM methods"):
            counts[category_for_class(layout.full_name(name))] += 1
    finally:
        connection.close()
    return counts
