"""Which engine, libraries, SDKs and shaders a game is built with, and where the game code uses them.

Evidence comes from the APK itself: native libraries (lib/*.so), Java packages in classes*.dex,
asset paths, IL2CPP assemblies/namespaces (methods.sqlite), shaders and materials in Unity
serialized files and bundles. Usage links each library to the game classes whose fields,
base classes or method signatures mention its types (e.g. a RoadBuilder holding a SplineComputer).
Results are written to <job>/tech_stack.json.
"""

from __future__ import annotations

import json
import re
import sqlite3
import struct
import zipfile
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

GROUPS = (
    "Engine & nền tảng", "Đồ hoạ & shader", "Animation & tween", "Đường đi / Spline",
    "Kiến trúc & async", "UI", "Vật lý / AI / điều khiển", "Dữ liệu & lưu trữ", "Mạng & backend",
    "Quảng cáo", "Analytics & attribution", "Thanh toán & cửa hàng", "Bảo vệ & chống gian lận",
    "Rung & âm thanh", "Tiện ích & debug",
)


@dataclass(frozen=True)
class Tech:
    name: str
    group: str
    purpose: str
    ns: str = ""        # namespace prefixes of its C# types (regex, matched at the start of the full name)
    asm: str = ""       # assembly names (regex, full match)
    native: str = ""    # lib/*.so file names (regex)
    dex: str = ""       # Java package prefixes inside classes*.dex, slash separated (regex)
    asset: str = ""     # paths inside the APK (regex)
    shader: str = ""    # shader names (regex)
    shader_weak: str = ""  # generic shader names, counted only when the library is found by other evidence


TECHS = (
    # Engines (non-Unity engines are recognised only from their native runtime).
    Tech("Unity", GROUPS[0], "Game engine", native=r"libunity\.so", asset=r"assets/bin/Data/"),
    Tech("Unreal Engine", GROUPS[0], "Game engine", native=r"libUE4\.so|libUnreal\.so"),
    Tech("Cocos2d-x / Cocos Creator", GROUPS[0], "Game engine", native=r"libcocos.*\.so",
         asset=r"assets/(res|src)/.*\.(jsc|luac)$"),
    Tech("Godot", GROUPS[0], "Game engine", native=r"libgodot_android\.so", asset=r"\.pck$"),
    Tech("GameMaker", GROUPS[0], "Game engine", native=r"libyoyo\.so"),
    Tech("Defold", GROUPS[0], "Game engine", native=r"libdmengine.*\.so"),
    Tech("Solar2D (Corona)", GROUPS[0], "Game engine", native=r"libcorona\.so"),
    Tech("libGDX", GROUPS[0], "Game framework Java", native=r"libgdx\.so", dex=r"com/badlogic/gdx"),
    Tech("Flutter", GROUPS[0], "UI framework", native=r"libflutter\.so"),
    Tech("React Native", GROUPS[0], "UI framework", native=r"libreactnativejni\.so"),
    Tech("Xamarin / .NET MAUI", GROUPS[0], ".NET trên Android", native=r"libmonodroid\.so"),
    Tech("Cordova / WebView game", GROUPS[0], "Game HTML5 trong WebView", asset=r"assets/www/(cordova\.js|index\.html)"),
    Tech("Unity IL2CPP", GROUPS[0], "Biên dịch C# sang C++ native", native=r"libil2cpp\.so"),
    Tech("Unity Mono", GROUPS[0], "Chạy C# bằng Mono (DLL còn nguyên)", asset=r"assets/bin/Data/Managed/Assembly-CSharp\.dll"),
    Tech("Unity Burst", GROUPS[0], "Biên dịch job C# tối ưu SIMD", ns=r"Unity\.Burst", native=r"lib_burst_generated\.so"),
    Tech("Unity Jobs / Collections / DOTS", GROUPS[0], "Xử lý đa luồng, dữ liệu native",
         ns=r"Unity\.(Collections|Jobs|Entities|Mathematics)", asm=r"Unity\.(Collections|Entities|Mathematics)"),
    Tech("Unity Addressables", GROUPS[0], "Nạp asset theo bundle/CDN",
         ns=r"UnityEngine\.(AddressableAssets|ResourceManagement)", asm=r"Unity\.(Addressables|ResourceManager)",
         asset=r"assets/aa/"),
    Tech("Unity Input System", GROUPS[0], "Nhận input (touch, phím, tay cầm)", ns=r"UnityEngine\.InputSystem"),
    # Rendering and shaders.
    Tech("Universal Render Pipeline (URP)", GROUPS[1], "Render pipeline của Unity",
         ns=r"UnityEngine\.Rendering\.Universal", shader=r"Universal Render Pipeline/"),
    Tech("High Definition Render Pipeline (HDRP)", GROUPS[1], "Render pipeline của Unity",
         ns=r"UnityEngine\.Rendering\.HighDefinition", shader=r"HDRP/"),
    Tech("Shader Graph", GROUPS[1], "Shader dựng bằng node", shader=r"Shader Graphs/"),
    Tech("Toony Colors Pro", GROUPS[1], "Shader hoạt hình (toon shading)", ns=r"ToonyColorsPro",
         shader=r"Toony Colors Pro"),
    Tech("All In 1 Sprite Shader", GROUPS[1], "Hiệu ứng sprite (viền, glow, dissolve...)",
         ns=r"AllIn1SpriteShader", asm=r"AllIn1SpriteShader.*", shader=r"AllIn1"),
    Tech("All In 1 VFX Toolkit", GROUPS[1], "Shader hiệu ứng VFX", ns=r"AllIn1VfxToolkit", shader=r"AllIn1Vfx"),
    Tech("Sprite Shaders Ultimate", GROUPS[1], "Hiệu ứng shader cho sprite/UI", ns=r"SpriteShadersUltimate",
         shader=r"Sprite Shaders Ultimate"),
    Tech("Easy Performant Outline (EPO)", GROUPS[1], "Viền sáng quanh object được chọn", ns=r"EPOOutline",
         asm=r"EPO.*", shader=r"Hidden/EPO/",
         shader_weak=r"Hidden/(Outline|Obstacle|ZPrepass|Dilate|Edge dilate|FinalBlit|BasicBlit|ClearStencil|Blur)$"),
    Tech("Quick Outline", GROUPS[1], "Viền quanh mesh 3D", shader=r"Custom/Outline (Fill|Mask)"),
    Tech("Amplify Shader Editor", GROUPS[1], "Shader dựng bằng node", shader=r"^ASE|Amplify"),
    Tech("Post Processing Stack v2", GROUPS[1], "Hiệu ứng hậu kỳ (bloom, màu...)",
         ns=r"UnityEngine\.Rendering\.PostProcessing", shader=r"Hidden/PostProcessing/"),
    Tech("Coffee UIEffect", GROUPS[1], "Hiệu ứng cho UI (gray, blur, shiny...)", ns=r"Coffee\.UIEffects?",
         shader=r"\(UIEffect\)|UI/Hidden/UI-Effect"),
    Tech("Coffee SoftMaskForUGUI", GROUPS[1], "Mask mềm (che UI theo alpha)", ns=r"Coffee\.UISoftMask",
         asm=r"Coffee\.SoftMaskForUGUI", shader=r"SoftMask", shader_weak=r"Hidden/UI/TerminalMaskingShape"),
    Tech("Coffee UIParticle", GROUPS[1], "Particle hiển thị trong UI", ns=r"Coffee\.UIExtensions",
         asm=r"Coffee\.UIParticle"),
    Tech("Particle Image", GROUPS[1], "Particle cho UI", ns=r"AssetKits\.ParticleImage", asm=r"ParticleImage"),
    Tech("Unity Sprite Shape", GROUPS[1], "Vẽ địa hình 2D theo đường cong", ns=r"UnityEngine\.U2D\.SpriteShape|UnityEngine\.U2D\.SpriteShapeController"),
    # Animation.
    Tech("Spine", GROUPS[2], "Animation 2D bằng xương", ns=r"Spine", asm=r"spine-(csharp|unity)",
         shader=r"^Spine/"),
    Tech("DragonBones", GROUPS[2], "Animation 2D bằng xương", ns=r"DragonBones"),
    Tech("Live2D Cubism", GROUPS[2], "Animation nhân vật 2D", ns=r"Live2D"),
    Tech("DOTween", GROUPS[2], "Tween (di chuyển, scale, fade theo thời gian)", ns=r"DG\.Tweening"),
    Tech("LitMotion", GROUPS[2], "Tween hiệu năng cao", ns=r"LitMotion"),
    Tech("PrimeTween", GROUPS[2], "Tween không cấp phát bộ nhớ", ns=r"PrimeTween"),
    Tech("LeanTween", GROUPS[2], "Tween", ns=r"LeanTween|DentedPixel"),
    Tech("Feel / MoreMountains Tools", GROUPS[2], "Game feel: rung màn hình, feedback, tiện ích",
         ns=r"MoreMountains\.(Feedbacks|Tools|FeedbacksForThirdParty)", asm=r"MoreMountains\..*"),
    Tech("Unity Timeline", GROUPS[2], "Dựng cutscene/chuỗi animation", ns=r"UnityEngine\.Timeline"),
    Tech("Cinemachine", GROUPS[2], "Điều khiển camera", ns=r"Cinemachine|Unity\.Cinemachine"),
    Tech("Unity 2D Animation / IK", GROUPS[2], "Animation 2D bằng xương của Unity", ns=r"UnityEngine\.U2D\.(Animation|IK)"),
    # Splines and paths.
    Tech("Unity Splines", GROUPS[3], "Đường cong spline (đường đi, ray, ống...)", ns=r"UnityEngine\.Splines",
         asm=r"Unity\.Splines"),
    Tech("Dreamteck Splines", GROUPS[3], "Spline: đường đi, mesh theo đường, object chạy theo đường",
         ns=r"Dreamteck\.Splines"),
    Tech("Curvy Splines", GROUPS[3], "Spline: đường đi, mesh theo đường", ns=r"FluffyUnderware\.Curvy"),
    Tech("BG Curve", GROUPS[3], "Spline/đường cong Bezier", ns=r"BansheeGz\.BGSpline"),
    Tech("Bezier Path Creator", GROUPS[3], "Đường Bezier cho object chạy theo", ns=r"PathCreation"),
    Tech("SplineMesh", GROUPS[3], "Kéo mesh theo spline (đường, ống, dây)", ns=r"SplineMesh"),
    Tech("Bezier Solution", GROUPS[3], "Spline Bezier", ns=r"BezierSolution"),
    Tech("A* Pathfinding Project", GROUPS[3], "Tìm đường cho AI", ns=r"Pathfinding"),
    # Architecture.
    Tech("Zenject / Extenject", GROUPS[4], "Dependency injection", ns=r"Zenject|ModestTree", asm=r"Zenject.*"),
    Tech("VContainer", GROUPS[4], "Dependency injection", ns=r"VContainer"),
    Tech("UniTask", GROUPS[4], "async/await không cấp phát", ns=r"Cysharp\.Threading\.Tasks", asm=r"UniTask.*"),
    Tech("UniRx", GROUPS[4], "Lập trình reactive", ns=r"UniRx"),
    Tech("R3", GROUPS[4], "Lập trình reactive (thế hệ sau UniRx)", ns=r"R3", asm=r"R3(\..*)?"),
    Tech("ZString / ZLinq", GROUPS[4], "Chuỗi và LINQ không cấp phát", ns=r"Cysharp\.Text|ZLinq",
         asm=r"ZString|ZLinq"),
    Tech("MessagePipe", GROUPS[4], "Pub/sub message", ns=r"MessagePipe"),
    Tech("Odin Inspector / Serializer", GROUPS[4], "Inspector và serialize nâng cao", ns=r"Sirenix",
         asm=r"Sirenix\..*"),
    Tech("Unity Visual Scripting (Bolt)", GROUPS[4], "Logic bằng node", ns=r"Unity\.VisualScripting|Ludiq|Bolt"),
    Tech("PlayMaker", GROUPS[4], "Logic bằng máy trạng thái", ns=r"HutongGames\.PlayMaker"),
    Tech("Behavior Designer", GROUPS[4], "Behavior tree cho AI", ns=r"BehaviorDesigner"),
    Tech("NodeCanvas / FlowCanvas", GROUPS[4], "Behavior tree / FSM", ns=r"NodeCanvas|FlowCanvas|ParadoxNotion"),
    # UI.
    Tech("TextMeshPro", GROUPS[5], "Hiển thị chữ sắc nét", ns=r"TMPro", shader=r"TextMeshPro"),
    Tech("Unity UI (uGUI)", GROUPS[5], "Giao diện Canvas", ns=r"UnityEngine\.UI", asm=r"UnityEngine\.UI"),
    Tech("UI Toolkit", GROUPS[5], "Giao diện kiểu web (UXML/USS)", ns=r"UnityEngine\.UIElements",
         asset=r"\.uxml$"),
    Tech("Lean Touch / Lean GUI", GROUPS[5], "Cử chỉ chạm, UI", ns=r"Lean\.(Touch|Gui|Common)"),
    Tech("I2 Localization", GROUPS[5], "Đa ngôn ngữ", ns=r"I2\.Loc"),
    Tech("Unity Localization", GROUPS[5], "Đa ngôn ngữ", ns=r"UnityEngine\.Localization"),
    # Physics, AI, controls.
    Tech("Obi Physics", GROUPS[6], "Mô phỏng dây, vải, chất lỏng", ns=r"Obi"),
    Tech("Rewired", GROUPS[6], "Quản lý input", ns=r"Rewired"),
    Tech("Lean Pool", GROUPS[6], "Object pool", ns=r"Lean\.Pool"),
    # Data and storage.
    Tech("Newtonsoft Json.NET", GROUPS[7], "Đọc/ghi JSON", ns=r"Newtonsoft\.Json"),
    Tech("MessagePack", GROUPS[7], "Serialize nhị phân", ns=r"MessagePack"),
    Tech("MemoryPack", GROUPS[7], "Serialize nhị phân", ns=r"MemoryPack"),
    Tech("FlatBuffers", GROUPS[7], "Serialize nhị phân", ns=r"Google\.FlatBuffers|FlatBuffers"),
    Tech("Protocol Buffers", GROUPS[7], "Serialize nhị phân", ns=r"Google\.Protobuf", dex=r"com/google/protobuf"),
    Tech("Easy Save", GROUPS[7], "Lưu game", ns=r"ES3"),
    Tech("SQLite", GROUPS[7], "Cơ sở dữ liệu", ns=r"SQLite", native=r"libsqlite.*\.so"),
    # Networking and backend.
    Tech("Firebase", GROUPS[8], "Remote Config, Messaging, Analytics, Crashlytics của Google",
         ns=r"Firebase", native=r"libFirebaseCpp.*\.so", dex=r"com/google/firebase"),
    Tech("Google Play Games", GROUPS[8], "Đăng nhập, thành tích, bảng xếp hạng",
         ns=r"GooglePlayGames|Google\.Play\.Games", dex=r"com/google/android/gms/games"),
    Tech("Google Play Core (Review / Update / Asset Delivery)", GROUPS[8], "Đánh giá trong app, cập nhật, tải asset",
         ns=r"Google\.Play\.(Core|Review|AppUpdate|AssetDelivery|Common)", dex=r"com/google/android/play/core"),
    Tech("PlayFab", GROUPS[8], "Backend game", ns=r"PlayFab"),
    Tech("Photon", GROUPS[8], "Multiplayer", ns=r"Photon|ExitGames"),
    Tech("Mirror", GROUPS[8], "Multiplayer", ns=r"Mirror"),
    Tech("Fish-Net", GROUPS[8], "Multiplayer", ns=r"FishNet"),
    Tech("Unity Netcode", GROUPS[8], "Multiplayer", ns=r"Unity\.Netcode"),
    Tech("Nakama", GROUPS[8], "Backend game", ns=r"Nakama"),
    Tech("Unity Gaming Services", GROUPS[8], "Dịch vụ cloud của Unity", ns=r"Unity\.Services"),
    Tech("BestHTTP", GROUPS[8], "HTTP/WebSocket", ns=r"BestHTTP"),
    Tech("OkHttp", GROUPS[8], "HTTP (Java)", dex=r"okhttp3"),
    # Ads.
    Tech("AppLovin MAX", GROUPS[9], "Mediation quảng cáo", ns=r"MaxSdk", asm=r"MaxSdk.*", dex=r"com/applovin"),
    Tech("ironSource / LevelPlay", GROUPS[9], "Mediation quảng cáo", ns=r"IronSource|com\.unity3d\.mediation",
         dex=r"com/ironsource|com/unity3d/mediation|com/unity3d/ironsourceads"),
    Tech("Google AdMob", GROUPS[9], "Quảng cáo Google", ns=r"GoogleMobileAds", dex=r"com/google/android/gms/ads"),
    Tech("Unity Ads", GROUPS[9], "Quảng cáo Unity", ns=r"UnityEngine\.Advertisements", dex=r"com/unity3d/ads|com/unity3d/services"),
    Tech("Meta Audience Network", GROUPS[9], "Quảng cáo Facebook", dex=r"com/facebook/ads",
         asset=r"assets/audience_network"),
    Tech("Pangle (TikTok / ByteDance)", GROUPS[9], "Quảng cáo", dex=r"com/bytedance/sdk/openadsdk|com/bytedance/adsdk|com/bytedance/sdk"),
    Tech("Mintegral", GROUPS[9], "Quảng cáo", dex=r"com/mbridge/msdk|com/mintegral"),
    Tech("Moloco", GROUPS[9], "Quảng cáo", dex=r"com/moloco"),
    Tech("InMobi", GROUPS[9], "Quảng cáo", dex=r"com/inmobi"),
    Tech("DT Exchange (Fyber)", GROUPS[9], "Quảng cáo", dex=r"com/fyber"),
    Tech("Liftoff Monetize (Vungle)", GROUPS[9], "Quảng cáo", dex=r"com/vungle"),
    Tech("Chartboost", GROUPS[9], "Quảng cáo", dex=r"com/chartboost"),
    Tech("MobileFuse", GROUPS[9], "Quảng cáo", dex=r"com/mobilefuse", asset=r"assets/mobilefuse"),
    Tech("Smaato", GROUPS[9], "Quảng cáo", dex=r"com/smaato"),
    Tech("Verve (PubNative)", GROUPS[9], "Quảng cáo", dex=r"net/pubnative"),
    Tech("HyprMX", GROUPS[9], "Quảng cáo", dex=r"com/hyprmx"),
    Tech("Amazon Publisher Services", GROUPS[9], "Quảng cáo", dex=r"com/amazon/device/ads|com/amazon/aps"),
    Tech("myTarget", GROUPS[9], "Quảng cáo", dex=r"com/my/target"),
    Tech("Yandex Ads", GROUPS[9], "Quảng cáo", dex=r"com/yandex/mobile/ads"),
    Tech("Tencent Ads (GDT)", GROUPS[9], "Quảng cáo", dex=r"com/qq/e"),
    Tech("Bigo Ads", GROUPS[9], "Quảng cáo", dex=r"sg/bigo/ads"),
    Tech("Ogury", GROUPS[9], "Quảng cáo", dex=r"io/presage|com/ogury"),
    Tech("AppLovin SafeDK", GROUPS[9], "Kiểm tra chất lượng quảng cáo", dex=r"com/safedk"),
    Tech("IAB Open Measurement", GROUPS[9], "Đo lượt xem quảng cáo", dex=r"com/iab/omid"),
    Tech("Google UMP (GDPR consent)", GROUPS[9], "Hỏi đồng ý quyền riêng tư",
         ns=r"GoogleMobileAds\.Ump", dex=r"com/google/android/ump"),
    # Analytics and attribution.
    Tech("AppsFlyer", GROUPS[10], "Đo nguồn cài đặt (attribution)", ns=r"AppsFlyerSDK|AppsFlyer", dex=r"com/appsflyer"),
    Tech("Adjust", GROUPS[10], "Đo nguồn cài đặt (attribution)", ns=r"com\.adjust|AdjustSdk", dex=r"com/adjust/sdk"),
    Tech("Singular", GROUPS[10], "Đo nguồn cài đặt (attribution)", dex=r"com/singular/sdk"),
    Tech("GameAnalytics", GROUPS[10], "Thống kê gameplay", ns=r"GameAnalyticsSDK", dex=r"com/gameanalytics"),
    Tech("Facebook SDK", GROUPS[10], "Đăng nhập, sự kiện Facebook", ns=r"Facebook\.Unity", dex=r"com/facebook/(appevents|core|login)"),
    Tech("TikTok Business SDK", GROUPS[10], "Sự kiện quảng cáo TikTok", dex=r"com/tiktok"),
    Tech("ByteDance APM Insight", GROUPS[10], "Theo dõi crash/hiệu năng", native=r"libapminsight.*\.so", dex=r"com/apm/insight"),
    Tech("Firebase Crashlytics", GROUPS[10], "Báo crash", ns=r"Firebase\.Crashlytics", native=r"libcrashlytics.*\.so"),
    Tech("Sentry", GROUPS[10], "Báo lỗi", ns=r"Sentry", dex=r"io/sentry"),
    Tech("Amplitude", GROUPS[10], "Thống kê", dex=r"com/amplitude"),
    Tech("Mixpanel", GROUPS[10], "Thống kê", dex=r"com/mixpanel"),
    Tech("Unity Analytics", GROUPS[10], "Thống kê của Unity", ns=r"UnityEngine\.Analytics|Unity\.Services\.Analytics"),
    # Payments.
    Tech("Unity IAP", GROUPS[11], "Mua trong app", ns=r"UnityEngine\.Purchasing", asm=r"Unity\.Purchasing.*"),
    Tech("Google Play Billing", GROUPS[11], "Thanh toán Google Play", dex=r"com/android/billingclient"),
    Tech("RevenueCat", GROUPS[11], "Quản lý gói đăng ký", dex=r"com/revenuecat"),
    # Protection.
    Tech("Google Play Integrity / PairIP", GROUPS[12], "Chống chỉnh sửa, kiểm tra bản quyền",
         dex=r"com/pairip|com/google/android/play/core/integrity"),
    Tech("Anti-Cheat Toolkit (CodeStage)", GROUPS[12], "Chống sửa bộ nhớ, tua thời gian", ns=r"CodeStage\.AntiCheat"),
    Tech("Beebyte Obfuscator", GROUPS[12], "Làm rối tên class/hàm", ns=r"Beebyte"),
    # Haptics and audio.
    Tech("Nice Vibrations (Lofelt)", GROUPS[13], "Rung phản hồi", ns=r"Lofelt|MoreMountains\.NiceVibrations",
         native=r"liblofelt.*\.so"),
    Tech("FMOD", GROUPS[13], "Âm thanh", ns=r"FMOD", native=r"libfmod.*\.so"),
    Tech("Wwise", GROUPS[13], "Âm thanh", ns=r"AK\.Wwise", native=r"libAkSoundEngine\.so"),
    Tech("Master Audio", GROUPS[13], "Quản lý âm thanh", ns=r"DarkTonic\.MasterAudio"),
    # Utilities.
    Tech("In-game Debug Console", GROUPS[14], "Console log trong game", ns=r"IngameDebugConsole"),
    Tech("Graphy", GROUPS[14], "Hiển thị FPS/bộ nhớ", ns=r"Tayx\.Graphy"),
    Tech("SRDebugger", GROUPS[14], "Bảng debug trong game", ns=r"SRDebugger|SRF"),
    Tech("Ultimate Screenshot Creator", GROUPS[14], "Chụp ảnh màn hình store", ns=r"AlmostEngine"),
    Tech("Kotlin", GROUPS[14], "Ngôn ngữ cho phần Java/Android", dex=r"kotlin"),
    Tech("Jetpack Compose", GROUPS[14], "UI Android (thường của SDK quảng cáo)", dex=r"androidx/compose"),
)

_COMPILED = {tech.name: {key: re.compile(getattr(tech, key))
                         for key in ("native", "dex", "asset", "shader", "shader_weak", "asm")
                         if getattr(tech, key)} for tech in TECHS}
_NS = [(tech, re.compile(rf"(?:{tech.ns})(?:\.|$)")) for tech in TECHS if tech.ns]

BUILTIN_SHADER = re.compile(
    r"^(Hidden/(Internal|BlitCopy|BlitTo|CubeBlur|CubeCopy|CubeBlend|VR/|Video|Compositing|TextCore|Physics2D|"
    r"ConvertTexture|Universal|CoreSRP|Core/)|Sprites/|UI/(Default|Unlit|Lit)|Skybox/|Standard|Legacy Shaders/|"
    r"Mobile/|Particles/|Unlit/|Nature/|GUI/|Autodesk|Diffuse|Specular|VertexLit)")
# (shader name pattern, property name pattern, hint). Properties count only when specific
# (a _DissolveTex, not the _StencilReadMask every UI shader carries).
SHADER_HINTS = (
    (r"stencil", r"^_Stencil(Ref)?$", "Stencil: che / cắt vùng hiển thị"),
    (r"mask", r"^_(Mask|AlphaMask|MaskTex|ClipMask)\w*$", "Mask (che bớt phần hình)"),
    (r"silhouette|x-?ray|see.?through|behind", "", "Hiện bóng khi bị vật khác che"),
    (r"outline", r"^_Outline(Width|Color|Size)$", "Viền (outline)"),
    (r"dissolve", r"dissolve", "Tan biến (dissolve)"),
    (r"VAT|vertex.?anim", r"^_(PosTex|AnimTex|VatTex|VAT)", "Vertex Animation Texture: animation chạy trên GPU"),
    (r"instanc", "", "GPU instancing: vẽ hàng loạt object giống nhau"),
    (r"blur", r"^_Blur", "Làm mờ (blur)"),
    (r"glow|bloom", r"^_Glow", "Phát sáng"),
    (r"fresnel|rim\b", r"^_(Rim|Fresnel)", "Viền sáng theo góc nhìn (fresnel/rim)"),
    (r"toon", r"^_Ramp", "Toon shading (tô màu hoạt hình)"),
    (r"distort|refract", r"^_Distort", "Méo hình / khúc xạ"),
    (r"water|wave|ocean", "", "Mặt nước / sóng"),
    (r"gradient", "", "Màu chuyển (gradient)"),
    (r"gr[ae]y|desaturat|hue", "", "Đổi màu / đen trắng"),
    (r"fill", "", "Tô đầy (fill)"),
    (r"additive|multiply|screen", "", "Hoà trộn màu (additive / multiply)"),
    (r"shadow", "", "Bóng đổ"),
    (r"fog", "", "Sương mù"),
    (r"pixelate", r"^_Pixelate", "Pixel hoá"),
    (r"hologram", r"^_Hologram", "Hologram"),
    (r"^Hidden/", "", "Ẩn: gọi từ code, không gán trực tiếp vào material"),
)
_SHADER_HINTS = [(re.compile(name, re.I), re.compile(prop, re.I) if prop else None, text)
                 for name, prop, text in SHADER_HINTS]
# Types that say nothing about which library a game class leans on.
_BORING_TYPES = re.compile(r"^(System|UnityEngine(\.(CoreModule|Object|Component|MonoBehaviour|GameObject|Transform|"
                           r"Vector[234]|Quaternion|Color|Rect|Mathf|Debug))?)(\.|$)")
_DOTTED = re.compile(r"[A-Za-z_][\w`]*(?:\.[A-Za-z_][\w`]*)+")
_DEX_CLASS = re.compile(rb"L([a-zA-Z_][\w/$]*)/[\w$]+;")
_UNITY_VERSION = re.compile(r"(?:20\d{2}|6000)\.\d+\.\d+[abfp]\d+")
MAX_USAGE_CLASSES = 60
MAX_UNITY_FILE = 768 * 1024 * 1024


def _job_apks(job: Path) -> list[Path]:
    from .runner import _apk_inputs
    info = json.loads((job / "job.json").read_text(encoding="utf-8")) if (job / "job.json").is_file() else {}
    apks = _apk_inputs([Path(p) for p in info.get("inputs", [])], job)
    if not apks:  # a lone XAPK whose split APKs were never extracted
        apks = [Path(p) for p in info.get("inputs", []) if Path(p).is_file() and zipfile.is_zipfile(p)]
    return apks


def _scan_archives(apks: list[Path], emit, cancel) -> dict:
    """Native libraries, asset paths, dex packages, shaders/materials and the Unity version."""
    found = {"native": set(), "assets": [], "dex_packages": set(), "shaders": {}, "unity_version": None}
    graph = _SceneGraph()
    for apk in apks:
        try:
            archive = zipfile.ZipFile(apk)
        except (OSError, zipfile.BadZipFile):
            continue
        with archive:
            unity_files = []
            for info in archive.infolist():
                if cancel is not None and cancel.is_set():
                    return found
                name = info.filename.replace("\\", "/")
                if info.is_dir():
                    continue
                found["assets"].append(name)
                if name.startswith("lib/") and name.endswith(".so"):
                    found["native"].add(name.rsplit("/", 1)[-1])
                elif re.fullmatch(r"(.*/)?classes\d*\.dex", name):
                    data = archive.read(info)
                    found["dex_packages"].update(m.group(1).decode("ascii", "replace")
                                                 for m in _DEX_CLASS.finditer(data))
                elif name.startswith("assets/") and info.file_size <= MAX_UNITY_FILE and (
                        name.endswith((".bundle", ".unity3d", ".assets", ".ab"))
                        or re.search(r"assets/bin/Data/(level\d+|globalgamemanagers)$", name)):
                    unity_files.append(info)
            if unity_files:
                emit(f"Công nghệ: đọc shader, material, prefab và scene trong {len(unity_files)} file Unity "
                     f"của {apk.name}...")
            for info in unity_files:
                if cancel is not None and cancel.is_set():
                    return found
                graph.read(archive.read(info), info.filename, found)
    graph.finish(found)
    return found


_RENDERERS = {"MeshRenderer", "SkinnedMeshRenderer", "SpriteRenderer", "ParticleSystemRenderer",
              "LineRenderer", "TrailRenderer", "BillboardRenderer", "TilemapRenderer", "SpriteShapeRenderer"}
_SCENE_KINDS = {"Shader", "Material", "GameObject", "Transform", "RectTransform", "MonoBehaviour", "MonoScript",
                "AssetBundle", "ResourceManager", "BuildSettings"} | _RENDERERS
MAX_USES = 12


def _is_game_script(name: str) -> bool:
    return bool(name) and not name.startswith(("UnityEngine.", "Unity.", "TMPro.", "System.")) \
        and not any(pattern.match(name) for _, pattern in _NS)


def _key(obj) -> tuple[str, int]:
    return obj.assets_file.name.lower(), obj.path_id


def _pptr(obj, file_id: int, path_id: int) -> tuple[str, int] | None:
    """Global key of the object a PPtr in `obj` points at (other bundles included)."""
    if not path_id:
        return None
    if not file_id:
        return obj.assets_file.name.lower(), path_id
    externals = getattr(obj.assets_file, "externals", [])
    if file_id - 1 >= len(externals):
        return None
    return str(getattr(externals[file_id - 1], "path", "")).replace("\\", "/").rsplit("/", 1)[-1].lower(), path_id


def _pointers(value, field: str = ""):
    """(field, file_id, path_id) of every PPtr inside a MonoBehaviour typetree."""
    if isinstance(value, dict):
        if "m_PathID" in value and "m_FileID" in value:
            yield field, value["m_FileID"], value["m_PathID"]
            return
        for name, item in value.items():
            if name not in ("m_GameObject", "m_Script"):
                yield from _pointers(item, name)
    elif isinstance(value, list):
        for item in value:
            yield from _pointers(item, field)


class _SceneGraph:
    """Who uses what in the serialized scenes, prefabs and assets: materials on renderers and in
    script fields, scripts on GameObjects, and the prefab/scene each GameObject belongs to."""

    def __init__(self):
        self.shader_names: dict = {}
        self.material_names: dict = {}
        self.material_shader: dict = {}
        self.names: dict = {}           # GameObject -> name
        self.transform_go: dict = {}    # Transform -> GameObject
        self.transform_father: dict = {}
        self.scripts: dict = {}         # MonoScript -> full class name
        self.behaviours: list = []      # (GameObject or None, MonoScript, own name)
        self.links: list = []           # (target, via, GameObject or None, MonoScript or None, own name)
        self.container: dict = {}       # root asset -> container path (e.g. a prefab)
        self.scenes: list = []
        self.file_label: dict = {}

    def read(self, blob: bytes, label: str, found: dict) -> None:
        try:
            import UnityPy
            env = UnityPy.load(blob)
        except Exception:
            return
        for obj in env.objects:
            kind = obj.type.name
            if kind not in _SCENE_KINDS:
                continue
            if found["unity_version"] is None:
                version = str(getattr(obj.assets_file, "unity_version", "") or "")
                if _UNITY_VERSION.fullmatch(version):
                    found["unity_version"] = version
            self.file_label.setdefault(obj.assets_file.name.lower(), label.rsplit("/", 1)[-1])
            try:
                if kind == "MonoBehaviour":
                    self._behaviour(obj)
                    continue
                tree = obj.read_typetree()
            except Exception:
                continue
            key = _key(obj)
            if kind == "Shader":
                parsed = tree.get("m_ParsedForm") or {}
                name = parsed.get("m_Name") or tree.get("m_Name") or ""
                props = [p.get("m_Name", "") for p in (parsed.get("m_PropInfo") or {}).get("m_Props", [])]
                self.shader_names[key] = name
                entry = found["shaders"].setdefault(name, {"properties": [], "materials": set(), "files": set()})
                entry["properties"] = entry["properties"] or props
                entry["files"].add(label.rsplit("/", 1)[-1])
            elif kind == "Material":
                pointer = tree.get("m_Shader") or {}
                self.material_names[key] = tree.get("m_Name", "")
                self.material_shader[key] = _pptr(obj, pointer.get("m_FileID", 0), pointer.get("m_PathID", 0))
            elif kind == "GameObject":
                self.names[key] = tree.get("m_Name", "")
            elif kind in ("Transform", "RectTransform"):
                go, father = tree.get("m_GameObject") or {}, tree.get("m_Father") or {}
                self.transform_go[key] = _pptr(obj, go.get("m_FileID", 0), go.get("m_PathID", 0))
                self.transform_father[key] = _pptr(obj, father.get("m_FileID", 0), father.get("m_PathID", 0))
            elif kind in _RENDERERS:
                go = tree.get("m_GameObject") or {}
                owner = _pptr(obj, go.get("m_FileID", 0), go.get("m_PathID", 0))
                for pointer in tree.get("m_Materials") or []:
                    target = _pptr(obj, pointer.get("m_FileID", 0), pointer.get("m_PathID", 0))
                    if target:
                        self.links.append((target, kind, owner, None, ""))
            elif kind == "MonoScript":
                namespace = tree.get("m_Namespace") or ""
                self.scripts[key] = f"{namespace}.{tree.get('m_ClassName', '')}" if namespace else tree.get("m_ClassName", "")
            elif kind == "AssetBundle":
                for path, info in tree.get("m_Container") or []:
                    asset = info.get("asset") or {}
                    target = _pptr(obj, asset.get("m_FileID", 0), asset.get("m_PathID", 0))
                    if target:
                        self.container.setdefault(target, path)
            elif kind == "ResourceManager":
                for path, pointer in tree.get("m_Container") or []:
                    target = _pptr(obj, pointer.get("m_FileID", 0), pointer.get("m_PathID", 0))
                    if target:
                        self.container.setdefault(target, f"Resources/{path}")
            elif kind == "BuildSettings":
                self.scenes = list(tree.get("scenes") or tree.get("m_Scenes") or [])

    def _behaviour(self, obj) -> None:
        # The header is fixed: m_GameObject PPtr, m_Enabled (aligned), m_Script PPtr, m_Name.
        # Players often strip MonoBehaviour typetrees, so read it from the bytes.
        raw = obj.get_raw_data()
        go = _pptr(obj, *struct.unpack_from("<iq", raw, 0))
        script = _pptr(obj, *struct.unpack_from("<iq", raw, 16))
        length = struct.unpack_from("<i", raw, 28)[0] if len(raw) >= 32 else 0
        name = raw[32:32 + length].decode("utf-8", "replace") if 0 < length < 256 else ""
        self.behaviours.append((go, script, name))
        node = getattr(getattr(obj, "serialized_type", None), "node", None)
        pointers = []
        if node is not None:
            try:
                pointers = list(_pointers(obj.read_typetree()))
            except Exception:
                pointers = []
        else:
            # No typetree: only 64-bit path ids of bundles are distinctive enough to spot.
            for offset in range(32, len(raw) - 11, 4):
                file_id, path_id = struct.unpack_from("<iq", raw, offset)
                if abs(path_id) > 1 << 32 and 0 <= file_id < 64:
                    pointers.append(("", file_id, path_id))
        for field, file_id, path_id in pointers:
            target = _pptr(obj, file_id, path_id)
            if target:
                self.links.append((target, field, go, script, name))

    # ---------- results ----------
    def _scene_of(self, file_name: str) -> str:
        match = re.fullmatch(r"level(\d+)", file_name)
        if match and int(match.group(1)) < len(self.scenes):
            return "Scene " + self.scenes[int(match.group(1))].rsplit("/", 1)[-1].removesuffix(".unity")
        return self.file_label.get(file_name, file_name)

    def finish(self, found: dict) -> None:
        for key, shader in self.material_shader.items():
            name, material = self.shader_names.get(shader), self.material_names.get(key)
            if name and material:
                found["shaders"][name]["materials"].add(material)
        self.father_of = {self.transform_go[t]: self.transform_father.get(t) for t in self.transform_go}
        scripts_on: dict = defaultdict(list)
        for go, script, _ in self.behaviours:
            if go and script in self.scripts:
                scripts_on[go].append(self.scripts[script])
        cache: dict = {}

        def place(go):
            if go not in cache:
                cache[go] = self._place(go)
            return cache[go]

        uses: dict = defaultdict(list)
        for target, via, go, script, own in self.links:
            material = self.material_names.get(target)
            if not material:
                continue
            path, source = place(go)
            holder = self.scripts.get(script, "") if script else ""
            # The game script that owns this object: on it, or on its nearest parent.
            owner = holder if _is_game_script(holder) else ""
            current, seen = go, set()
            while not owner and current and current not in seen:
                seen.add(current)
                owner = next((s for s in scripts_on.get(current, []) if _is_game_script(s)), "")
                parent = self.father_of.get(current)
                current = self.transform_go.get(parent) if parent else None
            uses[material].append({
                "via": f"{holder.rsplit('.', 1)[-1]}.{via}" if holder and via else holder or via,
                "object": path or own or holder, "source": source or self._scene_of(target[0]),
                "scripts": sorted(set(scripts_on.get(go, [])))[:6], "owner": owner})
        found["material_uses"] = {name: rows for name, rows in uses.items()}
        components: dict = defaultdict(list)
        for go, script, own in self.behaviours:
            name = self.scripts.get(script)
            if name:
                components[name].append(go)
        found["components"] = components
        found["place"] = place
        found["scripts_on"] = scripts_on

    def _place(self, go) -> tuple[str, str]:
        if go is None:
            return "", ""
        parts, current, seen, root = [], go, set(), go
        while current and current not in seen:
            seen.add(current)
            parts.append(self.names.get(current, "?"))
            root = current
            parent = self.father_of.get(current)
            current = self.transform_go.get(parent) if parent else None
        path = "/".join(reversed(parts))
        if root in self.container:
            return path, self.container[root]
        source = self._scene_of(root[0])
        if source.startswith("Scene "):
            return path, source
        # A prefab referenced straight from a scene has no container path; name it by its root.
        where = root[0] if root[0].endswith(".assets") else source
        return path, f"Prefab {self.names.get(root, '?')} · {where}"


def _code_usage(job: Path) -> tuple[dict[str, set[str]], dict[str, dict[str, set[str]]], list[str]]:
    """Types per technology, game classes using each technology, unrecognised SDK assemblies."""
    database = job / "methods.sqlite"
    if not database.is_file():
        return {}, {}, []
    from .assemblies import assembly_category, resolver_for_job, type_key
    connection = sqlite3.connect(database)
    try:
        resolver = resolver_for_job(job, connection)
        names = [name for (name,) in connection.execute("SELECT DISTINCT class_name FROM methods")]
        assemblies = resolver.assembly_map
        all_keys = set(assemblies) | {type_key(name) for name in names}

        def tech_of(key: str, assembly: str | None = None) -> str | None:
            for tech, pattern in _NS:
                if pattern.match(key):
                    return tech.name
            assembly = assembly or assemblies.get(key)
            if assembly:
                for tech in TECHS:
                    regex = _COMPILED[tech.name].get("asm")
                    if regex and regex.fullmatch(assembly):
                        return tech.name
            return None

        tech_types: dict[str, set[str]] = defaultdict(set)
        owner: dict[str, str | None] = {}
        simple_owner: dict[str, set] = defaultdict(set)
        for key in all_keys:
            tech = tech_of(key)
            owner[key] = tech
            if tech:
                tech_types[tech].add(key)
            simple_owner[re.split(r"[.+]", key)[-1]].add(tech)
        known = {assembly for key, assembly in assemblies.items() if owner.get(key)}
        unknown = sorted({assembly for assembly in assemblies.values() if assembly not in known
                          and assembly_category(assembly, resolver.studio_tokens) == "sdk"
                          and not assembly.startswith("Assembly-CSharp")})

        usage: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
        game_classes = {name for name in names
                        if resolver.category(name) == "game" and owner.get(type_key(name)) is None}
        for class_name, signature in connection.execute("SELECT class_name, signature FROM methods"):
            if class_name not in game_classes:
                continue
            outer = class_name.split("+", 1)[0]
            for dotted in _DOTTED.findall(signature.split("::", 1)[-1] + " " + signature.split(" ", 1)[0]):
                if _BORING_TYPES.match(dotted):
                    continue
                key = type_key(dotted)
                tech = owner.get(key, None) if key in owner else tech_of(key)
                if tech:
                    usage[tech][outer].add(key.rsplit(".", 1)[-1])
    finally:
        connection.close()
    _stub_usage(job, simple_owner, usage)
    return tech_types, usage, unknown


def _stub_usage(job: Path, simple_owner: dict[str, set], usage) -> None:
    """Fields and base classes from Cpp2IL's C# stubs of the game assemblies."""
    root = job / "cpp2il_types" / "DiffableCs"
    report = job / "assemblies.json"
    if not root.is_dir() or not report.is_file():
        return
    game_assemblies = {row["assembly"] for row in json.loads(report.read_text(encoding="utf-8"))["assemblies"]
                       if row["category"] == "game"}
    unique = {name: next(iter(techs)) for name, techs in simple_owner.items()
              if len(name) >= 4 and len(techs) == 1 and None not in techs}
    word = re.compile(r"[A-Za-z_]\w+")
    for assembly in game_assemblies:
        folder = root / assembly
        if not folder.is_dir():
            continue
        for path in folder.rglob("*.cs"):
            outer = ".".join(path.relative_to(folder).with_suffix("").parts).split("`", 1)[0]
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for line in text.splitlines():
                code = line.split("//", 1)[0].split("=", 1)[0].strip().rstrip(";")
                if "Field offset" in line:
                    # "private List<SplineComputer> roads" -> the type part only, never the field name.
                    code = re.sub(r"<[^<>]*>k__BackingField", "", code).rsplit(" ", 1)[0]
                elif re.match(r"(\w+\s+)*(class|struct)\s+\S+.*?:", code):
                    code = code.split(":", 1)[1]
                else:
                    continue
                for token in word.findall(code):
                    tech = unique.get(token)
                    if tech:
                        usage[tech][outer].add(token)


def _shader_owner(name: str, present: set[str]) -> str | None:
    for tech in TECHS:
        compiled = _COMPILED[tech.name]
        if "shader" in compiled and compiled["shader"].search(name):
            return tech.name
        if tech.name in present and "shader_weak" in compiled and compiled["shader_weak"].search(name):
            return tech.name
    return None


def _shader_hints(name: str, properties: list[str]) -> list[str]:
    return [hint for by_name, by_prop, hint in _SHADER_HINTS
            if by_name.search(name) or (by_prop and any(by_prop.search(p) for p in properties))]


def scan_tech_stack(job: Path, emit=print, cancel=None) -> dict:
    job = Path(job)
    emit("Công nghệ: đang nhận diện engine, thư viện, SDK và shader...")
    found = _scan_archives(_job_apks(job), emit, cancel)
    tech_types, usage, unknown_assemblies = _code_usage(job)

    evidence: dict[str, list[str]] = defaultdict(list)
    packages = sorted(found["dex_packages"])
    for tech in TECHS:
        compiled = _COMPILED[tech.name]
        if "native" in compiled:
            libs = [lib for lib in sorted(found["native"]) if compiled["native"].fullmatch(lib)]
            if libs:
                evidence[tech.name].append("Thư viện native: " + ", ".join(libs))
        if "dex" in compiled:
            hits = sorted({p for p in packages if compiled["dex"].match(p)})
            if hits:
                roots = sorted({compiled["dex"].match(p).group(0) for p in hits})
                evidence[tech.name].append(f"Java (dex): {', '.join(r.replace('/', '.') for r in roots[:4])}"
                                           f" — {len(hits)} package")
        if "asset" in compiled:
            hits = [a for a in found["assets"] if compiled["asset"].search(a)]
            if hits:
                evidence[tech.name].append(f"File trong APK: {hits[0]}" + (f" (+{len(hits) - 1})" if len(hits) > 1 else ""))
        if tech.name in tech_types:
            types = tech_types[tech.name]
            namespaces = sorted({t.rsplit(".", 1)[0] for t in types if "." in t})
            evidence[tech.name].append(f"C# IL2CPP: {len(types)} kiểu" +
                                       (f", namespace {', '.join(namespaces[:3])}" if namespaces else ""))

    from .asset_purpose import Vocabulary, describe, features
    material_uses = found.get("material_uses", {})
    vocabulary = Vocabulary(job)
    shaders = []
    for name, entry in sorted(found["shaders"].items()):
        owner = _shader_owner(name, {key for key, lines in evidence.items() if lines}) or ("Unity (có sẵn)" if BUILTIN_SHADER.match(name) else "Shader riêng của game")
        materials = sorted(entry["materials"])
        shaders.append({"name": name, "owner": owner, "hints": _shader_hints(name, entry["properties"]),
                        "properties": entry["properties"][:40], "materials": materials[:40],
                        "material_count": len(materials), "files": sorted(entry["files"])[:5],
                        "material_uses": {m: {"count": len(material_uses.get(m, [])),
                                              "uses": _dedupe(material_uses.get(m, []))[:MAX_USES],
                                              "purpose": describe(m, material_uses.get(m, []), vocabulary)}
                                          for m in materials[:40]}})
        if owner in _COMPILED:
            evidence[owner].append(f"Shader: {name}")

    # Scripts attached to GameObjects: library components count as evidence too.
    components, place = found.get("components", {}), found.get("place", lambda go: ("", ""))
    tech_components: dict[str, list[dict]] = defaultdict(list)
    game_components = []
    for script, owners in sorted(components.items(), key=lambda item: -len(item[1])):
        tech = next((t.name for t, pattern in _NS if pattern.match(script)), None)
        row = {"script": script, "count": len(owners),
               "objects": _dedupe([dict(zip(("object", "source"), place(go))) for go in owners if go])[:8]}
        if tech:
            tech_components[tech].append(row)
        elif not script.startswith(("UnityEngine.", "Unity.", "TMPro.", "System.")):
            game_components.append(row)
    for tech, rows in tech_components.items():
        evidence[tech].append(f"Component trên object: {sum(r['count'] for r in rows)} "
                              f"({', '.join(r['script'].rsplit('.', 1)[-1] for r in rows[:3])})")
    sources: dict[str, dict] = {}
    for script, owners in components.items():
        for go in owners:
            if not go:
                continue
            source = place(go)[1]
            entry = sources.setdefault(source, {"source": source, "scripts": defaultdict(int), "materials": set()})
            entry["scripts"][script] += 1
    for material, rows in material_uses.items():
        for row in rows:
            if row["source"] in sources:
                sources[row["source"]]["materials"].add(material)
    scenes = [{"source": entry["source"],
               "components": sum(entry["scripts"].values()),
               "scripts": sorted(entry["scripts"].items(), key=lambda item: -item[1])[:40],
               "materials": sorted(entry["materials"])[:60]}
              for entry in sorted(sources.values(), key=lambda e: (not e["source"].startswith("Scene"), e["source"]))]

    technologies = []
    for tech in TECHS:
        if not evidence.get(tech.name):
            continue
        classes = usage.get(tech.name, {})
        ranked = sorted(classes.items(), key=lambda item: (-len(item[1]), item[0]))
        technologies.append({
            "name": tech.name, "group": tech.group, "purpose": tech.purpose,
            "evidence": _squash_shaders(evidence[tech.name]),
            "usage_total": len(classes),
            "usage": [{"class": name, "types": sorted(types)[:8]} for name, types in ranked[:MAX_USAGE_CLASSES]],
            "shaders": [s["name"] for s in shaders if s["owner"] == tech.name],
            "components": tech_components.get(tech.name, [])[:20],
        })

    present = {t["name"] for t in technologies}
    engine = next((t for t in ("Unity", "Unreal Engine", "Cocos2d-x / Cocos Creator", "Godot", "GameMaker",
                               "Defold", "Solar2D (Corona)", "libGDX", "Flutter", "React Native",
                               "Xamarin / .NET MAUI", "Cordova / WebView game") if t in present), None)
    unity = {}
    if engine == "Unity" or "Unity IL2CPP" in present:
        engine = "Unity"
        unity = {
            "version": found["unity_version"] or _job_value(job, "unity_version"),
            "scripting_backend": "IL2CPP" if "Unity IL2CPP" in present else "Mono" if "Unity Mono" in present else None,
            "render_pipeline": ("URP" if "Universal Render Pipeline (URP)" in present else
                                "HDRP" if "High Definition Render Pipeline (HDRP)" in present else "Built-in"),
        }
    result = {
        "version": 1,
        "package": _job_value(job, "package_name"),
        "engine": {"name": engine or "Android (Java/Kotlin)", **unity},
        "technologies": technologies,
        "unrecognized_assemblies": unknown_assemblies,
        "shaders": shaders,
        "game_components": game_components[:300],
        "features": features(material_uses, vocabulary),
        "scenes": scenes,
        "native_libraries": sorted(found["native"]),
    }
    (job / "tech_stack.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    custom = sum(1 for s in shaders if s["owner"] == "Shader riêng của game")
    emit(f"Công nghệ: {engine or 'Android'} · {len(technologies)} công nghệ/SDK · {len(shaders)} shader "
         f"({custom} shader riêng của game). Chi tiết: tab Công nghệ / tech_stack.json")
    return result


def _dedupe(rows: list[dict]) -> list[dict]:
    seen, unique = set(), []
    for row in rows:
        marker = json.dumps(row, sort_keys=True, ensure_ascii=False)
        if marker not in seen:
            seen.add(marker)
            unique.append(row)
    return unique


def _squash_shaders(lines: list[str]) -> list[str]:
    shaders = [line[len("Shader: "):] for line in lines if line.startswith("Shader: ")]
    rest = [line for line in lines if not line.startswith("Shader: ")]
    if shaders:
        rest.append(f"Shader ({len(shaders)}): " + ", ".join(shaders[:4]) + (" ..." if len(shaders) > 4 else ""))
    return rest


def _job_value(job: Path, key: str):
    try:
        return json.loads((job / "job.json").read_text(encoding="utf-8")).get(key)
    except (OSError, ValueError):
        return None
