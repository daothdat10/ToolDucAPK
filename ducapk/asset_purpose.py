"""What an asset (a material and the objects it is attached to) is for in the game.

Three kinds of evidence, all from the APK:
* area: interface (Screen/Modal/... prefabs, UI folders), effect (Fx/VFX/Particle roots) or gameplay;
* the game script that owns the object (on the object itself or its nearest parent);
* level mechanics from LevelModel.cs (GunData.IceHp, GunObstacleType.Dynamite, CookieBlockerData...)
  whose words appear in the object path or the asset name ("Gun/.../Ice/..." -> GunData.IceHp).
Matches by name are hints, shown as such.
"""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

_WORD = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+")
# Words that name structure, not meaning.
_GENERIC = {
    "data", "datas", "id", "ids", "count", "index", "is", "require", "required", "the", "of", "new", "root",
    "visual", "visuals", "base", "container", "wrap", "group", "image", "img", "bg", "icon", "text", "txt", "obj",
    "item", "items", "holder", "content", "mat", "material", "default", "mobile", "no", "ui", "safe", "area",
    "button", "btn", "panel", "view", "left", "right", "top", "bottom", "main", "game", "level", "levels", "type",
    "start", "end", "pos", "position", "positions", "size", "x", "y", "z", "none", "normal", "info", "list",
    "core", "play", "gameplay", "manager", "controller", "global", "enum", "model", "layer", "frame", "mask",
    "sprite", "mesh", "renderer", "object", "prefab", "clone", "copy", "elements", "element", "fill", "outline",
    "shadow", "glow", "light", "dark", "white", "black", "move", "on", "in", "out", "to", "and", "for", "with",
}
COMMON_WORD_LABELS = 4
UI_ROOT = re.compile(r"^(Screen|Modal|Activity|Popup|Panel|Canvas|Dialog|Window|Page|Hud|HUD|UI)", re.I)
FX_ROOT = re.compile(r"^(Fx|VFX|Particle|Effect|Confetti)", re.I)


def words(text: str) -> list[str]:
    result = []
    for word in _WORD.findall(text or ""):
        word = word.lower()
        if len(word) > 3 and word.endswith("s") and not word.endswith("ss"):
            word = word[:-1]
        if len(word) >= 3 and word not in _GENERIC:
            result.append(word)
    return result


class Vocabulary:
    """Level mechanics (classes, fields, enum members) from the job's LevelModel.cs."""

    def __init__(self, job: Path):
        self.labels: dict[str, list[str]] = {}  # label -> its words
        model = job / "LevelModel.cs"
        if not model.is_file():
            return
        current, kind = None, None
        for line in model.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            declaration = re.match(r"public (class|enum) (\w+)", line)
            if declaration:
                kind, current = declaration.groups()
                if kind == "class" and current != "LevelModel":
                    self._add(re.sub(r"Data$", "", current), current)
                continue
            field = re.match(r"public [\w\[\]<>,. ]+ (\w+);", line)
            # Root fields (LevelModel.HungryDoors) only repeat the classes they hold.
            if field and current and kind == "class" and current != "LevelModel":
                self._add(field.group(1), f"{current}.{field.group(1)}")
            member = re.match(r"(\w+)\s*=\s*\d+,?$", line)
            if member and current and kind == "enum" and member.group(1) not in ("None", "Normal"):
                self._add(member.group(1), f"{current}.{member.group(1)}")

        # A word in many mechanics ("gun" in a gun game) says nothing on its own.
        frequency = Counter(token for tokens in self.labels.values() for token in set(tokens))
        self.common = {token for token, count in frequency.items() if count >= COMMON_WORD_LABELS}

    def _add(self, name: str, label: str) -> None:
        tokens = words(name)
        if tokens:
            self.labels[label] = tokens

    def match(self, text_words: set[str]) -> list[str]:
        """Mechanics whose words mostly appear in the given words, most specific first."""
        found = []
        for label, tokens in self.labels.items():
            hits = [token for token in tokens if token in text_words]
            if hits and len(hits) * 2 >= len(tokens) and any(token not in self.common for token in hits):
                found.append((-len(hits), "." not in label, label))
        return [label for *_, label in sorted(found)][:4]


def area(source: str, path: str) -> str:
    root = path.split("/", 1)[0]
    if re.search(r"(^|/)UI/", source) or UI_ROOT.match(root):
        return "Giao diện (UI)"
    if FX_ROOT.match(root) or re.search(r"(^|/)(Fx|VFX|Effects?)/", source, re.I):
        return "Hiệu ứng (FX)"
    if source.startswith("Scene ") or "GamePlay" in source or root:
        return "Gameplay / object trong game"
    return "Khác"


def describe(material: str, uses: list[dict], vocabulary: Vocabulary) -> dict:
    """Purpose of one material from where it is attached (or from its name when it is not)."""
    areas, owners, mechanics, roots = Counter(), Counter(), Counter(), Counter()
    for use in uses:
        where = area(use["source"], use["object"])
        areas[where] += 1
        if use.get("owner"):
            owners[use["owner"]] += 1
        roots[use["object"].split("/", 1)[0]] += 1
        if where != "Giao diện (UI)":  # screens reuse gameplay words in button and label names
            for label in vocabulary.match(set(words(use["object"])) | set(words(material))):
                mechanics[label] += 1
    if not uses:
        for label in vocabulary.match(set(words(material))):
            mechanics[label] += 1
    parts = []
    if areas:
        parts.append(" / ".join(name for name, _ in areas.most_common(2)))
    if owners:
        parts.append("script " + ", ".join(name.rsplit(".", 1)[-1] for name, _ in owners.most_common(2)))
    elif roots:
        parts.append("object " + ", ".join(name for name, _ in roots.most_common(2)))
    if mechanics:
        parts.append("cơ chế " + ", ".join(name for name, _ in mechanics.most_common(2)))
    if not uses:
        parts.append("không gắn trực tiếp trên object; có thể code nạp lúc chạy")
    return {"summary": " · ".join(parts), "areas": [n for n, _ in areas.most_common()],
            "owners": [n for n, _ in owners.most_common(5)], "mechanics": [n for n, _ in mechanics.most_common(5)],
            "guessed": not uses}


def features(material_uses: dict[str, list[dict]], vocabulary: Vocabulary) -> list[dict]:
    """Game features (mechanics, owning scripts, UI screens) and the materials/prefabs serving them."""
    index: dict[tuple[str, str], dict] = {}

    def add(kind: str, name: str, material: str, use: dict | None) -> None:
        entry = index.setdefault((kind, name), {"kind": kind, "name": name, "materials": set(), "sources": set(),
                                                "objects": []})
        entry["materials"].add(material)
        if use:
            entry["sources"].add(use["source"])
            if len(entry["objects"]) < 8 and use["object"] not in entry["objects"]:
                entry["objects"].append(use["object"])

    for material, uses in material_uses.items():
        for use in uses:
            ui = area(use["source"], use["object"]) == "Giao diện (UI)"
            if not ui:
                for label in vocabulary.match(set(words(use["object"])) | set(words(material))):
                    add("Cơ chế level", label, material, use)
            if use.get("owner"):
                add("Script game", use["owner"], material, use)
            elif ui:
                add("Màn hình UI", use["object"].split("/", 1)[0], material, use)
        if not uses:
            for label in vocabulary.match(set(words(material))):
                add("Cơ chế level", label, material, None)
    order = {"Cơ chế level": 0, "Script game": 1, "Màn hình UI": 2}
    rows = sorted(index.values(), key=lambda e: (order[e["kind"]], -len(e["materials"]), e["name"]))
    return [{"kind": e["kind"], "name": e["name"], "materials": sorted(e["materials"])[:60],
             "sources": sorted(e["sources"])[:30], "objects": e["objects"]} for e in rows]
