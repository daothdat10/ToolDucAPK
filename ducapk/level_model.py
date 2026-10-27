"""Write LevelModel.cs for the level JSON files DucAPK extracted from a game.

The JSON shape of every exported level is merged into one schema. When the job has
IL2CPP metadata, the game class whose serialized fields best cover the root JSON keys
is used as the model (real type names, enums and nested classes); JSON keys the class
does not declare, or the whole model when no class matches, are typed from the data.
"""

from __future__ import annotations

import json
import re
import threading
from pathlib import Path
from typing import Any

from .categories import category_for_class
from .level_editor import (SchemaBuilder, TypeLibrary, _is_serialized, _json_name, _load_apk_library,
                           ensure_cpp2il_types, render_leveldata_cs)

LEVEL_MODEL_FILE = "LevelModel.cs"
LEVEL_MODEL_ROOT = "LevelModel"
LEVEL_MODEL_NAMESPACE = "LevelModels"
# Share of root JSON keys a game class must declare to be taken as the level model.
MIN_ROOT_COVERAGE = 0.6
_INT32_MAX = 2 ** 31 - 1


class _Node:
    """Merged shape of every JSON value seen at one path."""

    def __init__(self):
        self.kinds: set[str] = set()
        self.fields: dict[str, _Node] = {}
        self.item: _Node | None = None
        self.objects = 0
        self.low = self.high = 0

    def add(self, value: Any) -> None:
        if value is None:
            self.kinds.add("null")
        elif isinstance(value, bool):
            self.kinds.add("bool")
        elif isinstance(value, int):
            self.kinds.add("int")
            self.low, self.high = min(self.low, value), max(self.high, value)
        elif isinstance(value, float):
            self.kinds.add("float")
        elif isinstance(value, str):
            self.kinds.add("string")
        elif isinstance(value, list):
            self.kinds.add("list")
            for item in value:
                if self.item is None:
                    self.item = _Node()
                self.item.add(item)
        elif isinstance(value, dict):
            self.kinds.add("object")
            self.objects += 1
            for key, item in value.items():
                self.fields.setdefault(str(key), _Node()).add(item)


def _level_records(job: Path) -> list[dict[str, Any]]:
    """The level dicts listed in levels.json (the decoded layout for wrapped puzzle documents)."""
    try:
        manifest = json.loads((job / "levels.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    records = []
    for group in manifest.get("groups", []) if isinstance(manifest, dict) else []:
        for level in group.get("levels", []) if isinstance(group, dict) else []:
            relative = Path(level["file"]) if isinstance(level, dict) and isinstance(level.get("file"), str) else None
            if relative is None or relative.is_absolute() or ".." in relative.parts:
                continue
            try:
                data = json.loads((job / relative).read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if isinstance(data, dict) and str(data.get("format", "")).startswith("ducapk-"):
                data = data.get("layout")
            if isinstance(data, dict):
                records.append(data)
    return records


def _identifier(key: str) -> str:
    name = re.sub(r"\W", "_", key)
    return f"_{name}" if not name or name[0].isdigit() else name


def _class_name(hint: str) -> str:
    words = re.findall(r"[A-Za-z0-9]+", hint) or ["Item"]
    name = "".join(word[:1].upper() + word[1:] for word in words)
    return f"_{name}" if name[0].isdigit() else name


def _singular(hint: str) -> str:
    for suffix, replacement in (("ies", "y"), ("Datas", "Data"), ("sses", "ss"), ("s", "")):
        if hint.endswith(suffix) and len(hint) > len(suffix) + 1:
            return hint[:-len(suffix)] + replacement
    return hint + "Item"


class _ModelWriter:
    def __init__(self, builder: SchemaBuilder):
        self.builder = builder
        self._visited: set[tuple[str, int]] = set()

    def _new_class(self, hint: str) -> str:
        name = _class_name(hint)
        taken = {item["name"] for item in self.builder.classes.values()}
        unique, index = name, 2
        while unique in taken:
            unique, index = f"{name}{index}", index + 1
        key = f"json:{unique}"
        self.builder.classes[key] = {"name": unique, "ns": "", "src": "json", "kind": "class", "fields": []}
        return key

    def describe(self, node: _Node | None, hint: str) -> dict[str, Any]:
        """Builder type description for a JSON-only value."""
        if node is None:
            return {"k": "raw", "cs": "object"}
        kinds = node.kinds - {"null"}
        if kinds == {"object"}:
            key = self._new_class(hint)
            self.builder.classes[key]["fields"] = [self._json_field(name, child, hint)
                                                   for name, child in node.fields.items()]
            description = {"k": "obj", "ref": key}
        elif kinds == {"list"}:
            description = {"k": "list", "of": self.describe(node.item, _singular(hint))}
        elif kinds == {"int"}:
            wide = node.high > _INT32_MAX or node.low < -_INT32_MAX - 1
            description = {"k": "int", "min": -2 ** 63 if wide else -2 ** 31, "max": 2 ** 63 - 1 if wide else _INT32_MAX}
        elif kinds and kinds <= {"int", "float"}:
            description = {"k": "float"}
        elif kinds in ({"bool"}, {"string"}):
            description = {"k": next(iter(kinds))}
        else:
            description = {"k": "raw", "cs": "object"}
        if "null" in node.kinds and kinds:
            description["nullable"] = True
        return description

    def _json_field(self, key: str, node: _Node, owner_hint: str) -> dict[str, Any]:
        hint = key if key[:1].isupper() else owner_hint + _class_name(key)
        return {"name": _identifier(key), "json": key, "cs": "", "type": self.describe(node, hint)}

    def reconcile(self, class_key: str, node: _Node) -> None:
        """Add JSON keys the game class lacks and walk into nested game classes."""
        if (class_key, id(node)) in self._visited:
            return
        self._visited.add((class_key, id(node)))
        item = self.builder.classes[class_key]
        if item["src"] in {"unity", "json"}:
            return
        by_json = {field["json"]: field for field in item["fields"]}
        for key, child in node.fields.items():
            field = by_json.get(key)
            if field is None:
                field = self._json_field(key, child, item["name"])
                field["comment"] = "Có trong JSON level nhưng class của game không khai báo; kiểu suy từ dữ liệu."
                item["fields"].append(field)
                continue
            description, value = field["type"], child
            while description["k"] == "list" and value is not None and value.item is not None:
                description, value = description["of"], value.item
            if description["k"] == "obj" and value is not None and value.fields:
                self.reconcile(description["ref"], value)
        if node.objects:
            for field in item["fields"]:
                if field["json"] not in node.fields and not field.get("comment"):
                    field["comment"] = "Không xuất hiện trong level nào đã trích."


def _game_root(apk: TypeLibrary, keys: set[str]) -> dict[str, Any] | None:
    """The game class whose serialized fields cover the most root JSON keys."""
    if len(keys) < 2:
        return None
    minimum = max(2, int(len(keys) * MIN_ROOT_COVERAGE + 0.999))
    best, best_score = None, None
    for name in apk.class_names_with_fields(keys, minimum):
        for item in apk.candidates(name):
            if item["kind"] not in {"class", "struct"}:
                continue
            fields = {_json_name(field) for field in item["fields"] if _is_serialized(field)}
            hits = len(keys & fields)
            if hits < minimum:
                continue
            score = (hits, category_for_class(item["key"]) == "game", -len(fields - keys), item["key"])
            if best_score is None or score > best_score:
                best, best_score = item, score
    return best


def write_level_model(job: Path, emit, cancel: threading.Event | None = None) -> Path | None:
    """Write <job>/LevelModel.cs from the exported levels; None when there are no JSON levels."""
    records = _level_records(job)
    if not records:
        return None
    root = _Node()
    for record in records:
        root.add(record)
    if (job / "input" / "libil2cpp.so").is_file():
        try:
            ensure_cpp2il_types(job, emit, cancel or threading.Event())
        except Exception as error:
            emit(f"Không tạo được kiểu Cpp2IL cho LevelModel: {error}")
    apk = _load_apk_library(job, emit)
    builder = SchemaBuilder(TypeLibrary("user"), apk)
    writer = _ModelWriter(builder)
    game_root = _game_root(apk, set(root.fields)) if apk.indexed else None
    if game_root is not None:
        root_key = builder.build(game_root)
        writer.reconcile(root_key, root)
        origin = f"class {game_root['qualified_name']} của game, đối chiếu với"
    else:
        root_key = writer.describe(root, LEVEL_MODEL_ROOT)["ref"]
        origin = "suy hoàn toàn từ"
    added = sum(1 for item in builder.classes.values() for field in item["fields"]
                if field.get("comment", "").startswith("Có trong JSON"))
    header = (f"// Sinh tự động bởi DucAPK cho {job.name}: {origin} {len(records):,} file level JSON đã trích.\n"
              "// Deserialize mỗi file levels/**/Level N.json thành class gốc bên dưới (Newtonsoft.Json hoặc JsonUtility).\n"
              "// Kiểm tra và chỉnh trước khi dùng trong project của bạn.\n")
    output = job / LEVEL_MODEL_FILE
    output.write_text(render_leveldata_cs(builder, root_key, job.name, LEVEL_MODEL_NAMESPACE, header),
                      encoding="utf-8")
    root_name = builder.classes[root_key]["name"]
    emit(f"Đã viết {LEVEL_MODEL_FILE}: class gốc {root_name} "
         f"({'từ metadata game' if game_root else 'suy từ JSON'}), {len(builder.classes)} class, "
         f"{len(builder.enums)} enum" + (f", thêm {added} field chỉ có trong JSON" if added else "")
         + f" → {output}")
    return output
