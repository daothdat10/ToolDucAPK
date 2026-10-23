"""Decode FlatBuffers level TextAssets using the schema recovered from dump.cs.

Unity games that use FlatBuffers ship generated C# accessors (``struct X :
IFlatbufferObject``). Il2CppDumper keeps those accessors in dump.cs, so the
schema (field order, types, enums, root tables) can be rebuilt without the
original .fbs file. The vtable slot of each table field is read from the ARM64
accessor (``mov w1, #slot`` before ``Table.__offset``); when that fails the
declaration order is used, which matches flatc output unless fields were
deprecated.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
import re
import struct
import threading
from typing import Any
import zipfile

SCALARS = {
    "bool": ("<?", 1), "sbyte": ("<b", 1), "byte": ("<B", 1),
    "short": ("<h", 2), "ushort": ("<H", 2), "int": ("<i", 4), "uint": ("<I", 4),
    "long": ("<q", 8), "ulong": ("<Q", 8), "float": ("<f", 4), "double": ("<d", 8),
}
MAX_DEPTH = 32
MAX_VECTOR = 1_000_000
# Accessors that are not schema fields.
_SKIP_METHODS = {"__init", "__assign", "get_ByteBuffer", "ValidateVersion", "UnPack", "UnPackTo",
                 "Pack", "Equals", "GetHashCode", "ToString"}

_NAMESPACE = re.compile(r"^// Namespace: ?(.*)$")
_FLAT_STRUCT = re.compile(r"^(?:public|internal) struct (\w+) : (?:[\w.]+, )*IFlatbufferObject\b")
_ENUM = re.compile(r"^(?:public|internal) enum (\w+)\b")
_ENUM_CONST = re.compile(r"^\tpublic const \w+ (\w+) = (-?\d+);")
_RVA = re.compile(r"^\t// RVA: 0x[0-9A-Fa-f]+ Offset: (0x[0-9A-Fa-f]+)")
_METHOD = re.compile(r"^\tpublic (static )?(.+?) (\w+)(<\w+>)?\(([^)]*)\) \{ \}")


class FlatbufferError(ValueError):
    pass


@dataclass
class FieldDef:
    name: str
    type_name: str
    vector: bool = False
    union: bool = False
    offset: int | None = None   # file offset of the accessor in libil2cpp.so
    slot: int | None = None     # table: vtable slot index; struct: byte offset


@dataclass
class TypeDef:
    name: str
    namespace: str
    is_struct: bool
    root: bool = False
    fields: list[FieldDef] = field(default_factory=list)
    size: int = 0
    align: int = 1

    @property
    def full_name(self) -> str:
        return f"{self.namespace}.{self.name}" if self.namespace else self.name


@dataclass
class Schema:
    types: dict[str, TypeDef]
    enums: dict[str, tuple[str, dict[int, str]]]  # name -> (underlying, value -> name)
    slot_sources: dict[str, int] = field(default_factory=dict)

    def roots(self) -> list[TypeDef]:
        return [t for t in self.types.values() if t.root and not t.is_struct]


def _strip_nullable(type_name: str) -> str:
    match = re.fullmatch(r"Nullable<(.+)>", type_name)
    return match.group(1) if match else type_name


def parse_schema(dump_cs: Path) -> Schema:
    """Collect FlatBuffers tables/structs and enums from Il2CppDumper's dump.cs."""
    types: dict[str, TypeDef] = {}
    enums: dict[str, tuple[str, dict[int, str]]] = {}
    namespace = ""
    current: TypeDef | None = None
    enum_name: str | None = None
    enum_type = "int"
    enum_values: dict[int, str] = {}
    pending_offset: int | None = None
    methods: list[tuple[str, str, str, bool, str, int | None]] = []
    with dump_cs.open("r", encoding="utf-8-sig", errors="replace") as source:
        for line in source:
            line = line.rstrip("\r\n")
            match = _NAMESPACE.match(line)
            if match:
                namespace = match.group(1).strip()
                continue
            if current is None and enum_name is None:
                match = _FLAT_STRUCT.match(line)
                if match:
                    current = TypeDef(match.group(1), namespace, is_struct=False)
                    methods = []
                    pending_offset = None
                    continue
                match = _ENUM.match(line)
                if match:
                    enum_name, enum_type, enum_values = match.group(1), "int", {}
                continue
            if enum_name is not None:
                if line.startswith("}"):
                    enums.setdefault(enum_name, (enum_type, enum_values))
                    enum_name = None
                elif "value__;" in line:
                    enum_type = line.split()[1]
                else:
                    match = _ENUM_CONST.match(line)
                    if match:
                        enum_values.setdefault(int(match.group(2)), match.group(1))
                continue
            # Inside a FlatBuffers struct/table.
            if line.startswith("}"):
                _finish_type(current, methods)
                types.setdefault(current.name, current)
                current = None
                continue
            if "Struct __p;" in line:
                current.is_struct = True
                continue
            match = _RVA.match(line)
            if match:
                pending_offset = int(match.group(1), 16)
                continue
            match = _METHOD.match(line)
            if match:
                is_static, ret, name, generic, params = match.groups()
                methods.append((ret, name, params.strip(), bool(is_static), generic or "", pending_offset))
                pending_offset = None
    return Schema(types, enums)


def _finish_type(type_def: TypeDef, methods: list) -> None:
    for ret, name, params, is_static, generic, offset in methods:
        if is_static:
            if name == f"GetRootAs{type_def.name}":
                type_def.root = True
            continue
        if (name in _SKIP_METHODS or name.startswith("Mutate") or name.endswith("ByKey")
                or (name.startswith("get_") and name.endswith("Length"))
                or re.fullmatch(r"Get\w+(Bytes|Array)", name)):
            continue
        if generic and not params:
            type_def.fields.append(FieldDef(name, "union", union=True, offset=offset))
        elif name.startswith("get_") and not params:
            type_def.fields.append(FieldDef(name[4:], _strip_nullable(ret), offset=offset))
        elif params == "int j":
            type_def.fields.append(FieldDef(name, _strip_nullable(ret), vector=True, offset=offset))


def _arm64_slot(binary: bytes, offset: int | None) -> int | None:
    """Find 'mov w1, #imm' (MOVZ) in the accessor prologue; imm is the vtable offset."""
    if offset is None or offset < 0 or offset + 4 > len(binary):
        return None
    for index in range(24):
        position = offset + index * 4
        if position + 4 > len(binary):
            break
        word = struct.unpack_from("<I", binary, position)[0]
        if (word & 0xFFE0001F) == 0x52800001:  # MOVZ W1, #imm16 (hw=0)
            value = (word >> 5) & 0xFFFF
            if value >= 4 and value % 2 == 0:
                return (value - 4) // 2
            return None
        if (word & 0xFC000000) == 0x94000000 or word == 0xD65F03C0:  # BL / RET
            return None
    return None


def resolve_layout(schema: Schema, binary: Path | None = None) -> Schema:
    """Assign table slots (ARM64 accessor or declaration order) and struct offsets."""
    data = binary.read_bytes() if binary is not None and binary.is_file() else b""
    from_code = from_order = 0
    for type_def in schema.types.values():
        if type_def.is_struct:
            continue
        used: set[int] = set()
        next_slot = 0
        for item in type_def.fields:
            slot = _arm64_slot(data, item.offset) if data else None
            if slot is not None and slot not in used:
                from_code += 1
            else:
                slot = next_slot
                while slot in used:
                    slot += 1
                from_order += 1
            item.slot = slot
            used.add(slot)
            next_slot = slot + 1
    for type_def in schema.types.values():
        if type_def.is_struct:
            _struct_layout(schema, type_def, set())
    schema.slot_sources = {"arm64": from_code, "declaration_order": from_order}
    return schema


def _scalar_type(schema: Schema, type_name: str) -> str | None:
    if type_name in SCALARS:
        return type_name
    enum = schema.enums.get(type_name.rsplit(".", 1)[-1])
    if enum and enum[0] in SCALARS:
        return enum[0]
    return None


def _struct_layout(schema: Schema, type_def: TypeDef, visiting: set[str]) -> None:
    if type_def.size or type_def.name in visiting:
        return
    visiting.add(type_def.name)
    position, align = 0, 1
    for item in type_def.fields:
        size, item_align = _inline_size(schema, item.type_name, visiting)
        position = (position + item_align - 1) // item_align * item_align
        item.slot = position
        position += size
        align = max(align, item_align)
    type_def.size = max(1, (position + align - 1) // align * align)
    type_def.align = align


def _inline_size(schema: Schema, type_name: str, visiting: set[str]) -> tuple[int, int]:
    scalar = _scalar_type(schema, type_name)
    if scalar:
        size = SCALARS[scalar][1]
        return size, size
    nested = schema.types.get(type_name.rsplit(".", 1)[-1])
    if nested and nested.is_struct:
        _struct_layout(schema, nested, visiting)
        return nested.size, nested.align
    raise FlatbufferError(f"unknown inline type {type_name}")


class _Decoder:
    def __init__(self, schema: Schema, data: bytes):
        self.schema = schema
        self.data = data
        self.fields_read = 0

    def _read(self, fmt: str, position: int):
        size = struct.calcsize(fmt)
        if position < 0 or position + size > len(self.data):
            raise FlatbufferError("read out of bounds")
        return struct.unpack_from(fmt, self.data, position)[0]

    def _deref(self, position: int) -> int:
        target = position + self._read("<I", position)
        if target >= len(self.data):
            raise FlatbufferError("offset out of bounds")
        return target

    def _scalar(self, type_name: str, position: int):
        scalar = _scalar_type(self.schema, type_name)
        value = self._read(SCALARS[scalar][0], position)
        enum = self.schema.enums.get(type_name.rsplit(".", 1)[-1])
        if enum and type_name not in SCALARS:
            return enum[1].get(value, value)
        if isinstance(value, float) and value != value:
            raise FlatbufferError("NaN")
        return value

    def _string(self, position: int) -> str:
        start = self._deref(position)
        length = self._read("<I", start)
        if start + 4 + length > len(self.data):
            raise FlatbufferError("string out of bounds")
        try:
            return self.data[start + 4:start + 4 + length].decode("utf-8")
        except UnicodeDecodeError as error:
            raise FlatbufferError("invalid UTF-8") from error

    def table(self, type_def: TypeDef, position: int, depth: int = 0) -> dict[str, Any]:
        if depth > MAX_DEPTH:
            raise FlatbufferError("nesting too deep")
        vtable = position - self._read("<i", position)
        vtable_size = self._read("<H", vtable)
        table_size = self._read("<H", vtable + 2)
        if vtable_size < 4 or vtable_size % 2 or vtable + vtable_size > len(self.data) \
                or position + table_size > len(self.data):
            raise FlatbufferError("bad vtable")
        schema_slots = max((f.slot or 0) for f in type_def.fields) + 1 if type_def.fields else 0
        if (vtable_size - 4) // 2 > schema_slots:
            raise FlatbufferError("vtable has more fields than the schema")
        result: dict[str, Any] = {}
        for item in type_def.fields:
            entry = 4 + 2 * item.slot
            if entry + 2 > vtable_size:
                continue
            relative = self._read("<H", vtable + entry)
            if not relative:
                continue
            if relative >= table_size:
                raise FlatbufferError("field outside table")
            result[item.name] = self._value(item, position + relative, depth)
            self.fields_read += 1
        return result

    def _value(self, item: FieldDef, position: int, depth: int):
        if item.union:
            return {"offset": self._deref(position)}
        if item.vector:
            start = self._deref(position)
            count = self._read("<I", start)
            if count > MAX_VECTOR:
                raise FlatbufferError("vector too long")
            return [self._element(item.type_name, start + 4, index, depth) for index in range(count)]
        return self._single(item.type_name, position, depth)

    def _element(self, type_name: str, start: int, index: int, depth: int):
        if type_name == "string":
            return self._string(start + 4 * index)
        scalar = _scalar_type(self.schema, type_name)
        if scalar:
            return self._scalar(type_name, start + SCALARS[scalar][1] * index)
        nested = self._type(type_name)
        if nested.is_struct:
            return self.struct(nested, start + nested.size * index)
        return self.table(nested, self._deref(start + 4 * index), depth + 1)

    def _single(self, type_name: str, position: int, depth: int):
        if type_name == "string":
            return self._string(position)
        if _scalar_type(self.schema, type_name):
            return self._scalar(type_name, position)
        nested = self._type(type_name)
        if nested.is_struct:
            return self.struct(nested, position)
        return self.table(nested, self._deref(position), depth + 1)

    def struct(self, type_def: TypeDef, position: int) -> dict[str, Any]:
        result = {}
        for item in type_def.fields:
            result[item.name] = self._single(item.type_name, position + item.slot, 0)
        return result

    def _type(self, type_name: str) -> TypeDef:
        found = self.schema.types.get(type_name.rsplit(".", 1)[-1])
        if found is None:
            raise FlatbufferError(f"unknown type {type_name}")
        return found


def decode(schema: Schema, data: bytes, root: TypeDef) -> tuple[dict[str, Any], int]:
    """Decode a whole buffer as `root`; returns (data, number of fields read)."""
    if len(data) < 8:
        raise FlatbufferError("too small")
    decoder = _Decoder(schema, data)
    value = decoder.table(root, decoder._deref(0))
    return value, decoder.fields_read


def best_root(schema: Schema, data: bytes, preferred: TypeDef | None = None,
              candidates: list[TypeDef] | None = None) -> tuple[TypeDef, dict[str, Any]] | None:
    """Pick the root table that decodes the buffer cleanly and reads the most fields."""
    if preferred is not None:
        try:
            value, count = decode(schema, data, preferred)
            if count:
                return preferred, value
        except (FlatbufferError, struct.error, RecursionError):
            pass
    best = None
    for root in candidates if candidates is not None else schema.roots():
        try:
            value, count = decode(schema, data, root)
        except (FlatbufferError, struct.error, RecursionError):
            continue
        # Prefer more decoded fields, then the schema whose field count fits the vtable best.
        key = (count, -len(root.fields))
        if count and (best is None or key > best[0]):
            best = (key, root, value)
    return (best[1], best[2]) if best else None


def _group_of(asset_name: str) -> tuple[str, int | None]:
    """'12' -> ('levels', 12); 'story-3' -> ('story', 3); other names keep their pattern."""
    numbers = re.findall(r"\d+", asset_name)
    pattern = re.sub(r"\d+", "#", asset_name)
    group = re.sub(r"[#_\-\s]+", "_", pattern).strip("_") or "levels"
    return group, int(numbers[0]) if len(numbers) == 1 else None


def extract_flatbuffer_levels(apk_paths: list[Path], job: Path, emit,
                              cancel: threading.Event) -> int:
    """Export FlatBuffers TextAssets whose root table is a level type into levels/."""
    from .levels import (LevelScanCancelled, _bundle_text_assets, _decrypt_yooasset_bundle,
                         _is_unity_bundle_candidate, _json_ready, _safe_folder_name)

    dump_cs = job / "il2cppdumper" / "dump.cs"
    if not dump_cs.is_file():
        return 0
    schema = parse_schema(dump_cs)
    level_roots = [root for root in schema.roots() if "level" in root.name.lower()]
    if not level_roots:
        return 0
    resolve_layout(schema, job / "input" / "libil2cpp.so")
    emit(f"FlatBuffers: dựng lại schema từ dump.cs: {len(schema.types):,} kiểu, "
         f"{len(level_roots)} kiểu gốc level ({', '.join(r.name for r in level_roots[:6])}); "
         f"slot lấy từ mã ARM64: {schema.slot_sources['arm64']:,}, theo thứ tự khai báo: "
         f"{schema.slot_sources['declaration_order']:,}")

    groups: dict[tuple[str, str], dict[str, Any]] = {}
    preferred: dict[str, TypeDef] = {}
    exported = 0
    for apk_path in apk_paths:
        if not apk_path.is_file():
            continue
        with zipfile.ZipFile(apk_path) as archive:
            for info in archive.infolist():
                if cancel.is_set():
                    raise LevelScanCancelled("Đã dừng khi quét level FlatBuffers.")
                if not _is_unity_bundle_candidate(info):
                    continue
                try:
                    bundle, _ = _decrypt_yooasset_bundle(archive.read(info), None)
                    text_assets = _bundle_text_assets(bundle)
                except Exception:
                    continue
                bundle_key = _safe_folder_name(Path(info.filename).stem)
                for asset_name, raw in text_assets:
                    if not raw or raw[:1] in (b"{", b"[", b"<"):
                        continue
                    group_name, number = _group_of(asset_name)
                    found = best_root(schema, raw, preferred.get(group_name), level_roots)
                    if found is None:
                        continue
                    root, value = found
                    preferred[group_name] = root
                    key = (bundle_key, group_name)
                    group = groups.setdefault(key, {
                        "bundle": Path(info.filename).name, "name": group_name,
                        "source_format": f"FlatBuffers/{root.full_name}", "levels": []})
                    file_name = f"Level {number}.json" if number is not None \
                        else f"{_safe_folder_name(asset_name)}.json"
                    relative = Path("levels") / bundle_key / group_name / file_name
                    document = {"format": "ducapk-flatbuffers-level-v1", "asset_name": asset_name,
                                "root_type": root.full_name, "bundle": Path(info.filename).name,
                                "data": value}
                    path = job / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(json.dumps(_json_ready(document), ensure_ascii=False, indent=1),
                                    encoding="utf-8")
                    group["levels"].append({"name": asset_name, "export_name": file_name[:-5],
                                            "level_number": number, "file": relative.as_posix()})
                    exported += 1
    if not exported:
        emit("FlatBuffers: có schema level nhưng không TextAsset nào khớp.")
        return 0

    manifest_path = job / "levels.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        manifest = {"format": "ducapk-unity-puzzles-v9", "summary": {}, "export_root": "levels",
                    "groups": [], "notes": []}
    manifest["groups"] = [g for g in manifest.get("groups", [])
                          if not str(g.get("source_format", "")).startswith("FlatBuffers/")]
    for group in groups.values():
        group["levels"].sort(key=lambda level: (level["level_number"] is None,
                                                level["level_number"] or 0, level["name"]))
        group["listed_puzzles"] = group["exported_puzzles"] = len(group["levels"])
        group["missing_puzzles"] = 0
        manifest["groups"].append(group)
    summary = manifest.setdefault("summary", {})
    summary["flatbuffers_levels_exported"] = exported
    summary["flatbuffers_slot_sources"] = schema.slot_sources
    summary["real_puzzle_layouts_exported"] = sum(
        len(g.get("levels", [])) for g in manifest["groups"] if isinstance(g, dict))
    summary["groups_found"] = len(manifest["groups"])
    notes = manifest.setdefault("notes", [])
    note = ("FlatBuffers levels: schema rebuilt from dump.cs (IFlatbufferObject accessors); table "
            "slots come from the ARM64 accessor code, falling back to declaration order. Only fields "
            "present in each buffer are written; absent fields use the schema default.")
    if note not in notes:
        notes.append(note)
    manifest_path.write_text(json.dumps(_json_ready(manifest), ensure_ascii=False, indent=2),
                             encoding="utf-8")
    emit(f"FlatBuffers: đã xuất {exported:,} level JSON trong {len(groups)} nhóm "
         f"({', '.join(g['name'] + ': ' + format(len(g['levels']), ',') for g in groups.values())})")
    return exported
