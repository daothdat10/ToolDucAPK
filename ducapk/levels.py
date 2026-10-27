"""Extract real puzzle layouts from Unity's packed Puzzle AssetBundles."""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import re
import shutil
import struct
import threading
from pathlib import Path
from typing import Any
import zipfile

import UnityPy

try:
    from Crypto.Cipher import AES
except ImportError:  # pragma: no cover - reported when a protected manifest is present
    AES = None


PUZZLE_BUNDLE_PREFIX = "assets/assetbundles/puzzles/"
UNITY_BUNDLE_SUFFIXES = (".unity3d", ".bundle", ".assetbundle", ".ab")
MAX_BUNDLE_BYTES = 256 * 1024 * 1024
_PACKAGE_MANIFEST_IV = bytes.fromhex("122f08311b260d37152a043c1e210a33")
# Java ad SDK (com.jh.configmanager) config assets: Base64 of AES-128-CBC with
# the StringFog-hidden API_KEY and a null IV string padded to "0" * 16.
_CONFIG_AES_KEYS = ((b"dobestadssdatseb", b"0" * 16),)
# YooAsset bundles marked LoadFromMemory are read past a len(name)+4 byte
# prefix and decrypted by the game's XXTEA variant (BRVf) with this key as
# UTF-16LE text.
_MEMORY_BUNDLE_XXTEA_KEY = "WeDoBest"
# CoreData.LevelDataSerializer.Decrypt (Colony Flow): Base64, undo the in-place
# Swap(i, (7 * i + 3) % n) shuffle from the last byte down, AES-128-CBC with the
# GetKey/GetIV string literals as UTF-8, then GZip when the 1f8b magic is present.
_SWAP_AES_LEVEL_KEYS = ((b"6681430495957593", b"3870689237711935"),)
_XXTEA_DELTA = 0x9E3779B9


class LevelScanCancelled(Exception):
    pass


class MessagePackError(ValueError):
    pass


_JUICETIME_GROUP_STATUS = {
    0: "Normal", 1: "Cover", 2: "Wire", 3: "BigBottle",
}
_JUICETIME_SKEWER_STATUS = {
    -1: "Empty", 0: "Normal", 1: "Covered", 2: "Freezed1",
    3: "Freezed2", 4: "Freezed3", 5: "SugarPaper",
    6: "Freezed4", 7: "Freezed5",
}
_JUICETIME_LAYER_STATUS = {0: "Normal", 1: "Covered"}


def _normalize_juicetime_skewer_status(raw_status: int) -> int:
    status_id = raw_status // 100 if raw_status > 99 else raw_status
    if status_id not in _JUICETIME_SKEWER_STATUS:
        return 0
    # The game's parser contains a compatibility remap for legacy value 4.
    return 7 if status_id == 4 else status_id


def _split_juicetime_ints(value: str, delimiter: str, field_name: str) -> list[int]:
    if value == "":
        return []
    try:
        return [int(part) for part in value.split(delimiter)]
    except ValueError as error:
        raise ValueError(f"{field_name} contains a non-integer value") from error


def _parse_juicetime_level_payload(payload: str) -> dict[str, Any] | None:
    """Decode the JuiceTimeLevelParser semicolon/pipe/colon/slash format.

    This adapter is deliberately shape-driven so it can be applied to any APK
    that embeds records using the same parser format. The original payload and
    unused trailing fields are retained verbatim by the caller.
    """
    fields = payload.split(";")
    if len(fields) < 11:
        return None
    try:
        numeric = [int(fields[index]) for index in range(6)]
        level_id, total_fruit_count, color_type_count, group_count, empty_group_count, skewer_height = numeric
        fruit_plate_count = int(fields[8])
        big_bottle_target_color = int(fields[9])
        big_bottle_capacity = int(fields[10])
    except ValueError:
        return None
    def optional_flag(index: int) -> bool:
        try:
            return len(fields) > index and int(fields[index]) == 1
        except ValueError:
            return False

    butterfly_enabled = optional_flag(11)
    has_bubble = optional_flag(12)
    if (level_id < 0 or min(total_fruit_count, color_type_count, group_count,
                            empty_group_count, skewer_height, fruit_plate_count,
                            big_bottle_target_color) < 0 or big_bottle_capacity < 1 or
            big_bottle_target_color < 1):
        return None
    color_rows = fields[6].split("|") if fields[6] else []
    group_rows = fields[7].split("|") if fields[7] else []
    # The game creates one group per serialized color/status row. Refuse to
    # fabricate missing rows; the caller will still preserve the raw record.
    expected_rows = group_count + empty_group_count
    if len(color_rows) != expected_rows or len(group_rows) != expected_rows:
        return None

    groups: list[dict[str, Any]] = []
    group_status_counts: dict[str, int] = {}
    skewer_status_counts: dict[str, int] = {}
    layer_status_counts: dict[str, int] = {}
    active_mechanics: set[str] = set()
    for group_index, (color_row, group_row) in enumerate(zip(color_rows, group_rows)):
        parts = group_row.split(":")
        if len(parts) < 4:
            return None
        try:
            group_status_id = int(parts[0])
            need_element = int(parts[1])
        except ValueError:
            return None
        if group_status_id not in _JUICETIME_GROUP_STATUS:
            return None
        group_status_name = _JUICETIME_GROUP_STATUS[group_status_id]
        group_status_counts[group_status_name] = group_status_counts.get(group_status_name, 0) + 1
        if group_status_id != 0:
            active_mechanics.add(group_status_name)

        if color_row == "#" and parts[2] == "#" and parts[3] == "#":
            groups.append({
                "index": group_index,
                "is_empty_group": True,
                "group_status": {"id": group_status_id, "name": group_status_name},
                "need_element": need_element,
                "special_sign_element": {"value": 0, "source": "native_default_unassigned"},
                "skewers": [],
                "skewer_statuses": [],
            })
            continue

        skewer_color_rows = color_row.split(",") if color_row else []
        skewer_status_values = _split_juicetime_ints(parts[2], ",", "skewer statuses")
        skewer_layer_rows = parts[3].split(",") if parts[3] else []
        skewers: list[dict[str, Any]] = []
        for skewer_index, color_stack in enumerate(skewer_color_rows):
            colors = _split_juicetime_ints(color_stack, "/", "colors")
            if len(colors) > skewer_height:
                return None
            raw_status = (skewer_status_values[skewer_index]
                          if skewer_index < len(skewer_status_values) else 0)
            sugar_paper_element = raw_status % 100 if raw_status > 99 else 0
            status_id = _normalize_juicetime_skewer_status(raw_status)
            status_name = _JUICETIME_SKEWER_STATUS[status_id]
            skewer_status_counts[status_name] = skewer_status_counts.get(status_name, 0) + 1
            if status_id not in (0, -1):
                active_mechanics.add(status_name)
            raw_layers = (_split_juicetime_ints(skewer_layer_rows[skewer_index], "/", "layer statuses")
                          if skewer_index < len(skewer_layer_rows) else [])
            if any(layer not in _JUICETIME_LAYER_STATUS for layer in raw_layers):
                return None
            for layer in raw_layers:
                layer_name = _JUICETIME_LAYER_STATUS[layer]
                layer_status_counts[layer_name] = layer_status_counts.get(layer_name, 0) + 1
                if layer != 0:
                    active_mechanics.add(layer_name)
            skewers.append({
                "capacity": skewer_height,
                "colors_bottom_to_top": colors,
                "layer_statuses": [
                    {"id": layer, "name": _JUICETIME_LAYER_STATUS[layer]}
                    for layer in raw_layers
                ],
                "status": {"raw_id": raw_status, "id": status_id, "name": status_name},
                "sugar_paper_element": sugar_paper_element,
            })
        if len(skewer_status_values) > len(skewers) or len(skewer_layer_rows) > len(skewers):
            return None
        groups.append({
            "index": group_index,
            "is_empty_group": False,
            "group_status": {"id": group_status_id,
                             "name": _JUICETIME_GROUP_STATUS[group_status_id]},
            "need_element": need_element,
            # The native parser never assigns SpecialSignElement; its default
            # value is zero. Flag this so it is not mistaken for serialized data.
            "special_sign_element": {"value": 0, "source": "native_default_unassigned"},
            "skewers": skewers,
            "skewer_statuses": [
                {"raw_id": status,
                 "sugar_paper_element": status % 100 if status > 99 else 0,
                 "id": _normalize_juicetime_skewer_status(status),
                 "name": _JUICETIME_SKEWER_STATUS[_normalize_juicetime_skewer_status(status)]}
                for status in skewer_status_values
            ],
        })

    return {
        "parser": "JuiceTimeLevelParser.TryParse",
        "parser_rva": "0xCA1B0C",
        "level_id": level_id,
        "total_fruit_count": total_fruit_count,
        "color_type_count": color_type_count,
        "group_count": group_count,
        "empty_group_count": empty_group_count,
        "skewer_height": skewer_height,
        "fruit_plate_count": min(fruit_plate_count, 5),
        "big_bottle_target_color": big_bottle_target_color,
        "big_bottle_capacity": big_bottle_capacity,
        "big_bottle_butterfly_enabled": butterfly_enabled,
        "has_bubble": has_bubble,
        "mechanic_summary": {
            "active_status_names": sorted(active_mechanics),
            "group_status_counts": group_status_counts,
            "skewer_status_counts": skewer_status_counts,
            "fruit_layer_status_counts": layer_status_counts,
        },
        "groups": groups,
        "unparsed_trailing_fields": fields[13:],
    }


def _enrich_juicetime_level_record(record: Any) -> bool:
    """Add verified parsed fields to an HDPK text record without dropping raw data."""
    if not isinstance(record, dict) or record.get("format") != "ducapk-hdpk-text-level-v1":
        return False
    payload = record.get("payload")
    if not isinstance(payload, str):
        return False
    decoded = _parse_juicetime_level_payload(payload)
    if decoded is None:
        record.pop("decoded_juicetime", None)
        return False
    record["decoded_juicetime"] = decoded
    record["semicolon_fields"] = payload.split(";")
    return True


def _enrich_existing_juicetime_exports(job: Path, manifest: dict[str, Any]) -> tuple[int, int]:
    """Post-process cached HDPK exports and return (decoded, checked) counts."""
    decoded_count = 0
    checked_count = 0
    changed_files: dict[Path, dict[str, Any]] = {}
    decoded_records: list[dict[str, Any]] = []
    for group in manifest.get("groups", []):
        if not isinstance(group, dict):
            continue
        for level in group.get("levels", []):
            if not isinstance(level, dict) or not isinstance(level.get("file"), str):
                continue
            relative = Path(level["file"])
            if relative.is_absolute() or ".." in relative.parts:
                continue
            path = job / relative
            try:
                record = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(record, dict) or record.get("format") != "ducapk-hdpk-text-level-v1":
                continue
            checked_count += 1
            if _enrich_juicetime_level_record(record):
                decoded_count += 1
                decoded_records.append(record)
                changed_files[path] = record
            elif "decoded_juicetime" in record:
                record.pop("decoded_juicetime", None)
                changed_files[path] = record
    for path, record in changed_files.items():
        path.write_text(json.dumps(_json_ready(record), ensure_ascii=False, indent=2),
                        encoding="utf-8")
    summary = manifest.setdefault("summary", {})
    if isinstance(summary, dict):
        summary["juicetime_level_records_checked"] = checked_count
        summary["juicetime_level_records_decoded"] = decoded_count
        summary["juicetime_mechanics"] = _aggregate_juicetime_mechanics(decoded_records)
    return decoded_count, checked_count


def _aggregate_juicetime_mechanics(records: list[dict[str, Any]]) -> dict[str, Any]:
    counters: dict[str, dict[str, int]] = {
        "group_statuses": {}, "skewer_statuses": {}, "fruit_layer_statuses": {},
    }
    active_level_count = 0
    active_names: dict[str, int] = {}
    for record in records:
        decoded = record.get("decoded_juicetime", {})
        mechanics = decoded.get("mechanic_summary", {}) if isinstance(decoded, dict) else {}
        if not isinstance(mechanics, dict):
            continue
        if mechanics.get("active_status_names"):
            active_level_count += 1
        for name in mechanics.get("active_status_names", []):
            active_names[name] = active_names.get(name, 0) + 1
        for source_key, target_key in (
            ("group_status_counts", "group_statuses"),
            ("skewer_status_counts", "skewer_statuses"),
            ("fruit_layer_status_counts", "fruit_layer_statuses"),
        ):
            values = mechanics.get(source_key, {})
            if not isinstance(values, dict):
                continue
            for name, count in values.items():
                counters[target_key][name] = counters[target_key].get(name, 0) + int(count)
    return {
        "source": "JuiceTime enum definitions in IL2CPP metadata",
        "levels_with_non_normal_status": active_level_count,
        "levels_by_active_status_name": active_names,
        **counters,
    }


def _safe_unicode(value: str) -> str:
    """Replace lone surrogate code points that UTF-8 cannot encode."""
    return "".join("\ufffd" if 0xD800 <= ord(char) <= 0xDFFF else char
                   for char in value)


def _json_ready(value: Any, depth: int = 0) -> Any:
    """Convert decoded values into UTF-8 JSON-compatible values."""
    if depth > 80:
        return "<maximum nesting reached>"
    if isinstance(value, str):
        return _safe_unicode(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, bytes):
        return {"encoding": "base64", "data": base64.b64encode(value).decode("ascii")}
    if isinstance(value, dict):
        return {_safe_unicode(str(key)): _json_ready(item, depth + 1)
                for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_ready(item, depth + 1) for item in value]
    return _safe_unicode(str(value))


def _parse_csharp_enums(source: str) -> list[dict[str, Any]]:
    """Read named numeric enum members from generated IL2CPP C# declarations."""
    enums: list[dict[str, Any]] = []
    namespace = ""
    current_name: str | None = None
    current_members: dict[int, str] = {}
    previous_value = -1
    inside_body = False
    for raw_line in source.splitlines():
        namespace_match = re.match(r"\s*// Namespace:\s*(.*?)\s*$", raw_line)
        if namespace_match and current_name is None:
            namespace = namespace_match.group(1).strip()
        if current_name is None:
            enum_match = re.search(r"\benum\s+([A-Za-z_][A-Za-z_0-9]*)", raw_line)
            if not enum_match:
                continue
            current_name = enum_match.group(1)
            current_members = {}
            previous_value = -1
            if "{" not in raw_line:
                inside_body = False
                continue
            inside_body = True
            raw_line = raw_line.split("{", 1)[1]
        elif not inside_body:
            if "{" not in raw_line:
                continue
            inside_body = True
            raw_line = raw_line.split("{", 1)[1]

        if current_name is None:
            continue
        member_line = raw_line.split("//", 1)[0].strip().rstrip(",")
        if "}" in member_line:
            member_line = member_line.split("}", 1)[0].strip()
            closes_enum = True
        else:
            closes_enum = False
        member_line = re.sub(r"^(?:public|internal|private|protected|static)\s+", "", member_line)
        if member_line and member_line not in {"int value__;", "public int value__;"}:
            member = re.search(
                r"(?:const\s+" + re.escape(current_name) + r"\s+)?"
                r"(?P<member>[A-Za-z_][A-Za-z_0-9]*)\s*"
                r"(?:=\s*(?:\([^)]*\)\s*)?(?P<value>-?0[xX][0-9A-Fa-f]+|-?\d+))?\s*;?\s*$",
                member_line)
            if member and member.group("member") != "value__":
                raw_value = member.group("value")
                if raw_value is None:
                    value = previous_value + 1
                else:
                    negative = raw_value.startswith("-")
                    digits = raw_value[1:] if negative else raw_value
                    value = int(digits, 16 if digits.lower().startswith("0x") else 10)
                    if negative:
                        value = -value
                previous_value = value
                current_members[value] = member.group("member")
        if closes_enum:
            if current_members:
                enums.append({"name": current_name, "namespace": namespace,
                              "members": current_members})
            current_name = None
            inside_body = False
    return enums


def _enum_candidates_for_mechanic_field(field: str,
                                        enums: list[dict[str, Any]],
                                        context_hint: str = "") -> list[dict[str, Any]]:
    """Match mechanic/element ID fields only to semantically named enums.

    This intentionally avoids guessing mappings for generic fields such as `id`
    or `typeId`; each APK must provide a matching enum in its own metadata dump.
    """
    normalized = re.sub(r"[^a-z0-9]", "", field.casefold())
    stems = ("element", "mechanic", "obstacle", "special", "target")
    stem = next((candidate for candidate in stems
                 if normalized == candidate + "id" or normalized == candidate), None)
    if stem is None:
        return []
    candidates = []
    for enum in enums:
        enum_name = re.sub(r"[^a-z0-9]", "", enum["name"].casefold())
        if enum_name.endswith(stem + "type"):
            candidates.append(enum)
    if len(candidates) <= 1:
        return candidates
    # When common engine/framework enums share the suffix, prefer a unique enum
    # in the namespace that agrees with this APK's logical bundle/mode name.
    hint_tokens = [token for token in re.findall(r"[a-z]+", context_hint.casefold())
                   if len(token) >= 5 and token not in {"hurdle", "levels", "level", "bytes", "unity"}]
    ranked = []
    for enum in candidates:
        qualified = re.sub(r"[^a-z0-9]", "", f"{enum['namespace']}{enum['name']}".casefold())
        score = max((len(token) for token in hint_tokens
                     if re.sub(r"[^a-z0-9]", "", token) in qualified), default=0)
        ranked.append((score, enum))
    best = max((score for score, _ in ranked), default=0)
    winners = [enum for score, enum in ranked if score == best and score > 0]
    return winners if len(winners) == 1 else []


def _mechanic_annotations(level: Any, enums: list[dict[str, Any]],
                          context_hint: str = "") -> dict[str, Any] | None:
    """Build metadata-driven mechanic labels without changing source IDs."""
    if not isinstance(level, dict):
        return None
    records: list[dict[str, Any]] = []

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if isinstance(child, int) and not isinstance(child, bool):
                    candidates = _enum_candidates_for_mechanic_field(key, enums, context_hint)
                    if len(candidates) == 1:
                        records.append({"record": value, "field": key,
                                        "raw_id": child, "enum": candidates[0]})
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(level)
    if not records:
        return None

    by_mapping: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for record in records:
        enum = record["enum"]
        by_mapping.setdefault((enum["namespace"], enum["name"]), []).append(record)

    # Do not merge different numeric domains into one apparent mechanic list.
    if len(by_mapping) != 1:
        return None
    (namespace, enum_name), mapped_records = next(iter(by_mapping.items()))
    enum = mapped_records[0]["enum"]
    counts: dict[int, int] = {}
    for record in mapped_records:
        raw_id = record["raw_id"]
        counts[raw_id] = counts.get(raw_id, 0) + 1
        member_name = enum["members"].get(raw_id)
        record["record"]["ducapk_decoded_element"] = {
            "enum": enum_name,
            "id": raw_id,
            "name": member_name,
            "mapped": member_name is not None,
        }
    return {
        "source": "il2cpp_enum",
        "enum": f"{namespace}.{enum_name}" if namespace else enum_name,
        "id_field": mapped_records[0]["field"],
        "instances": len(mapped_records),
        "values": [
            {"id": raw_id, "name": enum["members"].get(raw_id), "count": count,
             "mapped": raw_id in enum["members"]}
            for raw_id, count in sorted(counts.items())
        ],
    }


def annotate_level_mechanics(job: Path, emit) -> int:
    """Annotate exported level ID fields using enums recovered for this APK.

    Raw IDs and payloads remain present. If no matching enum exists or the
    mapping is ambiguous, no labels are invented and the export is left alone.
    """
    manifest_path = job / "levels.json"
    enum_paths = [job / "il2cppdumper" / "dump.cs"]
    enum_paths.extend(sorted(p for p in (job / "cpp2il_map").rglob("*.cs") if p.is_file())
                      if (job / "cpp2il_map").is_dir() else [])
    enums: list[dict[str, Any]] = []
    for enum_path in enum_paths:
        try:
            enums.extend(_parse_csharp_enums(enum_path.read_text(encoding="utf-8", errors="replace")))
        except OSError:
            continue
    if not enums:
        emit("Metadata APK không có enum C# đọc được để giải mã ID mechanic; JSON và ID gốc được giữ nguyên.")
        return 0
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return 0
    if not isinstance(manifest, dict) or not isinstance(manifest.get("groups"), list):
        return 0

    annotated_levels = 0
    annotated_instances = 0
    used_enums: set[str] = set()
    mechanic_totals: dict[tuple[int, str | None], int] = {}
    unmapped_instances = 0
    for group in manifest["groups"]:
        if not isinstance(group, dict):
            continue
        for entry in group.get("levels", []):
            if not isinstance(entry, dict) or not isinstance(entry.get("file"), str):
                continue
            relative = Path(entry["file"])
            if relative.is_absolute() or ".." in relative.parts:
                continue
            level_path = (job / relative).resolve()
            try:
                level_path.relative_to((job / "levels").resolve())
            except ValueError:
                continue
            try:
                level = json.loads(level_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            context_hint = " ".join(str(group.get(key, "")) for key in ("bundle", "name"))
            annotation = _mechanic_annotations(level, enums, context_hint)
            if annotation is None:
                continue
            level["ducapk_mechanics"] = annotation
            level_path.write_text(json.dumps(_json_ready(level), ensure_ascii=False, indent=2),
                                  encoding="utf-8")
            entry["mechanics"] = annotation
            annotated_levels += 1
            annotated_instances += annotation["instances"]
            used_enums.add(annotation["enum"])
            for item in annotation["values"]:
                key = (item["id"], item["name"])
                mechanic_totals[key] = mechanic_totals.get(key, 0) + item["count"]
                if not item["mapped"]:
                    unmapped_instances += item["count"]

    summary = manifest.setdefault("summary", {})
    if isinstance(summary, dict):
        summary["mechanic_levels_annotated"] = annotated_levels
        summary["mechanic_elements_annotated"] = annotated_instances
        summary["mechanic_enum_sources"] = sorted(used_enums)
    manifest_path.write_text(json.dumps(_json_ready(manifest), ensure_ascii=False, indent=2),
                             encoding="utf-8")
    if annotated_levels:
        totals_text = ", ".join(
            f"{name or f'ID {raw_id} chưa ánh xạ'}={count:,}"
            for (raw_id, name), count in sorted(mechanic_totals.items(),
                                                key=lambda pair: (pair[0][0], pair[0][1] or "")))
        emit(f"Giải mã ID mechanic bằng enum metadata: {annotated_instances:,} mục trong {annotated_levels:,} level; {totals_text}; chưa ánh xạ {unmapped_instances:,}; enum: {', '.join(sorted(used_enums))}")
    else:
        emit("Không tìm thấy enum khớp các trường mechanic/element trong metadata của APK; giữ nguyên ID, không đoán tên.")
    return annotated_levels


_ALIAS_ATTRIBUTE_MARKER = re.compile(r"\[(?:[\w.]*\.)?(?:JsonProperty|JsonPropertyName|DataMember|Key)(?:Attribute)?\s*\(")


_ALIAS_PATTERNS = (
    re.compile(r"\[(?:[\w.]*\.)?JsonProperty(?:Name)?(?:Attribute)?\s*\(\s*(?:PropertyName\s*=\s*)?\"([^\"]+)\""),
    re.compile(r"\[(?:[\w.]*\.)?DataMember(?:Attribute)?\s*\([^)]*?\bName\s*=\s*\"([^\"]+)\""),
    re.compile(r"\[(?:[\w.]*\.)?Key(?:Attribute)?\s*\(\s*\"([^\"]+)\""),
)
_TYPE_DECLARATION = re.compile(r"\b(class|struct)\s+([^\s:<{(]+)")
_MEMBER_NAME = re.compile(r"[A-Za-z_]\w*")


def _scan_alias_classes(text: str, namespace: str = "") -> list[dict[str, Any]]:
    """Line-based scan of recovered C# for members carrying serialized-name attributes.

    Obfuscated IL2CPP names may contain braces, so this deliberately avoids
    parsing blocks and only relies on one-declaration-per-line dump layout.
    """
    found: dict[str, dict[str, str]] = {}
    stack: list[tuple[int, str]] = []
    pending: str | None = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("//"):
            match = re.match(r"// Namespace: ?(.*)", line)
            if match:
                namespace, stack = match.group(1).strip(), []
            continue
        match = re.match(r"namespace\s+([\w.]+)\s*;?", line)
        if match:
            namespace, stack = match.group(1), []
            continue
        indent = len(raw_line) - len(raw_line.lstrip("\t "))
        declaration = _TYPE_DECLARATION.search(line) if not line.startswith("[") else None
        if declaration and "(" not in line.split(declaration.group(0))[0]:
            while stack and stack[-1][0] >= indent:
                stack.pop()
            outer = stack[-1][1] if stack else (namespace + "." if namespace else "")
            joiner = "+" if stack else ""
            stack.append((indent, f"{outer}{joiner}{declaration.group(2)}"))
            pending = None
            continue
        if line.startswith("["):
            for pattern in _ALIAS_PATTERNS:
                alias = pattern.search(line)
                if alias:
                    pending = alias.group(1)
            continue
        if pending is None:
            continue
        alias, pending = pending, None
        if "(" in line or not stack:
            continue
        head = line.split("//", 1)[0].split("=", 1)[0].split("{", 1)[0].rstrip(" ;\t")
        name = head.split()[-1] if head.split() else ""
        if _MEMBER_NAME.fullmatch(name) and name.casefold() != alias.casefold():
            found.setdefault(stack[-1][1], {})[alias] = name
    return [{"class": owner, "aliases": aliases} for owner, aliases in found.items()]


def load_field_alias_maps(job: Path) -> list[dict[str, Any]]:
    """Collect {serialized key: C# member name} maps from the game's recovered classes."""
    from .categories import category_for_class
    sources: list[Path] = []
    for path in (job / "il2cppdumper" / "dump.cs",):
        if path.is_file():
            sources.append(path)
    for folder in (job / "cpp2il_types", job / "cpp2il_map"):
        if folder.is_dir():
            sources.extend(sorted(p for p in folder.rglob("*.cs") if p.is_file()))
    maps: list[dict[str, Any]] = []
    seen: set[str] = set()
    for path in sources:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if not _ALIAS_ATTRIBUTE_MARKER.search(text):
            continue
        for item in _scan_alias_classes(text):
            if item["class"] in seen or category_for_class(item["class"]) != "game":
                continue
            seen.add(item["class"])
            maps.append(item)
    return maps


def _best_alias_map(keys: set[str], maps: list[dict[str, Any]]) -> dict[str, Any] | None:
    best = None
    best_rank = None
    for candidate in maps:
        hits = len(keys & candidate["aliases"].keys())
        if not hits or hits * 2 < len(keys):
            continue
        rank = (hits, -len(candidate["aliases"].keys() - keys))
        if best_rank is None or rank > best_rank:
            best, best_rank = candidate, rank
    return best


def expand_field_aliases(value: Any, maps: list[dict[str, Any]],
                         used: dict[str, dict[str, str]]) -> Any:
    """Rename abbreviated JSON keys to the member names of the best matching class."""
    if isinstance(value, list):
        return [expand_field_aliases(item, maps, used) for item in value]
    if not isinstance(value, dict):
        return value
    chosen = _best_alias_map(set(value), maps)
    result = {}
    for key, item in value.items():
        new_key = key
        if chosen is not None and key in chosen["aliases"]:
            candidate = chosen["aliases"][key]
            if candidate not in value and candidate not in result:
                new_key = candidate
                used.setdefault(chosen["class"], {})[new_key] = key
        result[new_key] = expand_field_aliases(item, maps, used)
    return result


def annotate_level_field_names(job: Path, emit) -> int:
    """Rewrite exported level JSON keys from serialized aliases (e.g. "p") to full names.

    The reverse mapping is stored in each file under "ducapk_field_aliases" so
    the original compact keys remain recoverable.
    """
    manifest_path = job / "levels.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return 0
    if not isinstance(manifest, dict) or not isinstance(manifest.get("groups"), list):
        return 0
    maps = load_field_alias_maps(job)
    if not maps:
        emit("Không thấy thuộc tính JsonProperty/DataMember/Key trong code game; giữ nguyên tên trường JSON level.")
        return 0
    renamed_files = 0
    all_used: dict[str, dict[str, str]] = {}
    levels_root = (job / "levels").resolve()
    for group in manifest["groups"]:
        if not isinstance(group, dict):
            continue
        for entry in group.get("levels", []):
            if not isinstance(entry, dict) or not isinstance(entry.get("file"), str):
                continue
            relative = Path(entry["file"])
            if relative.is_absolute() or ".." in relative.parts:
                continue
            level_path = (job / relative).resolve()
            try:
                level_path.relative_to(levels_root)
                level = json.loads(level_path.read_text(encoding="utf-8"))
            except (ValueError, OSError, json.JSONDecodeError):
                continue
            if not isinstance(level, dict):
                continue
            previous = level.pop("ducapk_field_aliases", None)
            used: dict[str, dict[str, str]] = {}
            expanded = expand_field_aliases(level, maps, used)
            if isinstance(previous, dict):
                for owner, names in previous.items():
                    if isinstance(names, dict):
                        used.setdefault(owner, {}).update(names)
            if not used:
                continue
            expanded["ducapk_field_aliases"] = used
            level_path.write_text(json.dumps(_json_ready(expanded), ensure_ascii=False, indent=2),
                                  encoding="utf-8")
            renamed_files += 1
            for owner, names in used.items():
                all_used.setdefault(owner, {}).update(names)
    summary = manifest.setdefault("summary", {})
    if isinstance(summary, dict):
        summary["field_name_levels_expanded"] = renamed_files
        summary["field_name_aliases"] = all_used
    manifest_path.write_text(json.dumps(_json_ready(manifest), ensure_ascii=False, indent=2),
                             encoding="utf-8")
    if renamed_files:
        pairs = sorted({f"{short}->{full}" for names in all_used.values() for full, short in names.items()})
        emit(f"Đã đổi tên trường viết tắt sang tên đầy đủ trong {renamed_files:,} file level "
             f"({len(pairs):,} cặp: {', '.join(pairs[:20])}{'…' if len(pairs) > 20 else ''})")
    else:
        emit(f"Đã đọc {len(maps):,} class có tên trường rút gọn nhưng JSON level không dùng khóa viết tắt; giữ nguyên.")
    return renamed_files


def _unpack_msgpack(data: bytes) -> Any:
    """Decode the MessagePack subset used by the game's puzzle TextAssets."""
    offset = 0

    def read(size: int) -> bytes:
        nonlocal offset
        if size < 0 or offset + size > len(data):
            raise MessagePackError("MessagePack payload is truncated")
        value = data[offset:offset + size]
        offset += size
        return value

    def uint(size: int, signed: bool = False) -> int:
        return int.from_bytes(read(size), "big", signed=signed)

    def parse(depth: int = 0) -> Any:
        if depth > 100:
            raise MessagePackError("MessagePack nesting limit exceeded")
        tag = uint(1)
        if tag <= 0x7F:
            return tag
        if tag >= 0xE0:
            return tag - 0x100
        if 0x80 <= tag <= 0x8F:
            count = tag & 0x0F
            return _read_map(count, depth)
        if 0x90 <= tag <= 0x9F:
            return [parse(depth + 1) for _ in range(tag & 0x0F)]
        if 0xA0 <= tag <= 0xBF:
            return read(tag & 0x1F).decode("utf-8", errors="replace")
        if tag == 0xC0:
            return None
        if tag == 0xC2:
            return False
        if tag == 0xC3:
            return True
        if tag == 0xCA:
            return struct.unpack(">f", read(4))[0]
        if tag == 0xCB:
            return struct.unpack(">d", read(8))[0]
        if tag in (0xCC, 0xCD, 0xCE, 0xCF):
            return uint({0xCC: 1, 0xCD: 2, 0xCE: 4, 0xCF: 8}[tag])
        if tag in (0xD0, 0xD1, 0xD2, 0xD3):
            return uint({0xD0: 1, 0xD1: 2, 0xD2: 4, 0xD3: 8}[tag], signed=True)
        if tag in (0xC4, 0xC5, 0xC6):
            size = uint({0xC4: 1, 0xC5: 2, 0xC6: 4}[tag])
            return read(size)
        if tag in (0xD9, 0xDA, 0xDB):
            size = uint({0xD9: 1, 0xDA: 2, 0xDB: 4}[tag])
            return read(size).decode("utf-8", errors="replace")
        if tag in (0xDC, 0xDD):
            count = uint(2 if tag == 0xDC else 4)
            return [parse(depth + 1) for _ in range(count)]
        if tag in (0xDE, 0xDF):
            count = uint(2 if tag == 0xDE else 4)
            return _read_map(count, depth)
        raise MessagePackError(f"Unsupported MessagePack marker 0x{tag:02x}")

    def _read_map(count: int, depth: int) -> dict:
        result = {}
        for _ in range(count):
            key = parse(depth + 1)
            value = parse(depth + 1)
            try:
                result[key] = value
            except TypeError:
                result[repr(key)] = value
        return result

    value = parse()
    if offset != len(data):
        raise MessagePackError(f"{len(data) - offset} trailing bytes after MessagePack value")
    return value


def _textasset_bytes(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    # UnityPy decodes non-UTF8 TextAssets with surrogateescape on this package.
    return str(value or "").encode("utf-8", errors="surrogateescape")


def _unpack_hdpk_pack(data: bytes) -> list[tuple[int, Any]]:
    """Read the game's HDPK table and preserve each JSON or text level record."""
    if not data.startswith(b"HDPK") or len(data) < 20:
        return []
    count = int.from_bytes(data[4:8], "little")
    level_id = int.from_bytes(data[8:12], "little")
    data_offset = int.from_bytes(data[12:16], "little")
    if not 1 <= count <= 100_000 or not 16 <= data_offset <= len(data):
        raise ValueError("HDPK header has invalid count/data offset")
    cursor = 16
    start = data_offset
    result: list[tuple[int, Any]] = []
    for index in range(count):
        if index + 1 < count:
            if cursor + 12 > data_offset:
                raise ValueError("HDPK index table is truncated")
            size = int.from_bytes(data[cursor:cursor + 4], "little")
            next_id = int.from_bytes(data[cursor + 4:cursor + 8], "little")
            end = int.from_bytes(data[cursor + 8:cursor + 12], "little")
            cursor += 12
            if end != start + size:
                raise ValueError("HDPK level offsets do not match their lengths")
        else:
            if cursor + 4 > data_offset:
                raise ValueError("HDPK final size entry is missing")
            size = int.from_bytes(data[cursor:cursor + 4], "little")
            end = start + size
            if end > len(data):
                raise ValueError("HDPK final level extends beyond the TextAsset")
        if size <= 0 or end > len(data):
            raise ValueError("HDPK level record has an invalid range")
        raw_record = data[start:end]
        try:
            value = json.loads(raw_record.decode("utf-8-sig"))
        except json.JSONDecodeError:
            try:
                value = raw_record.decode("utf-8-sig")
            except UnicodeDecodeError as error:
                raise ValueError(f"HDPK level {level_id} is neither UTF-8 JSON nor text") from error
        except UnicodeDecodeError as error:
            raise ValueError(f"HDPK level {level_id} is not valid UTF-8: {error}") from error
        result.append((level_id, value))
        start = end
        if index + 1 < count:
            level_id = next_id
    if cursor + 4 > data_offset or start != len(data):
        raise ValueError("HDPK table or payload size does not match the TextAsset")
    return result


def _is_puzzle_layout(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    blocks = value.get("b")
    if not isinstance(blocks, list) or not blocks:
        return False
    return all(isinstance(block, dict) and "p" in block and "c" in block
               for block in blocks)


# MessagePack field names recovered from this game's generated
# MessagePack.GeneratedMessagePackResolver formatters.  Keep mappings scoped to
# their concrete record type: the same short key means different things in
# different records (for example, "c" is Cubes, LockedByColor, or NormalCubes).
_PUZZLE_FIELDS = {
    "v": "Version", "h": "HardLevel", "s": "Size", "l": "PathLength",
    "ps": "PathSectionDistance", "b": "Boxes", "p": "Paths",
    "m": "MapData", "g": "Groups", "c": "Covers", "sd": "SurpriseDatas",
}
_BOX_FIELDS = {
    "t": "BoxType", "i": "PathIndex", "iv2": "PathIndexV2",
    "p": "Position", "r": "Rotation", "c": "Cubes",
    "lci": "LinkedCubes", "l": "LockColor", "e": "IsEnterOnly",
    "n": "NumLock", "lc": "LimitedColor", "al": "IsAdjacentLocked",
    "mc": "MultiColorLock",
}
_CUBE_FIELDS = {
    "t": "Type", "s": "IsSecret", "k": "GroupKeyId",
    "l": "NumLock", "f": "IsFixed",
}
_GAME_PATH_FIELDS = {"c": "IsCircle", "p": "ControlPoints"}
_CONTROL_POINT_FIELDS = {"p": "Position", "i": "InTangent", "o": "OutTangent"}
_MAP_COMPONENT_FIELDS = {"n": "Name", "p": "Position", "r": "Rotation", "s": "Scale"}
_GROUP_FIELDS = {"i": "Id", "b": "BoxIndexes", "c": "LockedByColor"}
_COVER_FIELDS = {"b": "BoxIndexes"}
_SURPRISE_FIELDS = {"s": "SurpriseType", "c": "NormalCubes"}


def _rename_record(record: Any, fields: dict[str, str]) -> Any:
    if not isinstance(record, dict):
        return record
    return {fields.get(key, key): value for key, value in record.items()}


def _expand_puzzle_field_names(layout: Any) -> Any:
    """Expand compact MessagePack aliases to the game's formatter field names."""
    if not isinstance(layout, dict):
        return layout
    expanded = _rename_record(layout, _PUZZLE_FIELDS)
    expanded["Boxes"] = [
        _rename_record(box, _BOX_FIELDS) | {
            "Cubes": [_rename_record(cube, _CUBE_FIELDS) for cube in box.get("c", [])]
        } if isinstance(box, dict) and isinstance(box.get("c", []), list)
        else _rename_record(box, _BOX_FIELDS)
        for box in layout.get("b", [])
    ] if isinstance(layout.get("b", []), list) else layout.get("b")
    expanded["Paths"] = [
        _rename_record(path, _GAME_PATH_FIELDS) | {
            "ControlPoints": [_rename_record(point, _CONTROL_POINT_FIELDS)
                              for point in path.get("p", [])]
        } if isinstance(path, dict) and isinstance(path.get("p", []), list)
        else _rename_record(path, _GAME_PATH_FIELDS)
        for path in layout.get("p", [])
    ] if isinstance(layout.get("p", []), list) else layout.get("p")
    if isinstance(layout.get("m"), list):
        expanded["MapData"] = [_rename_record(item, _MAP_COMPONENT_FIELDS)
                               for item in layout["m"]]
    if isinstance(layout.get("g"), list):
        expanded["Groups"] = [_rename_record(item, _GROUP_FIELDS) for item in layout["g"]]
    if isinstance(layout.get("c"), list):
        expanded["Covers"] = [_rename_record(item, _COVER_FIELDS) for item in layout["c"]]
    if isinstance(layout.get("sd"), list):
        expanded["SurpriseDatas"] = [
            _rename_record(item, _SURPRISE_FIELDS) | {
                "NormalCubes": [_rename_record(cube, _CUBE_FIELDS)
                                for cube in item.get("c", [])]
            } if isinstance(item, dict) and isinstance(item.get("c", []), list)
            else _rename_record(item, _SURPRISE_FIELDS)
            for item in layout["sd"]
        ]
    return expanded


def _level_document(display_name: str, ordinal: int, folder_name: str,
                    bundle_name: str, puzzle_id: Any, attrs: Any,
                    layout: dict[str, Any]) -> dict[str, Any]:
    compact_layout = _json_ready(layout)
    return {
        "format": "ducapk-unity-puzzle-v3",
        "name": display_name,
        "export_name": f"Level {ordinal}",
        "level_number": ordinal,
        "group": folder_name,
        "bundle": bundle_name,
        "puzzle_id": puzzle_id,
        "asset_name": f"p{puzzle_id}",
        "display_name": display_name,
        "attributes": _json_ready(attrs),
        "layout": _json_ready(_expand_puzzle_field_names(layout)),
        "layout_compact": compact_layout,
    }


def _safe_folder_name(value: str) -> str:
    cleaned = re.sub(r'[<>:"/\\|?*\x00-\x1f]+', "_", _safe_unicode(value)).strip(" .")
    return cleaned[:100] or "PuzzleGroup"


def _decrypt_package_manifest(data: bytes, res_code: str) -> bytes:
    if AES is None:
        raise RuntimeError("Cần cài pycryptodome để giải mã PackageManifest của game")
    key = hashlib.sha256(res_code.encode("utf-8")).digest()
    if not data or len(data) % AES.block_size:
        raise ValueError("PackageManifest AES có kích thước không hợp lệ")
    plain = AES.new(key, AES.MODE_CBC, _PACKAGE_MANIFEST_IV).decrypt(data)
    padding = plain[-1]
    if 1 <= padding <= AES.block_size and plain[-padding:] == bytes([padding]) * padding:
        plain = plain[:-padding]
    if not plain or not any(token in plain for token in (b".unity3d", b".bundle", b".bytes")):
        raise ValueError("PackageManifest giải mã được nhưng không có bản ghi bundle hợp lệ")
    return plain


def _manifest_bundle_names(plain: bytes) -> dict[str, str]:
    """Read YooAsset bundle-name/hash pairs from its decrypted binary manifest."""
    result: dict[str, str] = {}
    suffixes = (b".unity3d", b".bundle", b".assetbundle", b".ab")
    search_at = 0
    while True:
        marker = min((pos for suffix in suffixes
                      if (pos := plain.find(suffix, search_at)) >= 0), default=-1)
        if marker < 0:
            break
        end = marker + next(len(suffix) for suffix in suffixes
                            if plain[marker:marker + len(suffix)] == suffix)
        search_at = end
        # YooAsset writes strings as a little-endian UInt16 byte length, then
        # the UTF-8 name, followed here by CRC, hash length, and hash text.
        for name_len in range(8, min(256, end) + 1):
            start = end - name_len
            if start < 2 or int.from_bytes(plain[start - 2:start], "little") != name_len:
                continue
            try:
                name = plain[start:end].decode("utf-8")
            except UnicodeDecodeError:
                continue
            hash_len_at = end + 4
            if hash_len_at + 2 > len(plain):
                continue
            hash_len = int.from_bytes(plain[hash_len_at:hash_len_at + 2], "little")
            if hash_len != 32 or hash_len_at + 2 + hash_len > len(plain):
                continue
            bundle_hash = plain[hash_len_at + 2:hash_len_at + 2 + hash_len].decode("ascii", errors="ignore").lower()
            if re.fullmatch(r"[0-9a-f]{32}", bundle_hash):
                result[bundle_hash] = name
                break
    return result


def _load_bundle_name_index(apk_paths: list[Path], emit,
                            cancel: threading.Event) -> dict[str, str]:
    """Decrypt built-in YooAsset manifests and map APK hash filenames to names."""
    index: dict[str, str] = {}
    for apk_path in apk_paths:
        if cancel.is_set():
            raise LevelScanCancelled("Đã dừng khi đọc PackageManifest.")
        if not apk_path.is_file():
            continue
        try:
            with zipfile.ZipFile(apk_path) as archive:
                names = archive.namelist()
                manifests = [name for name in names
                             if Path(name).name.casefold().startswith("packagemanifest_")
                             and Path(name).name.casefold().endswith(".bytes")]
                for manifest_path in manifests:
                    manifest_file = Path(manifest_path).name
                    version_name = manifest_file.rsplit("_", 1)[0] + ".version"
                    version_path = str(Path(manifest_path).with_name(version_name))
                    res_code = ""
                    if version_path in names:
                        try:
                            version_data = json.loads(archive.read(version_path).decode("utf-8-sig"))
                            res_code = str(version_data.get("resCode", ""))
                        except (UnicodeDecodeError, json.JSONDecodeError, AttributeError):
                            pass
                    if not res_code:
                        match = re.search(r"_(\d+)\.bytes$", manifest_file, re.IGNORECASE)
                        res_code = match.group(1) if match else ""
                    if not res_code:
                        continue
                    try:
                        plain = _decrypt_package_manifest(archive.read(manifest_path), res_code)
                        found = _manifest_bundle_names(plain)
                        index.update(found)
                        emit(f"Đã giải mã PackageManifest {manifest_file}: ánh xạ {len(found):,} bundle")
                    except Exception as error:
                        emit(f"Không giải mã được PackageManifest {manifest_file}: {_safe_unicode(str(error)[:200])}")
        except (OSError, zipfile.BadZipFile):
            continue
    return index


def _decrypt_bundle_stream(bundle: bytes, logical_name: str) -> bytes:
    """Undo the game's BundleStream one-byte XOR before UnityFS parsing."""
    if bundle.startswith(b"UnityFS"):
        return bundle
    name_chars = logical_name.encode("utf-16-le")
    name_length = len(name_chars) // 2
    base_offset = name_length + 4
    if name_length == 0 or base_offset >= len(bundle):
        return bundle
    # Match ARM64 unchecked Int32 arithmetic and C# signed remainder behavior.
    weighted_sum = 0
    for index in range(name_length):
        char_value = int.from_bytes(name_chars[index * 2:index * 2 + 2], "little")
        weighted_sum = (weighted_sum + (index + 1) * char_value) & 0xFFFFFFFF
    remaining = len(bundle) - base_offset
    product = (remaining * weighted_sum) & 0xFFFFFFFF
    signed_product = product if product < 0x80000000 else product - 0x100000000
    quotient = abs(signed_product) // 104729
    if signed_product < 0:
        quotient = -quotient
    remainder = signed_product - quotient * 104729
    salt = abs(remainder)
    threshold = salt % remaining
    key_index = salt % name_length
    key = key_index & 0xFF
    if key == 0:
        key = name_chars[0]
    absolute_offset = base_offset + threshold
    if absolute_offset >= len(bundle):
        return bundle
    decoded = bytearray(bundle)
    decoded[absolute_offset] ^= key
    if decoded[base_offset:base_offset + 7] != b"UnityFS":
        return bundle
    return bytes(decoded[base_offset:])


def _xxtea_decrypt_words(words: list[int], key: list[int]) -> list[int]:
    """Game XXTEA: 7 + 50/n rounds and a reshuffled MX (y/z swapped, shift 3)."""
    count = len(words)
    if count < 2:
        return words
    total = ((50 // count + 7) * _XXTEA_DELTA) & 0xFFFFFFFF
    y = words[0]
    while total:
        e = (total >> 2) & 3
        for p in range(count - 1, -1, -1):
            z = words[p - 1] if p else words[count - 1]
            mx = ((((y >> 5) ^ (z << 2)) + ((z >> 3) ^ (y << 3)))
                  ^ ((total ^ y) + (key[(p & 3) ^ e] ^ z))) & 0xFFFFFFFF
            words[p] = y = (words[p] - mx) & 0xFFFFFFFF
        total = (total - _XXTEA_DELTA) & 0xFFFFFFFF
    return words


def _decrypt_memory_bundle(bundle: bytes, logical_name: str) -> bytes | None:
    """Undo the game's LoadFromMemory bundle encryption, or return None."""
    body = bundle[len(logical_name) + 4:]
    if len(body) < 8 or len(body) % 4:
        return None
    key = list(struct.unpack("<4I", _MEMORY_BUNDLE_XXTEA_KEY.encode("utf-16-le")[:16].ljust(16, b"\0")))
    words = _xxtea_decrypt_words(list(struct.unpack(f"<{len(body) // 4}I", body)), key)
    length = words[-1]
    if not 0 <= (len(words) - 1) * 4 - length < 4:
        return None
    plain = struct.pack(f"<{len(words)}I", *words)[:length]
    return plain if plain.startswith(b"UnityFS") else None


def _decrypt_yooasset_bundle(bundle: bytes, logical_name: str | None) -> tuple[bytes, str | None]:
    """Return (bundle, transform) after trying the game's YooAsset bundle codecs."""
    if not logical_name or bundle.startswith(b"UnityFS"):
        return bundle, None
    decoded = _decrypt_bundle_stream(bundle, logical_name)
    if decoded is not bundle:
        return decoded, "bundle-stream-xor"
    decoded = _decrypt_memory_bundle(bundle, logical_name)
    if decoded is not None:
        return decoded, "load-from-memory-xxtea"
    return bundle, None


def _bundle_text_assets(bundle: bytes) -> list[tuple[str, bytes]]:
    """Return (name, raw bytes) for each TextAsset in a decoded bundle."""
    result = []
    for obj in UnityPy.load(bundle).objects:
        if obj.type.name != "TextAsset":
            continue
        asset = obj.parse_as_object()
        name = _safe_unicode(str(getattr(asset, "m_Name", "") or f"TextAsset_{obj.path_id}"))
        result.append((name, _textasset_bytes(getattr(asset, "m_Script", b""))))
    return result


def _bundle_asset_index(bundle: bytes, logical_name: str | None = None) -> tuple[dict[str, Any], int, int, int]:
    """Try UnityPy on a bundle and index any MessagePack TextAssets found."""
    if logical_name:
        bundle, _ = _decrypt_yooasset_bundle(bundle, logical_name)
    env = UnityPy.load(bundle)
    assets: dict[str, Any] = {}
    failures = 0
    object_count = 0
    text_asset_count = 0
    for obj in env.objects:
        object_count += 1
        if obj.type.name != "TextAsset":
            continue
        text_asset_count += 1
        name = ""
        try:
            asset = obj.parse_as_object()
            name = _safe_unicode(str(getattr(asset, "m_Name", "") or ""))
            text = _textasset_bytes(getattr(asset, "m_Script", b""))
            if text.startswith(b"HDPK"):
                try:
                    packed_levels = _unpack_hdpk_pack(text)
                    assets.setdefault("__hdpk_levels__", []).extend(
                        {"container": name, "entry_id": entry_id, "layout": layout}
                        for entry_id, layout in packed_levels)
                except Exception:
                    failures += 1
                continue
            serialized = _decrypt_swap_aes_level(text)
            if serialized is not None:
                assets.setdefault("__serialized_levels__", []).append(
                    {"container": name, "layout": serialized})
                continue
            decoded = _unpack_msgpack(text)
            if name:
                assets[name] = decoded
        except Exception:
            # A Unity bundle may have ordinary text assets (language tables,
            # build symbols, etc.) beside puzzle data. Only count a decode
            # failure when the asset name indicates it is part of our puzzle
            # index convention.
            if name == "folders" or re.fullmatch(r"[fp]\d+", name):
                failures += 1
    return assets, failures, object_count, text_asset_count


def _is_unity_bundle_candidate(info: zipfile.ZipInfo) -> bool:
    """Recognize Unity bundles across app-specific directory layouts."""
    if info.is_dir() or info.file_size <= 0 or info.file_size > MAX_BUNDLE_BYTES:
        return False
    name = info.filename.casefold()
    if name.endswith(".manifest"):
        return False
    if name.startswith(PUZZLE_BUNDLE_PREFIX):
        return True
    if name.endswith(UNITY_BUNDLE_SUFFIXES):
        return True
    # Some Unity games rename or hash their bundle files under these folders.
    return any(part in name for part in ("/assetbundles/", "/streamingassets/"))


def _base64_envelope_bytes(raw: bytes) -> bytes | None:
    """Recognize a plain Base64 envelope without claiming it is decrypted."""
    try:
        text = raw.removeprefix(b"\xef\xbb\xbf").decode("ascii").strip()
    except UnicodeDecodeError:
        return None
    if len(text) < 80 or not re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", text):
        return None
    try:
        decoded = base64.b64decode(text, validate=True)
    except (ValueError, base64.binascii.Error):
        return None
    return decoded if decoded else None


def _decrypt_config_payload(decoded: bytes) -> Any | None:
    """Try the known config AES keys and accept only PKCS#7-padded JSON output."""
    if AES is None or not decoded or len(decoded) % AES.block_size:
        return None
    for key, iv in _CONFIG_AES_KEYS:
        plain = AES.new(key, AES.MODE_CBC, iv).decrypt(decoded)
        padding = plain[-1]
        if not 1 <= padding <= AES.block_size or plain[-padding:] != bytes([padding]) * padding:
            continue
        try:
            return json.loads(plain[:-padding].decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
    return None


def _decrypt_swap_aes_level(raw: bytes) -> Any | None:
    """Decode a LevelDataSerializer TextAsset; accept only padded, JSON output."""
    decoded = _base64_envelope_bytes(raw)
    if AES is None or decoded is None or len(decoded) % AES.block_size:
        return None
    shuffled = bytearray(decoded)
    size = len(shuffled)
    for index in range(size - 1, -1, -1):
        other = (7 * index + 3) % size
        shuffled[index], shuffled[other] = shuffled[other], shuffled[index]
    for key, iv in _SWAP_AES_LEVEL_KEYS:
        plain = AES.new(key, AES.MODE_CBC, iv).decrypt(bytes(shuffled))
        padding = plain[-1]
        if not 1 <= padding <= AES.block_size or plain[-padding:] != bytes([padding]) * padding:
            continue
        plain = plain[:-padding]
        try:
            if plain.startswith(b"\x1f\x8b"):
                plain = gzip.decompress(plain)
            return json.loads(plain.decode("utf-8-sig"))
        except (OSError, EOFError, UnicodeDecodeError, json.JSONDecodeError):
            continue
    return None


def _level_number_from_name(name: str) -> int | None:
    match = re.search(r"(\d+)$", name)
    return int(match.group(1)) if match else None


def _collect_puzzle_exports(apk_paths: list[Path], emit,
                            cancel: threading.Event) -> tuple[list[dict], list[dict], int, int, dict[str, Any]]:
    groups: list[dict] = []
    exports: list[dict] = []
    parse_errors = 0
    bundles_scanned = 0
    stats: dict[str, Any] = {
        "bundle_candidates_seen": 0,
        "bundle_candidates_opened": 0,
        "opaque_bundle_candidates": 0,
        "unity_objects_decoded": 0,
        "text_assets_decoded": 0,
        "opaque_examples": [],
        "base64_payload_candidates": 0,
        "base64_payload_examples": [],
        "base64_payloads_decrypted": 0,
        "decrypted_config_files": [],
        "memory_bundles_decrypted": 0,
        "hdpk_packs_decoded": 0,
        "hdpk_level_payloads": 0,
        "serialized_aes_levels_decoded": 0,
    }

    bundle_names = _load_bundle_name_index(apk_paths, emit, cancel)
    stats["package_manifest_bundle_names"] = len(bundle_names)
    if bundle_names:
        emit(f"Đã chuẩn bị đảo phép XOR BundleStream cho {len(bundle_names):,} tên bundle YooAsset đã ánh xạ")

    for apk_path in apk_paths:
        if cancel.is_set():
            raise LevelScanCancelled("Đã dừng khi quét dữ liệu level.")
        if not apk_path.is_file():
            continue
        try:
            archive_context = zipfile.ZipFile(apk_path)
        except (OSError, zipfile.BadZipFile):
            continue
        with archive_context as archive:
            # Some games store encrypted remote/config payloads as Base64 text
            # in JSON-named assets rather than as ordinary Unity bundles.
            for info in archive.infolist():
                if info.is_dir() or not info.filename.casefold().endswith(".json"):
                    continue
                if info.file_size > 8 * 1024 * 1024:
                    continue
                try:
                    decoded = _base64_envelope_bytes(archive.read(info))
                    if decoded is None:
                        continue
                    config = _decrypt_config_payload(decoded)
                    if config is not None:
                        relative_path = Path("decrypted_assets") / Path(info.filename)
                        exports.append({"path": relative_path, "data": config, "kind": "config"})
                        stats["base64_payloads_decrypted"] += 1
                        stats["decrypted_config_files"].append(relative_path.as_posix())
                        continue
                    stats["base64_payload_candidates"] += 1
                    if len(stats["base64_payload_examples"]) < 12:
                        stats["base64_payload_examples"].append(info.filename)
                except Exception:
                    continue
            bundle_infos = [info for info in archive.infolist()
                            if _is_unity_bundle_candidate(info)]
            stats["bundle_candidates_seen"] += len(bundle_infos)
            for info in bundle_infos:
                if cancel.is_set():
                    raise LevelScanCancelled("Đã dừng khi quét dữ liệu level.")
                try:
                    bundle_hash = Path(info.filename).stem.casefold()
                    logical_name = bundle_names.get(bundle_hash)
                    bundle_bytes, transform = _decrypt_yooasset_bundle(
                        archive.read(info), logical_name)
                    assets, failures, object_count, text_asset_count = _bundle_asset_index(bundle_bytes)
                    if transform == "load-from-memory-xxtea":
                        # These bundles hold game config tables rather than
                        # levels; export their TextAssets verbatim.
                        export_dir = Path("decrypted_assets") / _safe_folder_name(Path(logical_name).stem)
                        for asset_name, raw in _bundle_text_assets(bundle_bytes):
                            relative_path = export_dir / (_safe_folder_name(asset_name) + ".bytes")
                            exports.append({"path": relative_path, "raw": raw, "kind": "config"})
                            stats["decrypted_config_files"].append(relative_path.as_posix())
                        stats["memory_bundles_decrypted"] += 1
                        emit(f"Đã giải mã bundle LoadFromMemory (XXTEA) {logical_name}; xuất TextAsset vào {export_dir.as_posix()}")
                    parse_errors += failures
                    bundles_scanned += 1
                    stats["bundle_candidates_opened"] += 1
                    stats["unity_objects_decoded"] += object_count
                    stats["text_assets_decoded"] += text_asset_count
                    if object_count == 0:
                        stats["opaque_bundle_candidates"] += 1
                        if len(stats["opaque_examples"]) < 12:
                            stats["opaque_examples"].append(info.filename)
                except Exception as error:
                    parse_errors += 1
                    stats["opaque_bundle_candidates"] += 1
                    if len(stats["opaque_examples"]) < 12:
                        stats["opaque_examples"].append(info.filename)
                    emit(f"Không đọc được puzzle bundle {Path(info.filename).name}: {_safe_unicode(str(error)[:250])}")
                    continue

                bundle_name = logical_name or Path(info.filename).name
                bundle_key = Path(bundle_name).stem
                group_count = 0
                packed_levels = assets.get("__hdpk_levels__")
                if isinstance(packed_levels, list) and packed_levels:
                    container_groups: dict[str, list[dict[str, Any]]] = {}
                    for packed_level in packed_levels:
                        if not isinstance(packed_level, dict):
                            continue
                        container_name = _safe_folder_name(str(packed_level.get("container") or "pack"))
                        container_groups.setdefault(container_name, []).append(packed_level)
                    for container_name, container_levels in container_groups.items():
                        group_levels = []
                        for ordinal, packed_level in enumerate(container_levels, start=1):
                            entry_id = packed_level.get("entry_id")
                            try:
                                level_number = int(entry_id)
                                if level_number <= 0:
                                    level_number = ordinal
                            except (TypeError, ValueError):
                                level_number = ordinal
                            level_data = packed_level.get("layout")
                            if isinstance(level_data, str):
                                level_data = {
                                    "format": "ducapk-hdpk-text-level-v1",
                                    "source_record_id": entry_id,
                                    "payload": level_data,
                                    "semicolon_fields": level_data.split(";"),
                                }
                            if not isinstance(level_data, dict):
                                continue
                            relative_path = (Path("levels") / bundle_key / container_name /
                                             f"Level {level_number}.json")
                            exports.append({"path": relative_path, "data": level_data})
                            group_levels.append({
                                "name": f"Level {level_number}",
                                "export_name": f"Level {level_number}",
                                "level_number": level_number,
                                "entry_id": entry_id,
                                "tree_id": level_data.get("treeID"),
                                "file": relative_path.as_posix(),
                            })
                        groups.append({
                            "bundle": bundle_name,
                            "name": container_name,
                            "listed_puzzles": len(group_levels),
                            "exported_puzzles": len(group_levels),
                            "missing_puzzles": 0,
                            "levels": group_levels,
                            "source_format": ("HDPK/JSON" if container_levels and
                                               isinstance(container_levels[0].get("layout"), dict)
                                               else "HDPK/semicolon-text"),
                        })
                        group_count += len(group_levels)
                        stats["hdpk_packs_decoded"] += 1
                        stats["hdpk_level_payloads"] += len(group_levels)
                        emit(f"Giải mã HDPK: {bundle_name} / {container_name}; xuất {len(group_levels):,} level JSON gốc")

                serialized_levels = assets.get("__serialized_levels__")
                if isinstance(serialized_levels, list) and serialized_levels:
                    serialized_levels.sort(key=lambda item: (
                        _level_number_from_name(item["container"]) is None,
                        _level_number_from_name(item["container"]) or 0, item["container"]))
                    group_levels = []
                    for ordinal, item in enumerate(serialized_levels, start=1):
                        level_number = _level_number_from_name(item["container"]) or ordinal
                        relative_path = Path("levels") / bundle_key / f"Level {level_number}.json"
                        exports.append({"path": relative_path, "data": item["layout"]})
                        group_levels.append({
                            "name": f"Level {level_number}",
                            "export_name": f"Level {level_number}",
                            "level_number": level_number,
                            "asset_name": item["container"],
                            "file": relative_path.as_posix(),
                        })
                    groups.append({
                        "bundle": bundle_name,
                        "name": bundle_key,
                        "listed_puzzles": len(group_levels),
                        "exported_puzzles": len(group_levels),
                        "missing_puzzles": 0,
                        "levels": group_levels,
                        "source_format": "LevelDataSerializer/Base64+Swap+AES-CBC(+GZip)/JSON",
                    })
                    group_count += len(group_levels)
                    stats["serialized_aes_levels_decoded"] += len(group_levels)
                    emit(f"Giải mã LevelDataSerializer: {bundle_name}; xuất {len(group_levels):,} level JSON")

                folder_defs = assets.get("folders")
                if not isinstance(folder_defs, list):
                    continue
                for folder in folder_defs:
                    if cancel.is_set():
                        raise LevelScanCancelled("Đã dừng khi quét dữ liệu level.")
                    if not isinstance(folder, dict) or "id" not in folder:
                        continue
                    folder_id = folder["id"]
                    folder_name_data = folder.get("name", {})
                    folder_name = (folder_name_data.get("en")
                                   if isinstance(folder_name_data, dict) else None)
                    folder_name = _safe_unicode(str(folder_name or f"Group_{folder_id}"))
                    listed = assets.get(f"f{folder_id}")
                    if not isinstance(listed, list):
                        parse_errors += 1
                        continue

                    slug = _safe_folder_name(folder_name)
                    export_group = Path("levels") / bundle_key / slug
                    group_levels: list[dict] = []
                    missing = 0
                    for ordinal, descriptor in enumerate(listed, start=1):
                        if cancel.is_set():
                            raise LevelScanCancelled("Đã dừng khi quét dữ liệu level.")
                        if not isinstance(descriptor, dict) or "id" not in descriptor:
                            missing += 1
                            continue
                        puzzle_id = descriptor["id"]
                        layout = assets.get(f"p{puzzle_id}")
                        if not _is_puzzle_layout(layout):
                            missing += 1
                            continue
                        entry_name = descriptor.get("name", {})
                        display_name = (entry_name.get("en")
                                        if isinstance(entry_name, dict) else entry_name)
                        display_name = _safe_unicode(str(display_name or f"Puzzle_{puzzle_id}"))
                        attrs = descriptor.get("attr", {})
                        level_doc = _level_document(
                            display_name, ordinal, folder_name, bundle_name,
                            puzzle_id, attrs, layout)
                        relative_path = export_group / f"Level {ordinal}.json"
                        group_levels.append({
                            "name": display_name,
                            "export_name": f"Level {ordinal}",
                            "level_number": ordinal,
                            "puzzle_id": puzzle_id,
                            "display_name": display_name,
                            "file": relative_path.as_posix(),
                        })
                        exports.append({"path": relative_path, "data": level_doc})
                    group_count += len(group_levels)
                    groups.append({
                        "bundle": bundle_name,
                        "folder_id": folder_id,
                        "name": folder_name,
                        "listed_puzzles": len(listed),
                        "exported_puzzles": len(group_levels),
                        "missing_puzzles": missing,
                        "levels": group_levels,
                    })
                emit(f"Quét puzzle bundle: {bundle_name}; xuất {group_count:,} layout trong {len(folder_defs)} nhóm")
    return groups, exports, parse_errors, bundles_scanned, stats


def _cached_level_export_is_complete(manifest: Any, job: Path) -> bool:
    """Only reuse a cache when it contains at least one real, existing level."""
    if not isinstance(manifest, dict) or manifest.get("format") != "ducapk-unity-puzzles-v9":
        return False
    summary = manifest.get("summary")
    groups = manifest.get("groups")
    if not isinstance(summary, dict) or not isinstance(groups, list):
        return False
    expected = summary.get("real_puzzle_layouts_exported")
    if not isinstance(expected, int) or expected <= 0:
        return False
    level_entries = [level for group in groups if isinstance(group, dict)
                     for level in group.get("levels", []) if isinstance(level, dict)]
    if len(level_entries) != expected:
        return False
    return all(isinstance(level.get("file"), str)
               and (job / Path(level["file"])).is_file()
               for level in level_entries)


def extract_level_json(apk_paths: list[Path], job: Path, emit,
                       cancel: threading.Event) -> Path:
    """Decode supported Unity bundle level formats and export real records as JSON."""
    destination = job / "levels.json"
    previous_level_files: set[str] = set()
    try:
        existing = json.loads(destination.read_text(encoding="utf-8"))
        if isinstance(existing, dict):
            previous_level_files = {
                level["file"]
                for group in existing.get("groups", []) if isinstance(group, dict)
                for level in group.get("levels", []) if isinstance(level, dict)
                if isinstance(level.get("file"), str)
            }
        if _cached_level_export_is_complete(existing, job):
            decoded_count, checked_count = _enrich_existing_juicetime_exports(job, existing)
            destination.write_text(json.dumps(_json_ready(existing), ensure_ascii=False, indent=2),
                                   encoding="utf-8")
            if checked_count:
                emit(f"JuiceTime: đã phân tích theo parser game {decoded_count:,}/{checked_count:,} level HDPK dạng chuỗi")
            emit(f"Đã có puzzle JSON đã giải mã; dùng lại: {destination}")
            return destination
    except (OSError, json.JSONDecodeError, AttributeError):
        pass

    emit("Đang giải mã UnityFS/HDPK và tìm level trong các Unity bundle...")
    groups, exports, parse_errors, bundles_scanned, scan_stats = _collect_puzzle_exports(apk_paths, emit, cancel)
    if cancel.is_set():
        raise LevelScanCancelled("Đã dừng khi quét dữ liệu level.")
    config_exports = [item for item in exports if item.get("kind") == "config"]
    exports = [item for item in exports if item.get("kind") != "config"]

    juicetime_checked = 0
    juicetime_decoded = 0
    for item in exports:
        if isinstance(item.get("data"), dict) and item["data"].get("format") == "ducapk-hdpk-text-level-v1":
            juicetime_checked += 1
            if _enrich_juicetime_level_record(item["data"]):
                juicetime_decoded += 1
    scan_stats["juicetime_level_records_checked"] = juicetime_checked
    scan_stats["juicetime_level_records_decoded"] = juicetime_decoded
    scan_stats["juicetime_mechanics"] = _aggregate_juicetime_mechanics(
        [item["data"] for item in exports
         if isinstance(item.get("data"), dict) and "decoded_juicetime" in item["data"]])

    # Move the previous heuristic output aside so it cannot be mistaken for real levels.
    legacy = job / "levels"
    legacy_target = job / "level_candidates_legacy"
    if legacy.is_dir() and any(legacy.glob("Level *.json")) and not legacy_target.exists():
        legacy.replace(legacy_target)
        (legacy_target / "README.txt").write_text(
            "Các JSON trong thư mục này là kết quả lọc heuristic cũ, không được xác minh là level.\n"
            "Dữ liệu puzzle đã giải mã nằm trong thư mục levels và được liệt kê trong levels.json.\n",
            encoding="utf-8")
        emit(f"Đã chuyển các file ứng viên cũ (không xác nhận là level) vào: {legacy_target}")

    for item in exports + config_exports:
        path = job / item["path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        if "raw" in item:
            path.write_bytes(item["raw"])
            continue
        path.write_text(json.dumps(_json_ready(item["data"]), ensure_ascii=False, indent=2),
                        encoding="utf-8")

    total = len(exports)
    result = {
        "format": "ducapk-unity-puzzles-v9",
        "source_apks": [_safe_unicode(str(path)) for path in apk_paths],
        "summary": {
            "puzzle_bundles_scanned": bundles_scanned,
            "groups_found": len(groups),
            "real_puzzle_layouts_exported": total,
            "parse_errors": parse_errors,
            **scan_stats,
        },
        "export_root": "levels",
        "groups": groups,
        "notes": [
            "Level N.json preserves each game's original decoded payload. HDPK semicolon records recognized as JuiceTimeLevelParser.TryParse are additionally expanded into decoded_juicetime; raw payload and unparsed trailing fields remain available. Other delimiter formats are preserved without guessed field meanings. Supported MessagePack puzzle TextAssets are exported with expanded layout fields and an original compact copy.",
            "For the Fruit Pick Puzzle YooAsset build, the tool decrypts PackageManifest, maps bundle hashes to logical names, reverses the BundleStream byte transform, and reads the HDPK offset table before writing each JSON level.",
            "Level N is the entry order within its source folder or HDPK pack; manifest entries also preserve the source asset identifiers where available.",
            "This includes puzzle layouts decoded from supported Unity bundles found in the selected APK splits. Content fetched later from a server is not included unless it is acquired and supplied to the tool.",
        ],
    }
    destination.write_text(json.dumps(_json_ready(result), ensure_ascii=False, indent=2),
                           encoding="utf-8")
    current_level_files = {item["path"].as_posix() for item in exports}
    stale_files_moved = 0
    stale_root = job / "level_export_stale_backup"
    for old_relative in previous_level_files - current_level_files:
        relative = Path(old_relative)
        if relative.is_absolute() or ".." in relative.parts:
            continue
        old_path = (job / relative).resolve()
        try:
            old_path.relative_to((job / "levels").resolve())
        except ValueError:
            continue
        if not old_path.is_file():
            continue
        backup_path = (stale_root / relative.relative_to("levels")).resolve()
        try:
            backup_path.relative_to(stale_root.resolve())
        except ValueError:
            continue
        backup_path.parent.mkdir(parents=True, exist_ok=True)
        if backup_path.exists():
            continue
        shutil.move(str(old_path), str(backup_path))
        stale_files_moved += 1
    if stale_files_moved:
        emit(f"Đã chuyển {stale_files_moved:,} file level cũ không còn trong lần giải mã này tới: {stale_root}")
    emit(f"Đã xuất {total:,} layout puzzle thật thành JSON; manifest: {destination}")
    if juicetime_checked:
        emit(f"JuiceTime: đã giải cấu trúc {juicetime_decoded:,}/{juicetime_checked:,} level dạng chuỗi theo parser của game")
    if scan_stats["opaque_bundle_candidates"]:
        emit(f"Phát hiện {scan_stats['opaque_bundle_candidates']:,}/{scan_stats['bundle_candidates_seen']:,} bundle Unity chưa giải mã/mở được; kiểm tra scan_stats.opaque_examples trong levels.json. Có thể cần codec hoặc khóa riêng của game.")
    if config_exports:
        emit(f"Đã giải mã {len(config_exports):,} tệp cấu hình (JSON AES và TextAsset từ bundle XXTEA); lưu tại: {job / 'decrypted_assets'}")
    if scan_stats["base64_payload_candidates"]:
        emit(f"Phát hiện {scan_stats['base64_payload_candidates']:,} tệp JSON chứa payload Base64; tool đã nhận diện lớp bọc nhưng chưa xác nhận giải mã được nội dung. Xem scan_stats.base64_payload_examples trong levels.json.")
    if scan_stats["bundle_candidates_seen"] and not bundles_scanned:
        emit("Có tệp giống Unity bundle nhưng chưa mở được tệp nào; chưa thể coi đây là APK không có dữ liệu.")
    if scan_stats["bundle_candidates_seen"] and not total and not scan_stats["opaque_bundle_candidates"]:
        emit("Bundle đọc được nhưng chưa thấy cấu trúc puzzle được hỗ trợ; cần bổ sung adapter cho schema của game này.")
    if parse_errors:
        emit(f"Có {parse_errors:,} asset không đọc/giải mã được; xem summary.parse_errors trong levels.json")
    return destination
