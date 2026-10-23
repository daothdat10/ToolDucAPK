"""Classify IL2CPP classes by declaring assembly: game code vs SDK vs Unity/.NET.

Unity compiles project scripts into Assembly-CSharp unless they use their own
assembly definition; SDKs normally ship their own DLLs. The studio's own
assemblies (e.g. an in-house framework) count as game code too; they are
recognised by the package name (com.<company>.<game>) or a "Game" token. Known SDK namespaces that are copied into Assets still go to SDK.
"""

from __future__ import annotations

import base64
import io
import json
import re
import sqlite3
import struct
import zipfile
from collections import Counter
from pathlib import Path

from .categories import category_for_class
from .layout import ClassLayout, split_type_name

UNITY_ASSEMBLY_PREFIXES = ("System", "Mono.", "UnityEngine", "Unity.")
UNITY_ASSEMBLIES = {"mscorlib", "netstandard", "Mono", "__Generated", "Il2CppDummyDll"}
GAME_TOKENS = {"game", "gameplay", "gamelogic", "gamecore"}
GENERIC_PACKAGE_TOKENS = {"com", "net", "org", "io", "co", "android", "app", "apps", "game",
                          "games", "unity", "studio", "studios", "mobile", "free", "play"}


def _strip_generic(segment: str) -> str:
    if segment.startswith("<"):
        match = re.match(r"^(<[^>]*>[\w$=]*)", segment)
        return match.group(1) if match else segment
    return segment.split("<", 1)[0].split("`", 1)[0]


def type_key(name: str) -> str:
    return ".".join(_strip_generic(part) for part in split_type_name(name))


def _assembly_name(name: str) -> str:
    return name[:-4] if name.lower().endswith(".dll") else name


def dump_assembly_map(dump_cs: Path) -> dict[str, str]:
    """Map type keys to assemblies using dump.cs image ranges and TypeDefIndex."""
    images: list[tuple[int, str]] = []
    mapping: dict[str, str | None] = {}
    namespace = ""
    with dump_cs.open("r", encoding="utf-8-sig", errors="replace") as source:
        for line in source:
            header = re.match(r"^// Image \d+: (.+?) - (\d+)", line)
            if header:
                images.append((int(header.group(2)), _assembly_name(header.group(1))))
                continue
            stripped = line.strip()
            if stripped.startswith("// Namespace:"):
                namespace = stripped.split(":", 1)[1].strip()
            elif "// TypeDefIndex:" in stripped and images:
                declaration, index = stripped.split("// TypeDefIndex:", 1)
                match = re.search(r"\b(?:class|struct|interface|enum)\s+(.+)", declaration)
                if not match:
                    continue
                name = match.group(1).split(" : ", 1)[0].strip()
                try:
                    type_index = int(index.strip())
                except ValueError:
                    continue
                assembly = images[0][1]
                for start, image in images:
                    if start > type_index:
                        break
                    assembly = image
                key = type_key(f"{namespace}.{name}" if namespace else name)
                mapping[key] = assembly if mapping.get(key, assembly) == assembly else None
    return {key: value for key, value in mapping.items() if value}


def cpp2il_assembly_map(table: Path) -> dict[str, str]:
    mapping: dict[str, str | None] = {}
    with table.open("r", encoding="utf-8-sig") as source:
        source.readline()
        for line in source:
            parts = line.rstrip("\r\n").split("\t")
            if len(parts) != 2:
                continue
            key = type_key(base64.b64decode(parts[0]).decode("utf-8", errors="replace"))
            assembly = _assembly_name(parts[1])
            mapping[key] = assembly if mapping.get(key, assembly) == assembly else None
    return {key: value for key, value in mapping.items() if value}


def package_name(apks: list[Path]) -> str | None:
    """Read the package name from resources.arsc of the base APK."""
    for apk in apks:
        try:
            with zipfile.ZipFile(apk) as archive:
                if "resources.arsc" not in archive.namelist():
                    continue
                data = archive.read("resources.arsc")
        except (OSError, zipfile.BadZipFile):
            continue
        offset = struct.unpack_from("<H", data, 2)[0]
        while offset + 8 <= len(data):
            chunk_type, _, size = struct.unpack_from("<HHI", data, offset)
            if chunk_type == 0x0200:
                name = data[offset + 12:offset + 268].decode("utf-16-le", errors="ignore")
                return name.split("\x00", 1)[0] or None
            if size <= 0:
                break
            offset += size
    return None


def package_tokens(package: str | None) -> set[str]:
    if not package:
        return set()
    return {token for token in re.split(r"[^a-z0-9]+", package.lower())
            if len(token) >= 4 and token not in GENERIC_PACKAGE_TOKENS}


def assembly_category(assembly: str, studio_tokens: set[str]) -> str:
    if assembly in UNITY_ASSEMBLIES or assembly.startswith(UNITY_ASSEMBLY_PREFIXES):
        return "unity"
    if assembly == "Assembly-CSharp":
        return "game"
    if assembly == "Assembly-CSharp-firstpass":
        return "sdk"
    tokens = [token for token in re.split(r"[^a-z0-9]+", assembly.lower()) if token]
    if any(token.endswith("sdk") for token in tokens):  # also the studio's own SDK DLLs
        return "sdk"
    if any(token in GAME_TOKENS for token in tokens):
        return "game"
    for token in tokens:
        if len(token) >= 4 and any(token == studio or studio.startswith(token) or
                                   token.startswith(studio) for studio in studio_tokens):
            return "game"
    return "sdk"


class CategoryResolver:
    """Category per class: declaring assembly first, namespace rules as fallback."""

    def __init__(self, class_names, assembly_map: dict[str, str] | None = None,
                 package: str | None = None):
        self.layout = ClassLayout(class_names)
        self.assembly_map = assembly_map or {}
        self.studio_tokens = package_tokens(package)

    def assembly(self, class_name: str) -> str | None:
        parts = type_key(self.layout.full_name(class_name)).split(".")
        for start in range(len(parts)):
            found = self.assembly_map.get(".".join(parts[start:]))
            if found:
                return found
        return None

    def category(self, class_name: str) -> str:
        full = self.layout.full_name(class_name)
        by_name = category_for_class(full)
        assembly = self.assembly(class_name)
        if by_name == "unity" or assembly is None:
            return by_name
        by_assembly = assembly_category(assembly, self.studio_tokens)
        # SDK sources copied into Assets compile into the game assemblies.
        if by_assembly == "game" and by_name == "sdk":
            return "sdk"
        return by_assembly


def _assembly_source(job: Path) -> Path | None:
    for candidate in (job / "il2cppdumper" / "dump.cs", job / "cpp2il_map" / "ducapk_assemblies.tsv"):
        if candidate.is_file():
            return candidate
    return None


def resolver_for_job(job: Path, connection: sqlite3.Connection) -> CategoryResolver:
    """Build (and cache in methods.sqlite) the class→assembly table for a job."""
    connection.execute("CREATE TABLE IF NOT EXISTS class_assemblies ("
                       "type_key TEXT PRIMARY KEY, assembly TEXT NOT NULL)")
    mapping = dict(connection.execute("SELECT type_key, assembly FROM class_assemblies"))
    source = _assembly_source(job)
    if not mapping and source is not None:
        mapping = (dump_assembly_map(source) if source.suffix == ".cs"
                   else cpp2il_assembly_map(source))
        connection.executemany("INSERT OR REPLACE INTO class_assemblies VALUES (?,?)",
                               mapping.items())
        connection.commit()
    info_path = job / "job.json"
    info = json.loads(info_path.read_text(encoding="utf-8")) if info_path.is_file() else {}
    names = [name for (name,) in connection.execute("SELECT DISTINCT class_name FROM methods")]
    return CategoryResolver(names, mapping, info.get("package_name"))


def assembly_report(job: Path, connection: sqlite3.Connection,
                    resolver: CategoryResolver) -> dict:
    """Native method counts per assembly and the category each one was given."""
    counts: Counter[tuple[str, str]] = Counter()
    for class_name, methods in connection.execute(
            "SELECT class_name, COUNT(*) FROM methods WHERE export_index IS NOT NULL "
            "GROUP BY class_name"):
        assembly = resolver.assembly(class_name) or "(không xác định)"
        counts[(assembly, resolver.category(class_name))] += methods
    rows = [{"assembly": assembly, "category": category, "native_methods": total}
            for (assembly, category), total in counts.most_common()]
    report = {"studio_tokens": sorted(resolver.studio_tokens), "assemblies": rows}
    (job / "assemblies.json").write_text(json.dumps(report, ensure_ascii=False, indent=2),
                                         encoding="utf-8")
    return report
