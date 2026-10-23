"""Build a self-contained levelEditor.html from a LevelData C# schema and APK metadata.

The user's LevelData.cs is the contract for the JSON the editor writes. Types it
references but does not declare are resolved from the APK's recovered IL2CPP
declarations (Il2CppDumper dump.cs or Cpp2IL diffable-cs). The APK also supplies
mechanic enums and the level records DucAPK extracted into levels.json, which the
editor can open and convert to the LevelData schema.
"""

from __future__ import annotations

from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import threading
from typing import Any

from .categories import category_for_class


TEMPLATE = Path(__file__).with_name("level_editor_template.html")
DATA_PLACEHOLDER = "/*__DUCAPK_DATA__*/null"
MAX_SAMPLE_LEVELS = 400
MAX_SAMPLE_BYTES = 12 * 1024 * 1024
MAX_MECHANIC_ENUMS = 80
MAX_APK_LEVEL_CLASSES = 40

_LITERAL_OR_COMMENT = re.compile(
    r'(\$?@"(?:[^"]|"")*"|\$?"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])+\')'
    r"|//[^\n]*|/\*.*?\*/", re.S)
_PLACEHOLDER = re.compile(r"\x01(\d+)\x01")
_IDENT = re.compile(r"[A-Za-z_]\w*$")
_MODIFIERS = {
    "public", "private", "protected", "internal", "static", "readonly", "const",
    "volatile", "new", "override", "virtual", "abstract", "sealed", "unsafe",
    "extern", "partial", "required", "async", "file", "ref",
}
_TYPE_KEYWORD = re.compile(
    r"^(class|struct|enum|interface|record)(?:\s+(?:class|struct))?\s+"
    r"([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)")
_INT_RANGES = {
    "int": (-2 ** 31, 2 ** 31 - 1), "int32": (-2 ** 31, 2 ** 31 - 1),
    "uint": (0, 2 ** 32 - 1), "uint32": (0, 2 ** 32 - 1),
    "long": (-2 ** 63, 2 ** 63 - 1), "int64": (-2 ** 63, 2 ** 63 - 1),
    "ulong": (0, 2 ** 64 - 1), "uint64": (0, 2 ** 64 - 1),
    "short": (-32768, 32767), "int16": (-32768, 32767),
    "ushort": (0, 65535), "uint16": (0, 65535),
    "byte": (0, 255), "sbyte": (-128, 127),
}
_FLOAT_TYPES = {"float", "double", "decimal", "single"}
_LIST_TYPES = {"list", "ilist", "icollection", "ienumerable", "ireadonlylist",
               "ireadonlycollection", "hashset", "queue", "stack", "linkedlist",
               "observablecollection", "sortedset"}
_DICT_TYPES = {"dictionary", "idictionary", "sorteddictionary", "ireadonlydictionary",
               "concurrentdictionary", "sortedlist"}
_UNITY_STRUCTS = {
    "Vector2": [("x", "float"), ("y", "float")],
    "Vector3": [("x", "float"), ("y", "float"), ("z", "float")],
    "Vector4": [("x", "float"), ("y", "float"), ("z", "float"), ("w", "float")],
    "Quaternion": [("x", "float"), ("y", "float"), ("z", "float"), ("w", "float")],
    "Vector2Int": [("x", "int"), ("y", "int")],
    "Vector3Int": [("x", "int"), ("y", "int"), ("z", "int")],
    "Color": [("r", "float"), ("g", "float"), ("b", "float"), ("a", "float")],
    "Color32": [("r", "byte"), ("g", "byte"), ("b", "byte"), ("a", "byte")],
    "Rect": [("x", "float"), ("y", "float"), ("width", "float"), ("height", "float")],
    "RectInt": [("x", "int"), ("y", "int"), ("width", "int"), ("height", "int")],
}
_ENGINE_BASES = {"object", "monobehaviour", "scriptableobject", "behaviour", "component",
                 "valuetype", "system.object", "unityengine.object"}
_MECHANIC_ENUM_NAME = re.compile(
    r"(Type|Kind|Element|Mechanic|Obstacle|Booster|Blocker|Tile|Cell|Piece|Item|Color|"
    r"Colour|Status|State|Shape|Direction|Goal|Target|Layer|Block|Gem|Candy|Fruit)s?$")
_MECHANIC_STRONG = re.compile(r"Element|Mechanic|Obstacle|Booster|Blocker|Tile|Cell|Piece|Block|Goal")
_NOT_GAMEPLAY = re.compile(
    r"Ad(s|Type|Network|Format)?$|^Ad|Iap|Purchase|Analytic|Network|Login|Audio|Sound|Music|"
    r"Popup|Panel|Scene|Font|Language|Locali|Platform|Log|Http|Request|Response|Consent|"
    r"Notification|Store|Shop|Server|Tween|Ease|Haptic|Vibrat|Debug|Quality|Render|Shader",
    re.I)


class LevelEditorError(ValueError):
    pass


# ---------------------------------------------------------------- C# reading
def _decode_literal(literal: str) -> str:
    literal = literal.lstrip("$")
    if literal.startswith("@"):
        return literal[2:-1].replace('""', '"')
    body = literal[1:-1]
    escapes = {"n": "\n", "t": "\t", "r": "\r", "0": "\0", "\\": "\\", '"': '"', "'": "'"}
    return re.sub(r"\\(.)", lambda m: escapes.get(m.group(1), m.group(1)), body)


def _split_top(text: str, separator: str = ",", angle: bool = True) -> list[str]:
    """Split on a separator outside (), [], {} and (for type text) <> nesting."""
    parts, depth, start = [], 0, 0
    opening, closing = ("([{<", ")]}>") if angle else ("([{", ")]}")
    for index, char in enumerate(text):
        if char in opening:
            depth += 1
        elif char in closing:
            depth = max(0, depth - 1)
        elif char == separator and depth == 0:
            parts.append(text[start:index])
            start = index + 1
    parts.append(text[start:])
    return [part.strip() for part in parts if part.strip()]


def _parse_attribute_list(text: str, strings: list[str]) -> list[dict[str, Any]]:
    attributes = []
    for item in _split_top(text):
        item = re.sub(r"^[a-z]+\s*:\s*", "", item)
        match = re.match(r"([A-Za-z_][\w.]*)\s*(?:\((.*)\))?\s*$", item, re.S)
        if not match:
            continue
        name = match.group(1).split(".")[-1]
        if name.endswith("Attribute") and name != "Attribute":
            name = name[:-len("Attribute")]
        args = [_restore(arg, strings) for arg in _split_top(match.group(2) or "")]
        attributes.append({"name": name, "args": args})
    return attributes


def _restore(text: str, strings: list[str]) -> Any:
    """Return the string literal a placeholder stands for, else the trimmed source text."""
    text = text.strip()
    whole = _PLACEHOLDER.fullmatch(text)
    if whole:
        return strings[int(whole.group(1))]
    return _PLACEHOLDER.sub(lambda m: json.dumps(strings[int(m.group(1))]), text)


def _take_attributes(text: str, strings: list[str]) -> tuple[list[dict[str, Any]], str]:
    attributes: list[dict[str, Any]] = []
    text = text.strip()
    while text.startswith("["):
        depth = 0
        for index, char in enumerate(text):
            if char == "[":
                depth += 1
            elif char == "]":
                depth -= 1
                if depth == 0:
                    break
        else:
            break
        attributes.extend(_parse_attribute_list(text[1:index], strings))
        text = text[index + 1:].strip()
    return attributes, text


def _take_modifiers(text: str) -> tuple[list[str], str]:
    modifiers = []
    while True:
        match = re.match(r"([a-z]+)\b\s*", text)
        if not match or match.group(1) not in _MODIFIERS:
            return modifiers, text.strip()
        modifiers.append(match.group(1))
        text = text[match.end():]


def _split_type(text: str) -> tuple[str, str] | None:
    """Split `Dictionary<int, List<Foo>>[] name = x` into its type and the remainder."""
    text = text.strip()
    match = re.match(r"(?:global::)?[A-Za-z_@][\w.`]*", text)
    if not match:
        return None
    index, length = match.end(), len(text)
    while index < length:
        cursor = index
        while cursor < length and text[cursor].isspace():
            cursor += 1
        if cursor >= length:
            break
        char = text[cursor]
        if char == "<":
            depth = 0
            for end in range(cursor, length):
                if text[end] == "<":
                    depth += 1
                elif text[end] == ">":
                    depth -= 1
                    if depth == 0:
                        break
            else:
                return None
            index = end + 1
        elif char == "[":
            end = text.find("]", cursor)
            if end < 0 or text[cursor + 1:end].strip(" ,"):
                break
            index = end + 1
        elif char == "?":
            index = cursor + 1
        elif char == "." and (nested := re.match(r"\.[A-Za-z_]\w*", text[cursor:])):
            index = cursor + nested.end()
        else:
            break
    return re.sub(r"\s+", "", text[:index]).replace("global::", ""), text[index:].strip()


def _top_level_index(text: str, char: str) -> int:
    depth = 0
    for index, current in enumerate(text):
        if current in "([{<":
            depth += 1
        elif current in ")]}>":
            depth = max(0, depth - 1)
        elif current == char and depth == 0:
            return index
    return -1


def _eval_enum_value(expression: str, known: dict[str, int]) -> int | None:
    expression = re.sub(r"\(\s*(?:int|uint|long|ulong|short|ushort|byte|sbyte)\s*\)", "", expression)
    expression = re.sub(r"0[xX][0-9A-Fa-f]+", lambda m: str(int(m.group(0), 16)), expression)
    expression = re.sub(r"(?<=\d)[uUlL]+\b", "", expression)

    def name_value(match: re.Match) -> str:
        name = match.group(0).split(".")[-1]
        if name not in known:
            raise KeyError(name)
        return f"({known[name]})"

    try:
        expression = re.sub(r"[A-Za-z_][\w.]*", name_value, expression)
    except KeyError:
        return None
    if not re.fullmatch(r"[\d\s|&^~<>+\-*()]+", expression):
        return None
    try:
        value = eval(expression, {"__builtins__": {}}, {})  # digits/operators only
    except Exception:
        return None
    return int(value) if isinstance(value, int) else None


def _new_type_frame(kind: str, name: str, namespace: str, outer: dict | None,
                    attributes: list, modifiers: list, bases: list[str]) -> dict[str, Any]:
    outer_name = outer["qualified_name"] if outer else ""
    qualified_name = f"{outer_name}.{name}" if outer_name else name
    return {"frame": "type", "kind": kind, "name": name.split(".")[-1],
            "qualified_name": qualified_name, "namespace": namespace,
            "outer": outer["key"] if outer else None,
            "key": f"{namespace}.{qualified_name}" if namespace else qualified_name,
            "attributes": attributes, "modifiers": modifiers, "bases": bases,
            "fields": [], "members": [], "buffer": "", "previous_value": -1,
            "last_property": None}


def _type_header(rest: str) -> tuple[str, str, list[str]] | None:
    match = _TYPE_KEYWORD.match(rest)
    if not match:
        return None
    kind, name = match.group(1), match.group(2)
    tail = rest[match.end():].strip()
    if tail.startswith("<"):
        depth = 0
        for index, char in enumerate(tail):
            depth += char == "<"
            depth -= char == ">"
            if depth == 0:
                tail = tail[index + 1:].strip()
                break
    if tail.startswith("("):
        tail = tail[tail.find(")") + 1:].strip() if ")" in tail else ""
    bases: list[str] = []
    if tail.startswith(":"):
        tail = re.split(r"\bwhere\b", tail[1:], 1)[0]
        bases = [re.sub(r"\s+", "", base) for base in _split_top(tail)]
    return ("class" if kind == "record" else kind), name, bases


def _parse_fields(frame: dict, statement: str, strings: list[str]) -> None:
    attributes, rest = _take_attributes(statement, strings)
    modifiers, rest = _take_modifiers(rest)
    if not rest:
        return
    if rest.startswith("=") and frame["last_property"] is not None:
        frame["last_property"]["default"] = _restore(rest[1:], strings)
        frame["last_property"] = None
        return
    frame["last_property"] = None
    if re.match(r"(?:using|event|delegate|operator|implicit|explicit)\b", rest) or "=>" in rest:
        return
    parenthesis, equals = _top_level_index(rest, "("), _top_level_index(rest, "=")
    if parenthesis >= 0 and (equals < 0 or parenthesis < equals):
        return  # method/constructor declaration without body
    split = _split_type(rest)
    if split is None:
        return
    type_text, declarators = split
    for declarator in _split_top(declarators):
        name, _, default = declarator.partition("=")
        name = name.strip().lstrip("@")
        if not _IDENT.match(name):
            continue
        frame["fields"].append({
            "name": name, "type": type_text, "attributes": attributes,
            "modifiers": modifiers, "property": False,
            "default": _restore(default, strings) if default.strip() else None,
        })


def _parse_enum_members(frame: dict, statement: str, strings: list[str]) -> None:
    known = {name: value for value, name in frame["members"]}
    for item in _split_top(statement, angle=False):
        _, item = _take_attributes(item, strings)
        modifiers, item = _take_modifiers(item)
        if "const" in modifiers:
            split = _split_type(item)
            if split is None:
                continue
            item = split[1]
        elif modifiers:
            continue  # `public int value__` in IL2CPP dumps
        name, _, expression = item.partition("=")
        name = name.strip()
        if not _IDENT.match(name) or name == "value__":
            continue
        if expression.strip():
            value = _eval_enum_value(expression, known)
            if value is None:
                continue
        else:
            value = frame["previous_value"] + 1
        frame["previous_value"] = value
        frame["members"].append((value, name))
        known[name] = value


def _finish_type(frame: dict) -> dict[str, Any]:
    result = {key: frame[key] for key in ("kind", "name", "qualified_name", "namespace",
                                          "outer", "key", "attributes", "modifiers", "bases")}
    if frame["kind"] == "enum":
        result["members"] = frame["members"]
    else:
        result["fields"] = frame["fields"]
    return result


def parse_csharp_types(source: str, default_namespace: str = "") -> list[dict[str, Any]]:
    """Parse class/struct/enum declarations and their serializable members."""
    strings: list[str] = []

    def keep(match: re.Match) -> str:
        if match.group(1) is None:
            return " "
        strings.append(_decode_literal(match.group(1)))
        return f"\x01{len(strings) - 1}\x01"

    text = _LITERAL_OR_COMMENT.sub(keep, source)
    text = re.sub(r"(?m)^[ \t]*#.*$", "", text)
    root = {"frame": "namespace", "namespace": default_namespace, "buffer": "", "type": None}
    stack: list[dict[str, Any]] = [root]
    types: list[dict[str, Any]] = []
    position = 0
    for match in re.finditer(r"[{};]", text):
        segment, delimiter = text[position:match.start()], match.group()
        position = match.end()
        top = stack[-1]
        if top["frame"] == "skip":
            if top.get("property") is not None:
                top["body"] += segment + delimiter
            if delimiter == "{":
                top["depth"] += 1
            elif delimiter == "}":
                top["depth"] -= 1
                if top["depth"] == 0:
                    stack.pop()
                    if top.get("property") is not None:
                        _finish_property(stack[-1], top)
            continue
        if top["frame"] == "init":
            top["owner"]["buffer"] += segment + delimiter
            if delimiter == "{":
                top["depth"] += 1
            elif delimiter == "}":
                top["depth"] -= 1
                if top["depth"] == 0:
                    stack.pop()
            continue

        statement = top["buffer"] + segment
        top["buffer"] = ""
        if delimiter == ";":
            _statement(top, statement, strings)
        elif delimiter == "{":
            _open_block(stack, top, statement, strings)
        else:
            if statement.strip():
                _statement(top, statement, strings)
            if top is root:
                continue
            stack.pop()
            if top["frame"] == "type":
                types.append(_finish_type(top))
    return types


def _statement(frame: dict, statement: str, strings: list[str]) -> None:
    if not statement.strip():
        return
    if frame["frame"] == "namespace":
        match = re.match(r"\s*namespace\s+([\w.]+)\s*$", statement)
        if match:
            frame["namespace"] = match.group(1)
        return
    if frame["kind"] == "enum":
        _parse_enum_members(frame, statement, strings)
    elif frame["kind"] in {"class", "struct"}:
        _parse_fields(frame, statement, strings)


def _open_block(stack: list[dict], top: dict, statement: str, strings: list[str]) -> None:
    attributes, rest = _take_attributes(statement, strings)
    modifiers, rest = _take_modifiers(rest)
    namespace = top["namespace"]
    namespace_match = re.match(r"namespace\s+([\w.]+)\s*$", rest)
    if namespace_match and top["frame"] == "namespace":
        inner = namespace_match.group(1)
        stack.append({"frame": "namespace", "buffer": "", "type": None,
                      "namespace": f"{namespace}.{inner}" if namespace else inner})
        return
    header = _type_header(rest)
    if header is not None:
        kind, name, bases = header
        outer = top if top["frame"] == "type" else None
        stack.append(_new_type_frame(kind, name, namespace, outer, attributes, modifiers, bases))
        return
    if top["frame"] == "type" and top["kind"] in {"class", "struct"}:
        equals = _top_level_index(rest, "=")
        parenthesis = _top_level_index(rest, "(")
        if equals >= 0 and "=>" not in rest and (parenthesis < 0 or equals < parenthesis):
            top["buffer"] = statement + "{"
            stack.append({"frame": "init", "owner": top, "depth": 1})
            return
        split = _split_type(rest) if parenthesis < 0 else None
        if split and _IDENT.match(split[1].lstrip("@")):
            stack.append({"frame": "skip", "depth": 1, "body": "", "property": {
                "name": split[1].lstrip("@"), "type": split[0], "attributes": attributes,
                "modifiers": modifiers}})
            return
    stack.append({"frame": "skip", "depth": 1})


def _finish_property(frame: dict, block: dict) -> None:
    if frame.get("frame") != "type" or frame.get("kind") not in {"class", "struct"}:
        return
    body = block["body"]
    if not re.search(r"\bget\b", body) or not re.search(r"\b(?:set|init)\b", body):
        return
    if re.search(r"\bprivate\s+set\b", body) and not any(
            a["name"] in {"JsonProperty", "JsonPropertyName", "DataMember"}
            for a in block["property"]["attributes"]):
        return
    entry = {**block["property"], "property": True, "default": None}
    frame["fields"].append(entry)
    frame["last_property"] = entry


# ---------------------------------------------------------------- type library
class TypeLibrary:
    """Types from parsed sources plus lazily parsed blocks of large IL2CPP dumps."""

    def __init__(self, source: str):
        self.source = source
        self.types: dict[str, dict[str, Any]] = {}
        self.by_short: dict[str, list[str]] = {}
        self._blocks: list[dict[str, Any]] = []
        self._block_index: dict[str, list[int]] = {}

    def add_types(self, types: list[dict[str, Any]], origin: str) -> None:
        for item in types:
            if item["key"] in self.types:
                continue
            item["origin"] = origin
            self.types[item["key"]] = item
            self.by_short.setdefault(item["name"], []).append(item["key"])

    def add_dump(self, text: str, origin: str) -> int:
        """Index Il2CppDumper dump.cs by `// Namespace:` blocks without parsing all of it."""
        starts = [(m.start(), m.group(1).strip()) for m in
                  re.finditer(r"(?m)^// Namespace: ?([^\r\n]*)", text)]
        for index, (start, namespace) in enumerate(starts):
            end = starts[index + 1][0] if index + 1 < len(starts) else len(text)
            head = text[start:min(end, start + 4000)]
            declaration = re.search(
                r"(?m)^[^\n/{;]*?\b(class|struct|enum|interface)\s+([A-Za-z_][\w.]*)", head)
            if not declaration:
                continue
            block_id = len(self._blocks)
            self._blocks.append({"text": text, "start": start, "end": end, "namespace": namespace,
                                 "kind": declaration.group(1), "origin": origin,
                                 "names": [declaration.group(2)], "loaded": False})
            self._block_index.setdefault(declaration.group(2).split(".")[-1], []).append(block_id)
        return len(starts)

    def add_file(self, path: Path, origin: str) -> None:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return
        names = [m.group(2) for m in re.finditer(r"\b(class|struct|enum|interface)\s+([A-Za-z_]\w*)", text)]
        if not names:
            return
        kind = re.search(r"\b(class|struct|enum|interface)\s+[A-Za-z_]", text).group(1)
        block_id = len(self._blocks)
        self._blocks.append({"text": text, "start": 0, "end": len(text), "namespace": "",
                             "kind": kind, "origin": origin, "names": names, "loaded": False})
        for name in names:
            self._block_index.setdefault(name, []).append(block_id)

    def _load_block(self, block_id: int) -> None:
        block = self._blocks[block_id]
        if block["loaded"]:
            return
        block["loaded"] = True
        try:
            parsed = parse_csharp_types(block["text"][block["start"]:block["end"]], block["namespace"])
        except Exception:
            parsed = []
        self.add_types(parsed, block["origin"])

    def candidates(self, short: str) -> list[dict[str, Any]]:
        for block_id in self._block_index.get(short, []):
            self._load_block(block_id)
        return [self.types[key] for key in self.by_short.get(short, [])]

    def enum_blocks(self) -> list[int]:
        return [index for index, block in enumerate(self._blocks) if block["kind"] == "enum"]

    def load_block_types(self, block_id: int) -> list[dict[str, Any]]:
        self._load_block(block_id)
        names = set(self._blocks[block_id]["names"])
        return [self.types[key] for name in names for key in self.by_short.get(name.split(".")[-1], [])]

    def class_block_names(self, pattern: re.Pattern) -> list[str]:
        return sorted({block["names"][0].split(".")[-1] for block in self._blocks
                       if block["kind"] in {"class", "struct"} and pattern.search(block["names"][0])})

    @property
    def indexed(self) -> int:
        return len(self._blocks) + len(self.types)


def _pick(candidates: list[dict[str, Any]], namespace: str) -> dict[str, Any] | None:
    if not candidates:
        return None
    same = [c for c in candidates if c["namespace"] == namespace]
    if same:
        return same[0]
    game = [c for c in candidates if category_for_class(c["key"]) == "game"]
    return (game or candidates)[0]


# ---------------------------------------------------------------- schema
class SchemaBuilder:
    def __init__(self, user: TypeLibrary, apk: TypeLibrary):
        self.user, self.apk = user, apk
        self.classes: dict[str, dict[str, Any]] = {}
        self.enums: dict[str, dict[str, Any]] = {}
        self.unresolved: dict[str, list[str]] = {}
        self._pending: list[dict[str, Any]] = []

    # resolution ---------------------------------------------------------
    def find(self, name: str, namespace: str, outer: str | None) -> dict[str, Any] | None:
        short = name.split(".")[-1]
        dotted = "." in name
        for library in (self.user, self.apk):
            candidates = library.candidates(short)
            if not candidates:
                continue
            if dotted:
                exact = [c for c in candidates if c["key"] == name or c["key"].endswith("." + name)
                         or c["qualified_name"] == name]
                if exact:
                    return _pick(exact, namespace)
            chain = outer
            while chain:
                nested = [c for c in candidates if c["key"] == f"{chain}.{short}"]
                if nested:
                    return nested[0]
                parent = library.types.get(chain) or self.user.types.get(chain)
                chain = parent["outer"] if parent else None
            if library is self.user or short not in _UNITY_STRUCTS:
                return _pick(candidates, namespace)
        return None

    def describe(self, type_text: str, namespace: str, outer: str | None, where: str) -> dict[str, Any]:
        text = type_text.replace(" ", "")
        nullable = False
        ranks: list[int] = []
        while True:
            if text.endswith("?"):
                nullable, text = True, text[:-1]
            elif text.endswith("]") and "[" in text:
                open_index = text.rfind("[")
                ranks.insert(0, text[open_index:].count(",") + 1)
                text = text[:open_index]
            else:
                break
        description = self._describe_core(text, namespace, outer, where)
        for rank in reversed(ranks):
            for _ in range(rank):
                description = {"k": "list", "of": description}
            if rank > 1:
                description["md"] = rank
        if nullable:
            description = {**description, "nullable": True}
        return description

    def _describe_core(self, text: str, namespace: str, outer: str | None, where: str) -> dict[str, Any]:
        generic_args: list[str] = []
        if text.endswith(">") and "<" in text:
            open_index = text.find("<")
            generic_args = _split_top(text[open_index + 1:-1])
            text = text[:open_index]
        base = re.sub(r"`\d+$", "", text)
        short = base.split(".")[-1]
        lowered = short.lower()
        if generic_args:
            if lowered == "nullable" and len(generic_args) == 1:
                return {**self.describe(generic_args[0], namespace, outer, where), "nullable": True}
            if lowered in _LIST_TYPES and len(generic_args) == 1:
                return {"k": "list", "of": self.describe(generic_args[0], namespace, outer, where)}
            if lowered in _DICT_TYPES and len(generic_args) == 2:
                return {"k": "dict", "key": self.describe(generic_args[0], namespace, outer, where),
                        "val": self.describe(generic_args[1], namespace, outer, where)}
            self.unresolved.setdefault(f"{base}<{', '.join(generic_args)}>", []).append(where)
            return {"k": "raw", "cs": f"{base}<{','.join(generic_args)}>"}
        if lowered in _INT_RANGES:
            low, high = _INT_RANGES[lowered]
            return {"k": "int", "min": low, "max": high}
        if lowered in _FLOAT_TYPES:
            return {"k": "float"}
        if lowered in {"bool", "boolean"}:
            return {"k": "bool"}
        if lowered == "string":
            return {"k": "string"}
        if lowered == "char":
            return {"k": "char"}
        if lowered in {"object", "jtoken", "jobject", "jarray", "dynamic"}:
            return {"k": "raw", "cs": base}
        found = self.find(base, namespace, outer)
        if found is None and short in _UNITY_STRUCTS:
            return self._unity_struct(short)
        if found is None:
            self.unresolved.setdefault(base, []).append(where)
            return {"k": "raw", "cs": base}
        if found["kind"] == "enum":
            return {"k": "enum", "ref": self._enum(found)}
        if found["kind"] in {"class", "struct"}:
            return {"k": "obj", "ref": self._class(found)}
        self.unresolved.setdefault(base, []).append(where)
        return {"k": "raw", "cs": base}

    def _unity_struct(self, short: str) -> dict[str, Any]:
        key = f"UnityEngine.{short}"
        if key not in self.classes:
            self.classes[key] = {
                "name": short, "ns": "UnityEngine", "src": "unity", "kind": "struct",
                "fields": [{"name": name, "json": name, "cs": kind,
                            "type": self.describe(kind, "", None, key)} for name, kind in _UNITY_STRUCTS[short]],
            }
        return {"k": "obj", "ref": key}

    def _enum(self, item: dict[str, Any]) -> str:
        key = item["key"]
        if key not in self.enums:
            self.enums[key] = {
                "name": item["name"], "ns": item["namespace"],
                "src": "leveldata" if item.get("origin") == "user" else "apk",
                "flags": any(a["name"] == "Flags" for a in item["attributes"]),
                "string": _uses_string_enum(item["attributes"]),
                "members": [[value, name] for value, name in item["members"]],
            }
        return key

    def _class(self, item: dict[str, Any]) -> str:
        key = item["key"]
        if key not in self.classes:
            self.classes[key] = {"name": item["name"], "ns": item["namespace"],
                                 "src": "leveldata" if item.get("origin") == "user" else "apk",
                                 "kind": item["kind"], "fields": []}
            self._pending.append(item)
        return key

    def build(self, root: dict[str, Any]) -> str:
        root_key = self._class(root)
        while self._pending:
            item = self._pending.pop()
            self.classes[item["key"]]["fields"] = self._fields_with_bases(item, set())
        return root_key

    def _fields_with_bases(self, item: dict[str, Any], seen: set[str]) -> list[dict[str, Any]]:
        seen.add(item["key"])
        inherited: list[dict[str, Any]] = []
        for base_name in item.get("bases", [])[:1]:
            if base_name.lower() in _ENGINE_BASES or base_name.lower().split("<")[0] in _ENGINE_BASES:
                continue
            base = self.find(re.sub(r"<.*$", "", base_name), item["namespace"], item["outer"])
            if base and base["kind"] == "class" and base["key"] not in seen:
                inherited = self._fields_with_bases(base, seen)
                if base["key"] in self.classes:
                    self.classes[item["key"]]["base"] = base["key"]
        own = []
        for field in item.get("fields", []):
            if not _is_serialized(field):
                continue
            own.append(self._field(field, item))
        names = {field["json"] for field in own}
        return [field for field in inherited if field["json"] not in names] + own

    def _field(self, field: dict[str, Any], owner: dict[str, Any]) -> dict[str, Any]:
        where = f"{owner['qualified_name']}.{field['name']}"
        description = self.describe(field["type"], owner["namespace"], owner["key"], where)
        attributes = {a["name"]: a["args"] for a in field["attributes"]}
        result: dict[str, Any] = {"name": field["name"], "json": _json_name(field), "cs": field["type"],
                                  "type": description}
        if field["property"]:
            result["prop"] = True
        if "Tooltip" in attributes and attributes["Tooltip"]:
            result["tooltip"] = str(attributes["Tooltip"][0])
        if "Header" in attributes and attributes["Header"]:
            result["header"] = str(attributes["Header"][0])
        if "Range" in attributes and len(attributes["Range"]) == 2:
            low, high = (_number(arg) for arg in attributes["Range"])
            if low is not None and high is not None:
                result["range"] = [low, high]
        if "Min" in attributes and attributes["Min"] and _number(attributes["Min"][0]) is not None:
            result["min"] = _number(attributes["Min"][0])
        if "TextArea" in attributes or "Multiline" in attributes:
            result["multiline"] = True
        if _uses_string_enum(field["attributes"]):
            result["string_enum"] = True
        default = self._default(field.get("default"), description)
        if default is not None:
            result["default"] = default
        return result

    def _default(self, raw: Any, description: dict[str, Any]) -> Any:
        if raw is None:
            return None
        kind = description["k"]
        if kind == "string" and isinstance(raw, str) and not raw.startswith("new"):
            return raw if not raw.startswith(("string.", "String.")) else ""
        if not isinstance(raw, str):
            return None
        value = raw.strip()
        if kind in {"int", "float"}:
            number = _number(value)
            if number is not None:
                return int(number) if kind == "int" else float(number)
        if kind == "bool" and value in {"true", "false"}:
            return value == "true"
        if kind == "enum":
            members = self.enums[description["ref"]]["members"]
            total = 0
            matched = False
            for part in value.split("|"):
                name = part.strip().split(".")[-1]
                for member_value, member_name in members:
                    if member_name == name:
                        total |= member_value
                        matched = True
            if matched:
                return total
            number = _number(value.replace("(int)", ""))
            return int(number) if number is not None else None
        return None


def _number(text: Any) -> float | int | None:
    if isinstance(text, (int, float)):
        return text
    if not isinstance(text, str):
        return None
    value = re.sub(r"(?<=[\d.])[fFdDmMuUlL]+$", "", text.strip())
    try:
        if re.fullmatch(r"-?0[xX][0-9A-Fa-f]+", value):
            return int(value, 16)
        if re.fullmatch(r"-?\d+", value):
            return int(value)
        return float(value)
    except ValueError:
        return None


def _uses_string_enum(attributes: list[dict[str, Any]]) -> bool:
    return any(a["name"] == "JsonConverter" and any("StringEnumConverter" in str(arg) for arg in a["args"])
               for a in attributes)


def _json_name(field: dict[str, Any]) -> str:
    for attribute in field["attributes"]:
        if attribute["name"] in {"JsonProperty", "JsonPropertyName"} and attribute["args"]:
            first = attribute["args"][0]
            if isinstance(first, str) and not first.startswith(("PropertyName", "Order", "Required")):
                return first
            for arg in attribute["args"]:
                match = re.match(r"PropertyName\s*=\s*\"(.*)\"", str(arg))
                if match:
                    return match.group(1)
        if attribute["name"] == "DataMember":
            for arg in attribute["args"]:
                match = re.match(r"Name\s*=\s*\"(.*)\"", str(arg))
                if match:
                    return match.group(1)
    return field["name"]


def _is_serialized(field: dict[str, Any]) -> bool:
    modifiers = set(field["modifiers"])
    names = {a["name"] for a in field["attributes"]}
    if modifiers & {"static", "const", "readonly"} or names & {"NonSerialized", "JsonIgnore", "IgnoreDataMember"}:
        return False
    if names & {"SerializeField", "SerializeReference", "JsonProperty", "JsonPropertyName", "DataMember"}:
        return True
    return "public" in modifiers


# ---------------------------------------------------------------- APK context
def _load_apk_library(job: Path | None, emit) -> TypeLibrary:
    library = TypeLibrary("apk")
    if job is None:
        return library
    dump = job / "il2cppdumper" / "dump.cs"
    if dump.is_file():
        try:
            count = library.add_dump(dump.read_text(encoding="utf-8", errors="replace"), "apk")
            emit(f"Đọc metadata APK: {count:,} kiểu trong {dump}")
        except OSError as error:
            emit(f"Không đọc được {dump}: {error}")
    for folder in (job / "cpp2il_types", job / "cpp2il_map"):
        if folder.is_dir():
            files = sorted(p for p in folder.rglob("*.cs") if p.is_file())
            for path in files:
                library.add_file(path, "apk")
            if files:
                emit(f"Đọc metadata APK (Cpp2IL): {len(files):,} file C# trong {folder}")
    return library


def ensure_cpp2il_types(job: Path, emit, cancel: threading.Event) -> None:
    """Cpp2IL's method map has no fields/enums; also write its diffable-cs view once."""
    if (job / "il2cppdumper" / "dump.cs").is_file():
        return
    if not (job / "cpp2il_map").is_dir() or (job / "cpp2il_types" / "DiffableCs").is_dir():
        return
    from . import runner
    if not runner.CPP2IL.is_file() or not runner.DOTNET.is_file():
        emit("Thiếu Cpp2IL trong tools/Cpp2IL; không lấy được field/enum của game.")
        return
    unity_version = runner._detect_unity_version(job)
    if unity_version is None:
        emit("Không tìm thấy phiên bản Unity để xuất kiểu C# bằng Cpp2IL.")
        return
    output = job / "cpp2il_types"
    output.mkdir(exist_ok=True)
    command = [str(runner.DOTNET), str(runner.CPP2IL),
               "--force-binary-path", str(job / "input" / "libil2cpp.so"),
               "--force-metadata-path", str(runner._metadata_path(job, emit)),
               "--force-unity-version", unity_version,
               "--output-as", "diffable-cs", "--output-to", str(output), "--low-memory-mode"]
    env = os.environ.copy()
    env["DOTNET_ROOT"] = str(runner.ROOT / "tools" / "dotnet")
    emit("Xuất class/field/enum của game bằng Cpp2IL (diffable-cs)...")
    code = runner._process(command, runner.ROOT, env, job / "cpp2il_types.log", emit, cancel)
    if code != 0:
        emit("Cpp2IL chưa xuất được kiểu C#; xem cpp2il_types.log. Editor chỉ dùng LevelData.cs.")


def _mechanic_enums(builder: SchemaBuilder, apk: TypeLibrary, focus_namespaces: set[str]) -> list[str]:
    scored: list[tuple[int, str]] = []
    for block_id in apk.enum_blocks():
        for item in apk.load_block_types(block_id):
            if item["kind"] != "enum" or item["key"] in builder.enums:
                continue
            if category_for_class(item["key"]) != "game" or not 2 <= len(item["members"]) <= 256:
                continue
            if not _MECHANIC_ENUM_NAME.search(item["name"]) or _NOT_GAMEPLAY.search(item["name"]):
                continue
            score = (3 if _MECHANIC_STRONG.search(item["name"]) else 0) + \
                    (2 if item["namespace"] in focus_namespaces else 0)
            scored.append((score, item["key"]))
            if len(scored) > 4000:
                break
    scored.sort(key=lambda pair: (-pair[0], pair[1]))
    keys = []
    for _, key in scored[:MAX_MECHANIC_ENUMS]:
        item = apk.types[key]
        keys.append(builder._enum(item))
    return keys


def _apk_level_classes(apk: TypeLibrary) -> list[dict[str, Any]]:
    result = []
    for name in apk.class_block_names(re.compile(r"Level|Stage|Board|Puzzle|Map", re.I)):
        for item in apk.candidates(name):
            if item["kind"] not in {"class", "struct"} or category_for_class(item["key"]) != "game":
                continue
            fields = [{"name": f["name"], "cs": f["type"]} for f in item["fields"] if _is_serialized(f)]
            if fields:
                result.append({"key": item["key"], "name": item["name"], "ns": item["namespace"],
                               "fields": fields[:60]})
        if len(result) >= MAX_APK_LEVEL_CLASSES:
            break
    return result


def _normalize_type(text: str) -> str:
    text = re.sub(r"\s+|global::|`\d+", "", text)
    return re.sub(r"[\w]+\.", "", text).lower()


def _compare_with_apk(user: TypeLibrary, apk: TypeLibrary) -> list[dict[str, Any]]:
    report = []
    for item in user.types.values():
        if item["kind"] not in {"class", "struct", "enum"}:
            continue
        candidates = [c for c in apk.candidates(item["name"]) if c["kind"] == item["kind"]]
        match = _pick(candidates, item["namespace"])
        entry: dict[str, Any] = {"name": item["qualified_name"], "kind": item["kind"]}
        if match is None:
            entry["status"] = "not_in_apk"
            report.append(entry)
            continue
        entry["apk"] = match["key"]
        if item["kind"] == "enum":
            ours, theirs = dict((n, v) for v, n in item["members"]), dict((n, v) for v, n in match["members"])
            entry["missing_in_leveldata"] = [f"{n}={theirs[n]}" for n in theirs if n not in ours]
            entry["extra_in_leveldata"] = [f"{n}={ours[n]}" for n in ours if n not in theirs]
            entry["value_mismatch"] = [f"{n}: {ours[n]} ≠ APK {theirs[n]}" for n in ours
                                       if n in theirs and ours[n] != theirs[n]]
        else:
            ours = {f["name"]: f for f in item["fields"] if _is_serialized(f)}
            theirs = {f["name"]: f for f in match["fields"] if _is_serialized(f)}
            entry["missing_in_leveldata"] = [f"{n}: {theirs[n]['type']}" for n in theirs if n not in ours]
            entry["extra_in_leveldata"] = [f"{n}: {ours[n]['type']}" for n in ours if n not in theirs]
            entry["value_mismatch"] = [
                f"{n}: {ours[n]['type']} ≠ APK {theirs[n]['type']}" for n in ours
                if n in theirs and _normalize_type(ours[n]["type"]) != _normalize_type(theirs[n]["type"])]
        entry["status"] = ("match" if not (entry["missing_in_leveldata"] or entry["extra_in_leveldata"]
                                           or entry["value_mismatch"]) else "differs")
        report.append(entry)
    return report


def _sample_levels(job: Path | None, emit) -> list[dict[str, Any]]:
    if job is None:
        return []
    files: list[tuple[str, Path]] = []
    manifest_path = job / "levels.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        for group in manifest.get("groups", []):
            if not isinstance(group, dict):
                continue
            label = str(group.get("name") or group.get("bundle") or "")
            for level in group.get("levels", []):
                if isinstance(level, dict) and isinstance(level.get("file"), str):
                    relative = Path(level["file"])
                    if not relative.is_absolute() and ".." not in relative.parts:
                        files.append((label, job / relative))
    except (OSError, ValueError, AttributeError):
        pass
    if not files and (job / "levels").is_dir():
        files = [(path.parent.name, path) for path in sorted((job / "levels").rglob("*.json"))]
    samples, total = [], 0
    for group, path in files:
        if len(samples) >= MAX_SAMPLE_LEVELS:
            break
        try:
            size = path.stat().st_size
            if total + size > MAX_SAMPLE_BYTES:
                break
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        total += size
        samples.append({"name": path.stem, "group": group,
                        "file": path.relative_to(job).as_posix() if path.is_relative_to(job) else path.name,
                        "data": data})
    if files:
        emit(f"Nhúng {len(samples):,}/{len(files):,} level trích từ APK vào editor để mở/chuyển sang LevelData.")
    return samples


# ---------------------------------------------------------------- entry points
def read_leveldata(paths: list[Path]) -> TypeLibrary:
    library = TypeLibrary("user")
    for path in paths:
        library.add_types(parse_csharp_types(path.read_text(encoding="utf-8-sig", errors="replace")), "user")
    return library


def leveldata_sources(source: Path) -> list[Path]:
    if source.is_dir():
        return sorted(path for path in source.rglob("*.cs") if path.is_file())
    return [source] if source.is_file() else []


def root_candidates(library: TypeLibrary) -> list[str]:
    """Classes in LevelData.cs, the likely level root first."""
    classes = [item for item in library.types.values() if item["kind"] in {"class", "struct"}]
    referenced = {re.sub(r"[\[\]?<>,]", " ", f["type"]).split()[-1].split(".")[-1]
                  for item in classes for f in item["fields"] if f["type"]}
    referenced |= {word for item in classes for f in item["fields"]
                   for word in re.findall(r"[A-Za-z_]\w*", f["type"])}

    def rank(item: dict[str, Any]) -> tuple:
        name = item["name"]
        return (name != "LevelData", "level" not in name.lower(), name in referenced,
                item["outer"] is not None, -len(item["fields"]), name)

    return [item["key"] for item in sorted(classes, key=rank)]


def build_level_editor(leveldata: Path, output_html: Path, job: Path | None = None,
                       root: str | None = None, emit=print,
                       cancel: threading.Event | None = None) -> dict[str, Any]:
    cancel = cancel or threading.Event()
    sources = leveldata_sources(leveldata)
    if not sources:
        raise LevelEditorError("Không tìm thấy file .cs LevelData.")
    user = read_leveldata(sources)
    candidates = root_candidates(user)
    if not candidates:
        raise LevelEditorError("LevelData.cs không có class/struct nào đọc được.")
    root_key = root or candidates[0]
    if root_key not in user.types:
        matches = [key for key in candidates if user.types[key]["name"] == root_key]
        if not matches:
            raise LevelEditorError(f"Không thấy class gốc '{root_key}' trong LevelData.cs.")
        root_key = matches[0]
    emit(f"LevelData: {len(user.types):,} kiểu từ {len(sources)} file; class gốc: {root_key}")

    if job is not None:
        ensure_cpp2il_types(job, emit, cancel)
    apk = _load_apk_library(job, emit)
    if cancel.is_set():
        raise LevelEditorError("Đã dừng.")

    builder = SchemaBuilder(user, apk)
    root_key = builder.build(user.types[root_key])
    used_enums = list(builder.enums)
    apk_types_used = sorted(key for key, value in {**builder.classes, **builder.enums}.items()
                            if value["src"] == "apk")
    if apk_types_used:
        emit(f"Kiểu lấy từ APK cho LevelData: {', '.join(apk_types_used[:12])}"
             + (" …" if len(apk_types_used) > 12 else ""))
    comparison = _compare_with_apk(user, apk) if apk.indexed else []
    for entry in comparison:
        if entry["status"] == "differs":
            emit(f"Khác APK: {entry['name']} ↔ {entry['apk']}: thiếu {len(entry['missing_in_leveldata'])}, "
                 f"thừa {len(entry['extra_in_leveldata'])}, lệch kiểu/giá trị {len(entry['value_mismatch'])}")
        elif entry["status"] == "match":
            emit(f"Khớp APK: {entry['name']} ↔ {entry['apk']}")
    focus = {builder.classes[key]["ns"] for key in builder.classes if builder.classes[key]["src"] == "apk"}
    focus |= {apk.types[e["apk"]]["namespace"] for e in comparison if e.get("apk") in apk.types}
    mechanic_keys = _mechanic_enums(builder, apk, focus) if apk.indexed else []
    level_classes = _apk_level_classes(apk) if apk.indexed else []
    samples = _sample_levels(job, emit)

    apk_name = ""
    if job is not None:
        try:
            inputs = json.loads((job / "job.json").read_text(encoding="utf-8")).get("inputs", [])
            apk_name = ", ".join(Path(p).name for p in inputs)
        except (OSError, ValueError):
            apk_name = job.name
    schema_text = json.dumps({"root": root_key, "classes": builder.classes}, sort_keys=True)
    data = {
        "meta": {
            "title": builder.classes[root_key]["name"],
            "apk": apk_name, "job": str(job) if job else "",
            "leveldata": [str(path) for path in sources],
            "generated": datetime.now().isoformat(timespec="seconds"),
            "schema_id": hashlib.sha1(schema_text.encode("utf-8")).hexdigest()[:16],
            "has_apk_types": bool(apk.indexed),
        },
        "root": root_key,
        "classes": builder.classes,
        "enums": builder.enums,
        "used_enums": used_enums,
        "mechanics": mechanic_keys,
        "apk_level_classes": level_classes,
        "comparison": comparison,
        "unresolved": [{"type": name, "used_by": sorted(set(where))[:6]}
                       for name, where in sorted(builder.unresolved.items())],
        "samples": samples,
    }
    for item in data["unresolved"]:
        emit(f"Chưa xác định kiểu {item['type']} (dùng ở {', '.join(item['used_by'])}); editor để ô JSON thô.")
    write_editor_html(data, output_html)
    emit(f"HOÀN TẤT LEVEL EDITOR: {output_html}")
    return {"output": str(output_html), "root": root_key, "classes": len(builder.classes),
            "enums": len(builder.enums), "apk_types_used": len(apk_types_used),
            "mechanic_enums": len(mechanic_keys), "levels_embedded": len(samples),
            "unresolved": len(data["unresolved"]), "candidates": candidates}


def write_editor_html(data: dict[str, Any], output_html: Path) -> None:
    template = TEMPLATE.read_text(encoding="utf-8")
    if DATA_PLACEHOLDER not in template:
        raise LevelEditorError("Template level editor thiếu chỗ nhúng dữ liệu.")
    payload = json.dumps(data, ensure_ascii=False, separators=(",", ":"), default=str)
    payload = (payload.replace("</", "<\\/").replace("<!--", "<\\!--")
               .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029"))
    output_html.parent.mkdir(parents=True, exist_ok=True)
    output_html.write_text(template.replace(DATA_PLACEHOLDER, payload, 1), encoding="utf-8")
