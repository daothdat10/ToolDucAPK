"""Gameplay rules inferred from the game's level classes and verified on its extracted levels.

Only rules that hold on the real data are reported, so the editor never invents gameplay.
Currently recognised:

* color_count_balance: the board is coloured cells (a list of {color, int[] cell ids}) and
  the level also holds units with a colour and a count (guns with bullets, cups with
  capacity...). The rule is accepted when, for most extracted levels, the units' counts
  summed per colour equal the number of cells of that colour.
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Any

from .categories import category_for_class
from .level_editor import TypeLibrary

_COLOR_FIELD = re.compile(r"colou?r", re.I)
_IDS_FIELD = re.compile(r"(ids|indices|indexes|positions|pixels|cells)$", re.I)
_COUNT_FIELD = re.compile(r"bullet|ammo|count|amount|capacity|quantity|number|value", re.I)
_PREFERRED_COUNT = re.compile(r"bullet|ammo", re.I)
_HIDDEN_FIELD = re.compile(r"hidden|secret|mystery|unknown", re.I)
_COLOR_WORD = re.compile(
    r"^(yellow|orange|red|green|blue|pink|purple|violet|brown|white|black|gr[ae]y|beige|begie|teal|cyan|"
    r"magenta|lime|navy|gold|silver|cream|mint|peach|maroon|olive|indigo|turquoise|aqua|lavender|"
    r"coral|salmon|skin|dark|light)", re.I)
MIN_RULE_SHARE = 0.9


def find_color_enum(apk: TypeLibrary) -> dict[str, Any] | None:
    """The game enum whose members are colour names (Yellow_1, Red_2, ...), if any."""
    best, best_score = None, None
    # Colour enums are often nested (ColorCubeGlobalConfig.ColorType), so scan every block declaring one.
    for block_id in apk.blocks_matching(re.compile(r"\b(Yellow|Red|Blue|Green)\w*\s*=\s*\d", re.I)):
        for item in apk.load_block_types(block_id):
            if item["kind"] != "enum" or len(item["members"]) < 5:
                continue
            hits = sum(1 for _, name in item["members"] if _COLOR_WORD.match(name))
            if hits < 0.7 * len(item["members"]):
                continue
            score = (category_for_class(item["key"]) == "game", hits)
            if best_score is None or score > best_score:
                best, best_score = item, score
    if best is None:
        return None
    return {"key": best["key"], "name": best["name"],
            "members": [[value, name] for value, name in best["members"]]}


def _fields(classes: dict[str, Any], key: str) -> list[dict[str, Any]]:
    item = classes.get(key)
    return item["fields"] if item else []


def _is_int(description: dict[str, Any]) -> bool:
    return description["k"] in {"int", "enum"}


def _unit_paths(classes: dict[str, Any], root: str, target: str) -> list[list[str]]:
    """JSON paths ("*" for list elements) from the root object to every object of class `target`."""
    found: list[list[str]] = []

    def walk(key: str, path: list[str], seen: tuple[str, ...]) -> None:
        for field in _fields(classes, key):
            description, step = field["type"], [field["json"]]
            while description["k"] == "list":
                description, step = description["of"], step + ["*"]
            if description["k"] != "obj":
                continue
            ref = description["ref"]
            if ref == target:
                found.append(path + step)
            elif ref not in seen and len(path) < 8:
                walk(ref, path + step, seen + (ref,))

    walk(root, [], (root,))
    return found


def _collect(value: Any, path: list[str]) -> list[Any]:
    if not path:
        return [value]
    head, rest = path[0], path[1:]
    if head == "*":
        return [x for item in value for x in _collect(item, rest)] if isinstance(value, list) else []
    return _collect(value.get(head), rest) if isinstance(value, dict) else []


def _cell_counts(level: dict[str, Any], cells: dict[str, str]) -> Counter:
    counts: Counter = Counter()
    for group in level.get(cells["list"]) or []:
        if isinstance(group, dict) and isinstance(group.get(cells["ids"]), list):
            counts[group.get(cells["color"])] += len(group[cells["ids"]])
    return counts


def _source_counts(level: dict[str, Any], sources: list[dict[str, str]]) -> Counter:
    """Extra coloured cells queued by spawners on the board (one per entry of e.g. PipeColors)."""
    counts: Counter = Counter()
    for source in sources:
        for item in level.get(source["list"]) or []:
            if isinstance(item, dict) and isinstance(item.get(source["colors"]), list):
                counts.update(item[source["colors"]])
    return counts


def _unit_counts(level: dict[str, Any], paths: list[list[str]], color: str, count: str) -> Counter:
    counts: Counter = Counter()
    for path in paths:
        for unit in _collect(level, path):
            if isinstance(unit, dict) and isinstance(unit.get(count), (int, float)):
                counts[unit.get(color)] += unit[count]
    return counts


def _layout(paths: list[list[str]]) -> tuple[dict[str, str] | None, dict[str, str] | None]:
    """Columns ([list, *, units, *]) and spawners inside a column ([list, *, field, *, units, *])."""
    columns = next(({"list": p[0], "units": p[2]} for p in paths
                    if len(p) == 4 and p[1] == "*" and p[3] == "*"), None)
    spawners = None
    if columns:
        spawners = next(({"field": p[2], "units": p[4]} for p in paths
                         if len(p) == 6 and p[0] == columns["list"] and p[1] == "*"
                         and p[3] == "*" and p[5] == "*"), None)
    return columns, spawners


def detect_color_count_balance(classes: dict[str, Any], root: str,
                               levels: list[dict[str, Any]]) -> dict[str, Any] | None:
    cell_options = []
    for field in _fields(classes, root):
        description = field["type"]
        if description["k"] != "list" or description["of"]["k"] != "obj":
            continue
        inner = _fields(classes, description["of"]["ref"])
        color = next((f["json"] for f in inner if _is_int(f["type"]) and _COLOR_FIELD.search(f["json"])), None)
        ids = next((f["json"] for f in inner if f["type"]["k"] == "list" and f["type"]["of"]["k"] == "int"
                    and _IDS_FIELD.search(f["json"])), None)
        if color and ids:
            cell_options.append({"list": field["json"], "color": color, "ids": ids,
                                 "class": description["of"]["ref"]})
    if not cell_options or not levels:
        return None
    # Root lists whose items queue coloured cells (int[] named like PipeColors) also need units.
    source_options = []
    for field in _fields(classes, root):
        description = field["type"]
        if description["k"] == "list" and description["of"]["k"] == "obj":
            colors = next((f["json"] for f in _fields(classes, description["of"]["ref"])
                           if f["type"]["k"] == "list" and _is_int(f["type"]["of"])
                           and re.search(r"colou?rs$", f["json"], re.I)), None)
            if colors:
                source_options.append({"list": field["json"], "colors": colors, "ids": next(
                    (f["json"] for f in _fields(classes, description["of"]["ref"])
                     if f["type"]["k"] == "list" and f["type"]["of"]["k"] == "int" and _IDS_FIELD.search(f["json"])), "")})
    variants = [[], source_options] if source_options else [[]]

    best: tuple[float, int, dict[str, Any]] | None = None
    for cells, sources in ((c, s) for c in cell_options for s in variants):
        for key, item in classes.items():
            if key == cells["class"] or item.get("src") == "unity":
                continue
            fields = item["fields"]
            color = next((f["json"] for f in fields if _is_int(f["type"]) and _COLOR_FIELD.search(f["json"])), None)
            counts = [f["json"] for f in fields if f["type"]["k"] == "int" and f["json"] != color
                      and _COUNT_FIELD.search(f["json"])]
            if not color or not counts:
                continue
            paths = _unit_paths(classes, root, key)
            if not paths:
                continue
            for count in sorted(counts, key=lambda name: not _PREFERRED_COUNT.search(name)):
                checked = matched = 0
                failed: list[int] = []
                for index, level in enumerate(levels):
                    have = _cell_counts(level, cells)
                    if not have:
                        continue
                    have.update(_source_counts(level, sources))
                    checked += 1
                    need = _unit_counts(level, paths, color, count)
                    if +have == +need:
                        matched += 1
                    elif len(failed) < 10:
                        failed.append(index)
                if checked and (best is None or (matched / checked, matched) > best[:2]):
                    best = (matched / checked, matched, {
                        "cells": cells, "sources": sources, "paths": paths, "failed": failed, "checked": checked,
                        "unit": {"class": key, "name": item["name"], "color": color, "count": count,
                                 "hidden": next((f["json"] for f in fields if f["type"]["k"] == "bool"
                                                 and _HIDDEN_FIELD.search(f["json"])), "")}})
    if best is None or best[0] < MIN_RULE_SHARE:
        return None
    share, matched, found = best
    columns, spawners = _layout(found["paths"])
    return {
        "kind": "color_count_balance",
        "cells": found["cells"],
        "sources": found["sources"],
        "unit": found["unit"],
        "unit_paths": found["paths"],
        "columns": columns,
        "spawners": spawners,
        "evidence": {"matched": matched, "checked": found["checked"], "share": round(share, 4),
                     "failed_samples": found["failed"]},
    }


_WIDTH_FIELD = re.compile(r"^(width|w|cols?|columns?|sizex|gridwidth|mapwidth|boardwidth|xsize)$", re.I)
_HEIGHT_FIELD = re.compile(r"^(height|h|rows?|sizey|gridheight|mapheight|boardheight|ysize)$", re.I)


def detect_cell_order(classes: dict[str, Any], root: str, cells: dict[str, str],
                      levels: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Whether flat cell ids are row-major (y*W+x) or column-major (x*H+y).

    Pictures are mostly made of same-coloured neighbours; on non-square boards only the right
    order keeps them, so count same-colour neighbour pairs under both readings.
    """
    ints = [f["json"] for f in _fields(classes, root) if f["type"]["k"] == "int"]
    width = next((name for name in ints if _WIDTH_FIELD.match(name)), None)
    height = next((name for name in ints if _HEIGHT_FIELD.match(name)), None)
    if not width or not height:
        return None
    votes = Counter()
    for level in levels:
        w, h = level.get(width), level.get(height)
        if not isinstance(w, int) or not isinstance(h, int) or w <= 1 or h <= 1 or w == h:
            continue
        color_of = {}
        for group in level.get(cells["list"]) or []:
            for cell in (group or {}).get(cells["ids"]) or []:
                if isinstance(cell, int):
                    color_of[cell] = group.get(cells["color"])

        def same_neighbours(to_xy) -> int:
            grid = {to_xy(cell): color for cell, color in color_of.items()}
            return sum(1 for (x, y), color in grid.items()
                       for neighbour in ((x + 1, y), (x, y + 1)) if grid.get(neighbour) == color)

        row = same_neighbours(lambda i: (i % w, i // w))
        column = same_neighbours(lambda i: (i // h, i % h))
        if row != column:
            votes["row" if row > column else "column"] += 1
        if sum(votes.values()) >= 60:
            break
    if not votes:
        return None
    order, count = votes.most_common(1)[0]
    return {"order": order, "width": width, "height": height,
            "evidence": {"votes": count, "levels": sum(votes.values())}}


def detect_game_rules(classes: dict[str, Any], root: str, levels: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rules = []
    balance = detect_color_count_balance(classes, root, levels)
    if balance:
        order = detect_cell_order(classes, root, balance["cells"], levels)
        if order:
            balance["cell_order"] = order
        rules.append(balance)
    return rules
