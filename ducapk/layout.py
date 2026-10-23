"""Folder layout for exported class files: namespace tree, nested types beside their owner."""

from __future__ import annotations

import re
from pathlib import PurePath

from .categories import category_for_class
from .metadata import class_file_name

NO_NAMESPACE = "_NoNamespace"
COMPILER_GENERATED = "_CompilerGenerated"
MAX_NAMESPACE_DEPTH = 5
MAX_SEGMENT = 40

# Global-namespace game classes are grouped by naming convention (checked in order).
ROLE_SUFFIXES = (
    ("Tutorial", ("Tutorial",)),
    ("States", ("State",)),
    ("Systems", ("System",)),
    ("Data", ("Sheet", "Config", "Data", "Settings", "Constants", "Container", "Database")),
    ("Bootstrap", ("Installer", "Scope", "Bootstrapper", "Bootstrap")),
    ("UI", ("Monitor", "Element", "Popup", "Panel", "Screen", "View", "Button", "Window",
            "Page", "Variant", "Transition", "Image", "Text", "Canvas", "Widget")),
    ("Services", ("Module", "Service", "Manager", "Controller", "Provider", "Handler",
                  "Resolver", "Verifier", "Helper", "Factory", "Pool")),
    ("Boosters", ("Booster",)),
    ("Extensions", ("Extensions", "Extension", "Utils", "Utility", "Utilities")),
)
OTHER_ROLE = "Other"


def split_type_name(name: str) -> list[str]:
    """Split on dots that are outside generic brackets."""
    parts, depth, current = [], 0, []
    for char in name:
        if char == "<":
            depth += 1
        elif char == ">":
            depth = max(0, depth - 1)
        if char == "." and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    return [part for part in parts if part]


def _base_name(segment: str) -> str:
    """Drop generic arguments but keep compiler-generated names such as <Run>d__4."""
    if segment.startswith("<"):
        return segment
    return segment.split("<", 1)[0].split("`", 1)[0]


def _generated(segment: str) -> bool:
    return segment.startswith("<")


def role_for_class(segment: str) -> str:
    base = _base_name(segment)
    for role, suffixes in ROLE_SUFFIXES:
        if any(base.endswith(suffix) for suffix in suffixes):
            return role
    return OTHER_ROLE


def _folder(segment: str) -> str:
    # Strip after truncating: Windows drops a trailing "." from folder names, which
    # would make the written path differ from the one recorded for cleanup.
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", segment)[:MAX_SEGMENT].strip(" ._")
    return safe or "_"


class ClassLayout:
    """Resolve IL2CPP class names to namespace/owner and relative export paths.

    Il2CppDumper names nested types after their declaring type without its
    namespace (``CombineLatest._CombineLatest.<DisposeAsync>d__75``), so the
    owner is looked up among all class names by its simple name.
    """

    def __init__(self, class_names, group_global_by_role: bool = True):
        self.group_global_by_role = group_global_by_role
        self.known: set[str] = set()
        by_simple: dict[str, set[tuple[str, ...]]] = {}
        names = [split_type_name(name) for name in class_names]
        for parts in names:
            self.known.add(".".join(_base_name(part) for part in parts))
        for parts in names:
            owner = self._known_owner(parts)
            if len(owner) > 1:  # namespaced top-level type
                key = tuple(_base_name(part) for part in owner)
                by_simple.setdefault(key[-1], set()).add(key[:-1])
        # Pick the owner's namespace when unique, or when every candidate is in one category.
        self.namespace_of = {}
        for simple, spaces in by_simple.items():
            ordered = sorted(spaces)
            if len(ordered) == 1 or len({category_for_class(".".join((*space, simple)))
                                         for space in ordered}) == 1:
                self.namespace_of[simple] = ordered[0]
        self._cache: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {}

    def _known_owner(self, parts: list[str]) -> list[str]:
        for length in range(1, len(parts)):
            if ".".join(_base_name(part) for part in parts[:length]) in self.known:
                return parts[:length]
        return parts

    def split(self, class_name: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
        """Return (namespace, type path) where type path[0] is the outermost type."""
        cached = self._cache.get(class_name)
        if cached is not None:
            return cached
        parts = split_type_name(class_name) or [class_name]
        first = _base_name(parts[0])
        if len(parts) > 1 and first not in self.known and first in self.namespace_of:
            # Nested type named after a namespaced owner: recover that namespace.
            result = (self.namespace_of[first], tuple(parts))
        else:
            owner = self._known_owner(parts)
            if len(owner) == len(parts) and len(parts) > 1:
                # No declared owner: generated members belong to the type before them.
                first_generated = next((i for i, part in enumerate(parts) if _generated(part)), None)
                if first_generated:
                    owner = parts[:first_generated]
            result = (tuple(owner[:-1]), tuple(parts[len(owner) - 1:]))
        self._cache[class_name] = result
        return result

    def full_name(self, class_name: str) -> str:
        """Class name with the namespace recovered for nested types, for categorisation."""
        namespace, types = self.split(class_name)
        return ".".join((*namespace, *types))

    def relative_path(self, class_name: str, suffix: str) -> PurePath:
        namespace, types = self.split(class_name)
        top = types[0]
        if _generated(top) or not namespace and _base_name(top).startswith("__"):
            folders = [COMPILER_GENERATED]
        elif not namespace:
            folders = [NO_NAMESPACE]
            if self.group_global_by_role:
                folders.append(role_for_class(top))
        else:
            folders = [_folder(part) for part in namespace[:MAX_NAMESPACE_DEPTH]]
            if len(namespace) > MAX_NAMESPACE_DEPTH:
                folders[-1] = _folder(".".join(namespace[MAX_NAMESPACE_DEPTH - 1:]))
        # Nested and compiler-generated types share the owner's folder and sort next to it.
        return PurePath(*folders, class_file_name(".".join(types), digest_of=class_name) + suffix)
