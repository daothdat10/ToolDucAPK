import struct
import tempfile
import unittest
from pathlib import Path

from ducapk import flatbuffers_levels as fb


DUMP_CS = """// Namespace: Game.FlatLevel
public enum EColor // TypeDefIndex: 1
{
\t// Fields
\tpublic sbyte value__; // 0x0
\tpublic const EColor None = 0;
\tpublic const EColor Green = 2;
}

// Namespace: Game.FlatLevel
public struct FCell : IFlatbufferObject // TypeDefIndex: 2
{
\t// Fields
\tprivate Table __p; // 0x0

\t// Methods

\t// RVA: 0x10 Offset: 0x10 VA: 0x10
\tpublic static FCell GetRootAsFCell(ByteBuffer _bb) { }

\t// RVA: 0x20 Offset: 0x20 VA: 0x20
\tpublic int get_X() { }

\t// RVA: 0x30 Offset: 0x30 VA: 0x30
\tpublic EColor get_Color() { }
}

// Namespace: Game.FlatLevel
public struct FLevel : IFlatbufferObject // TypeDefIndex: 3
{
\t// Fields
\tprivate Table __p; // 0x0

\t// Methods

\t// RVA: 0x40 Offset: 0x40 VA: 0x40
\tpublic static FLevel GetRootAsFLevel(ByteBuffer _bb) { }

\t// RVA: 0x50 Offset: 0x50 VA: 0x50
\tpublic ByteBuffer get_ByteBuffer() { }

\t// RVA: 0x60 Offset: 0x60 VA: 0x60
\tpublic string get_Name() { }

\t// RVA: 0x70 Offset: 0x70 VA: 0x70
\tpublic Nullable<ArraySegment<byte>> GetNameBytes() { }

\t// RVA: 0x80 Offset: 0x80 VA: 0x80
\tpublic int get_Move() { }

\t// RVA: 0x90 Offset: 0x90 VA: 0x90
\tpublic Nullable<FCell> Cells(int j) { }

\t// RVA: 0xA0 Offset: 0xA0 VA: 0xA0
\tpublic int get_CellsLength() { }
}
"""


def _level_buffer() -> bytes:
    """FLevel{Name="abc", Move=30, Cells=[FCell{X=7, Color=Green}]} laid out by hand."""
    data = bytearray(68)
    struct.pack_into("<I", data, 0, 16)                       # root table
    struct.pack_into("<HHHHH", data, 4, 10, 16, 4, 8, 12)     # FLevel vtable
    struct.pack_into("<i", data, 16, 12)                      # table -> vtable at 4
    struct.pack_into("<I", data, 20, 12)                      # Name -> 32
    struct.pack_into("<i", data, 24, 30)                      # Move
    struct.pack_into("<I", data, 28, 12)                      # Cells -> 40
    struct.pack_into("<I", data, 32, 3)
    data[36:39] = b"abc"
    struct.pack_into("<II", data, 40, 1, 12)                  # 1 element -> 56
    struct.pack_into("<HHHH", data, 48, 8, 12, 4, 8)          # FCell vtable
    struct.pack_into("<i", data, 56, 8)                       # table -> vtable at 48
    struct.pack_into("<i", data, 60, 7)
    struct.pack_into("<b", data, 64, 2)
    return bytes(data)


class FlatbufferLevelTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        dump = Path(folder.name) / "dump.cs"
        dump.write_text(DUMP_CS, encoding="utf-8")
        self.schema = fb.resolve_layout(fb.parse_schema(dump))

    def test_schema_from_dump_cs(self):
        level = self.schema.types["FLevel"]
        self.assertTrue(level.root)
        self.assertEqual([(f.name, f.slot, f.vector) for f in level.fields],
                         [("Name", 0, False), ("Move", 1, False), ("Cells", 2, True)])
        self.assertEqual(self.schema.enums["EColor"], ("sbyte", {0: "None", 2: "Green"}))

    def test_decode_level_buffer(self):
        root, value = fb.best_root(self.schema, _level_buffer())
        self.assertEqual(root.name, "FLevel")
        self.assertEqual(value, {"Name": "abc", "Move": 30,
                                 "Cells": [{"X": 7, "Color": "Green"}]})

    def test_rejects_unrelated_bytes(self):
        self.assertIsNone(fb.best_root(self.schema, b"\xff" * 64))
        self.assertIsNone(fb.best_root(self.schema, b"not a flatbuffer at all"))

    def test_slot_from_arm64_accessor(self):
        code = struct.pack("<III", 0xA9BF7BFD, 0x52800101, 0x94000000)  # stp; mov w1,#8; bl
        self.assertEqual(fb._arm64_slot(code, 0), 2)
        self.assertIsNone(fb._arm64_slot(struct.pack("<I", 0x94000000), 0))

    def test_group_names(self):
        self.assertEqual(fb._group_of("1250"), ("levels", 1250))
        self.assertEqual(fb._group_of("story-12"), ("story", 12))
        self.assertEqual(fb._group_of("c_7"), ("c", 7))


if __name__ == "__main__":
    unittest.main()
