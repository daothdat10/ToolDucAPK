import base64
import struct
import tempfile
import unittest
from pathlib import Path

from ducapk.metadata import build_cpp2il_metadata_index, elf_rva_delta


def _make_elf64(text_vaddr: int, text_offset: int, with_sections: bool = True) -> bytes:
    """Minimal ELF64: one executable PT_LOAD and optionally a .text section."""
    header_size, ph_size, sh_size = 64, 56, 64
    names = b"\x00.text\x00.shstrtab\x00"
    phoff = header_size
    names_offset = phoff + ph_size
    shoff = (names_offset + len(names) + 7) & ~7 if with_sections else 0
    shnum = 3 if with_sections else 0
    blob = bytearray(b"\x7fELF" + bytes([2, 1, 1]) + bytes(9))
    blob += struct.pack("<HHIQQQIHHHHHH", 3, 183, 1, 0, phoff, shoff, 0,
                        header_size, ph_size, 1, sh_size, shnum, 2 if with_sections else 0)
    blob += struct.pack("<IIQQQQQQ", 1, 5, text_offset, text_vaddr, text_vaddr, 0x1000, 0x1000, 0x1000)
    blob += names
    if with_sections:
        blob += bytes(shoff - len(blob))
        blob += bytes(sh_size)
        blob += struct.pack("<IIQQQQIIQQ", 1, 1, 6, text_vaddr, text_offset, 0x1000, 0, 0, 4, 0)
        blob += struct.pack("<IIQQQQIIQQ", 7, 3, 0, 0, names_offset, len(names), 0, 0, 1, 0)
    return bytes(blob)


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


class Cpp2IlRvaTests(unittest.TestCase):
    def test_delta_from_text_section_and_exec_segment(self):
        with tempfile.TemporaryDirectory() as temp:
            binary = Path(temp) / "libil2cpp.so"
            binary.write_bytes(_make_elf64(0x1534AF0, 0x1530AF0))
            self.assertEqual(elf_rva_delta(binary), 0x4000)
            binary.write_bytes(_make_elf64(0x2000, 0x1000, with_sections=False))
            self.assertEqual(elf_rva_delta(binary), 0x1000)
            binary.write_bytes(b"not an elf")
            self.assertEqual(elf_rva_delta(binary), 0)
            self.assertEqual(elf_rva_delta(Path(temp) / "missing.so"), 0)

    def test_cpp2il_file_offsets_become_virtual_addresses(self):
        with tempfile.TemporaryDirectory() as temp:
            job = Path(temp)
            (job / "input").mkdir()
            (job / "input" / "libil2cpp.so").write_bytes(_make_elf64(0x1534AF0, 0x1530AF0))
            method_map = job / "ducapk_methods.tsv"
            method_map.write_text(
                "rva\tclass_b64\tmethod_b64\tsignature_b64\n"
                f"{0x1ACBDC4}\t{_b64('CoreData.LevelDataSerializer')}\t{_b64('Decrypt')}\t{_b64('Decrypt()')}\n"
                f"0\t{_b64('CoreData.LevelDataSerializer')}\t{_b64('Abstract')}\t{_b64('Abstract()')}\n",
                encoding="utf-8")
            summary = build_cpp2il_metadata_index(method_map, job, lambda message: None)
            self.assertEqual(summary["rva_delta"], 0x4000)
            rows = (job / "methods.tsv").read_text(encoding="utf-8").splitlines()
            self.assertEqual([row.split("\t")[1] for row in rows], [str(0x1ACFDC4)])


if __name__ == "__main__":
    unittest.main()
