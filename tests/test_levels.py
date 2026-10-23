import hashlib
import json
import struct
import tempfile
import unittest
from pathlib import Path

from ducapk import levels


class LevelRecoveryTests(unittest.TestCase):
    def test_juicetime_native_level_payload_decode_and_raw_preservation(self):
        payload = "41;4;2;1;0;4;1/12/7/12,3/5;0:7:510,4:0/1/0/1,1/0/1/0;2;3;5;1;0;tail"
        parsed = levels._parse_juicetime_level_payload(payload)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["parser"], "JuiceTimeLevelParser.TryParse")
        self.assertEqual(parsed["level_id"], 41)
        self.assertEqual(parsed["groups"][0]["need_element"], 7)
        self.assertEqual(parsed["groups"][0]["skewers"][0]["colors_bottom_to_top"], [1, 12, 7, 12])
        self.assertEqual(parsed["groups"][0]["skewers"][0]["status"],
                         {"raw_id": 510, "id": 5, "name": "SugarPaper"})
        self.assertEqual(parsed["groups"][0]["skewers"][0]["sugar_paper_element"], 10)
        self.assertEqual(parsed["groups"][0]["skewers"][1]["status"]["name"], "Freezed5")
        self.assertEqual(parsed["unparsed_trailing_fields"], ["tail"])

        record = {"format": "ducapk-hdpk-text-level-v1", "payload": payload,
                  "semicolon_fields": payload.split(";")}
        self.assertTrue(levels._enrich_juicetime_level_record(record))
        self.assertEqual(record["payload"], payload)
        self.assertEqual(record["decoded_juicetime"], parsed)

    def test_juicetime_decoder_handles_empty_groups_and_rejects_bad_shape(self):
        payload = "13;4;4;1;1;4;1/2/3/4|#;0:0:0:0/0/0/0|0:0:#:#;0;2;10;0;;0"
        parsed = levels._parse_juicetime_level_payload(payload)
        self.assertIsNotNone(parsed)
        self.assertEqual(len(parsed["groups"]), 2)
        self.assertTrue(parsed["groups"][-1]["is_empty_group"])
        self.assertFalse(parsed["has_bubble"])
        self.assertIsNone(levels._parse_juicetime_level_payload("1;not-a-level"))

    def test_cached_level_exports_are_enriched_and_manifest_counts_mechanics(self):
        payload = "1;2;2;1;0;4;1/2;0:0:0:0/1;0;1;2;0;0"
        with tempfile.TemporaryDirectory() as temporary:
            job = Path(temporary)
            level_path = job / "levels" / "sample" / "pack" / "Level 1.json"
            level_path.parent.mkdir(parents=True)
            original = {"format": "ducapk-hdpk-text-level-v1", "payload": payload,
                        "semicolon_fields": payload.split(";")}
            level_path.write_text(json.dumps(original), encoding="utf-8")
            manifest = {"groups": [{"levels": [{"file": level_path.relative_to(job).as_posix()}]}],
                        "summary": {}}
            decoded, checked = levels._enrich_existing_juicetime_exports(job, manifest)
            self.assertEqual((decoded, checked), (1, 1))
            output = json.loads(level_path.read_text(encoding="utf-8"))
            self.assertEqual(output["payload"], payload)
            self.assertEqual(output["decoded_juicetime"]["mechanic_summary"]["active_status_names"],
                             ["Covered"])
            self.assertEqual(manifest["summary"]["juicetime_mechanics"]["levels_with_non_normal_status"], 1)

    def test_csharp_enum_parser_and_mechanic_id_annotation(self):
        source = """// Namespace: sample.game
public enum PuzzleElementType // TypeDefIndex: 12
{
    public int value__; // 0x0
    public const PuzzleElementType NORMAL = 0;
    public const PuzzleElementType ICE = 3;
    public const PuzzleElementType UNKNOWN = 5;
}
"""
        enums = levels._parse_csharp_enums(source)
        self.assertEqual(len(enums), 1)
        self.assertEqual(enums[0]["members"], {0: "NORMAL", 3: "ICE", 5: "UNKNOWN"})
        level = {"fruitList": [{"id": 1, "elementID": 3, "coveringIds": [2]},
                               {"id": 2, "elementID": 5, "coveringIds": []}]}
        annotation = levels._mechanic_annotations(level, enums)
        self.assertEqual(annotation["enum"], "sample.game.PuzzleElementType")
        self.assertEqual(annotation["values"], [
            {"id": 3, "name": "ICE", "count": 1, "mapped": True},
            {"id": 5, "name": "UNKNOWN", "count": 1, "mapped": True},
        ])
        self.assertEqual(level["fruitList"][0]["ducapk_decoded_element"]["name"], "ICE")

    def test_mechanic_annotation_does_not_guess_using_generic_id(self):
        enums = levels._parse_csharp_enums("""public enum PuzzleElementType
{
    ICE = 3,
}
""")
        self.assertIsNone(levels._mechanic_annotations({"id": 3, "typeId": 3}, enums))

    def test_ambiguous_enum_uses_current_bundle_context_or_stays_unmapped(self):
        enums = [
            {"name": "FruitElementType", "namespace": "game.fruitstackmatch", "members": {3: "ICE"}},
            {"name": "ElementType", "namespace": "UnityEngine.Rendering", "members": {3: "Edge"}},
        ]
        self.assertEqual(
            levels._enum_candidates_for_mechanic_field(
                "elementID", enums, "hurdle_fruitstackmatch_levels_pack_001"),
            [enums[0]],
        )
        self.assertEqual(levels._enum_candidates_for_mechanic_field("elementID", enums), [])

    def test_job_level_export_is_annotated_and_manifest_is_updated(self):
        with tempfile.TemporaryDirectory() as temporary:
            job = Path(temporary)
            (job / "il2cppdumper").mkdir()
            level_path = job / "levels" / "hurdle_puzzlemode_levels_pack_001" / "pack_001" / "Level 1.json"
            level_path.parent.mkdir(parents=True)
            (job / "il2cppdumper" / "dump.cs").write_text("""// Namespace: example.puzzlemode
public enum PuzzleElementType
{
    ICE = 3,
}
""", encoding="utf-8")
            level_path.write_text(json.dumps({"items": [{"elementID": 3}]}), encoding="utf-8")
            manifest = {
                "groups": [{"bundle": "hurdle_puzzlemode_levels_pack_001.unity3d",
                            "levels": [{"file": level_path.relative_to(job).as_posix()}]}],
                "summary": {},
            }
            (job / "levels.json").write_text(json.dumps(manifest), encoding="utf-8")
            messages = []

            annotated = levels.annotate_level_mechanics(job, messages.append)

            self.assertEqual(annotated, 1)
            exported = json.loads(level_path.read_text(encoding="utf-8"))
            self.assertEqual(exported["items"][0]["elementID"], 3)
            self.assertEqual(exported["items"][0]["ducapk_decoded_element"]["name"], "ICE")
            updated_manifest = json.loads((job / "levels.json").read_text(encoding="utf-8"))
            self.assertEqual(updated_manifest["summary"]["mechanic_levels_annotated"], 1)
            self.assertEqual(updated_manifest["groups"][0]["levels"][0]["mechanics"]["values"][0]["name"], "ICE")

    def test_game_stream_transform_round_trip(self):
        logical_name = "hurdle_example_levels_pack_001_bytes.unity3d"
        base = len(logical_name) + 4
        tail = b"UnityFS\x00payload-and-block-data"
        plain = b"P" * base + tail
        chars = logical_name.encode("utf-16-le")
        weighted = sum((i + 1) * int.from_bytes(chars[i * 2:i * 2 + 2], "little")
                       for i in range(len(chars) // 2)) & 0xFFFFFFFF
        remaining = len(plain) - base
        product = (remaining * weighted) & 0xFFFFFFFF
        signed_product = product if product < 0x80000000 else product - 0x100000000
        quotient = abs(signed_product) // 104729
        if signed_product < 0:
            quotient = -quotient
        salt = abs(signed_product - quotient * 104729)
        threshold = salt % remaining
        key = salt % (len(chars) // 2) & 0xFF
        if key == 0:
            key = chars[0]
        masked = bytearray(plain)
        masked[base + threshold] ^= key

        self.assertEqual(levels._decrypt_bundle_stream(bytes(masked), logical_name), tail)

    def test_hdpk_index_decodes_original_json_records(self):
        records = [
            {"treeID": 3, "fruitList": [{"fruit": "apple"}]},
            "1;2;3;fruit/stack|match",
            {"treeID": 5, "fruitList": [{"fruit": "pear"}]},
        ]
        payloads = [json.dumps(item, separators=(",", ":")).encode() for item in records]
        data_offset = 16 + (len(records) - 1) * 12 + 4
        table = bytearray()
        position = data_offset
        for index, payload in enumerate(payloads[:-1]):
            end = position + len(payload)
            table.extend(struct.pack("<III", len(payload), index + 2, end))
            position = end
        table.extend(struct.pack("<I", len(payloads[-1])))
        header = b"HDPK" + struct.pack("<III", len(records), 1, data_offset)
        header += table
        header += b"\x00" * (data_offset - len(header))
        packed = header + b"".join(payloads)

        result = levels._unpack_hdpk_pack(packed)
        self.assertEqual([entry_id for entry_id, _ in result], [1, 2, 3])
        self.assertEqual([record for _, record in result], records)

    @unittest.skipIf(levels.AES is None, "pycryptodome is required")
    def test_package_manifest_decryption_and_bundle_index(self):
        name = "hurdle_example_levels_pack_001_bytes.unity3d"
        bundle_hash = "0123456789abcdef0123456789abcdef"
        plain = (struct.pack("<H", len(name.encode())) + name.encode()
                 + struct.pack("<I", 0x12345678) + struct.pack("<H", 32)
                 + bundle_hash.encode())
        padding = 16 - (len(plain) % 16)
        padded = plain + bytes([padding]) * padding
        key = hashlib.sha256(b"test-code").digest()
        encrypted = levels.AES.new(key, levels.AES.MODE_CBC,
                                   levels._PACKAGE_MANIFEST_IV).encrypt(padded)

        decrypted = levels._decrypt_package_manifest(encrypted, "test-code")
        self.assertEqual(levels._manifest_bundle_names(decrypted), {bundle_hash: name})

    def test_abbreviated_level_keys_are_expanded_from_game_classes(self):
        source = (
            "namespace Game.Levels\n{\n"
            "public class LevelData\n{\n"
            "\t[JsonProperty(\"id\")]\n\tpublic int levelId;\n"
            "\t[JsonProperty(\"t\")]\n\tpublic List<TileData> tiles;\n}\n"
            "public class TileData\n{\n"
            "\t[JsonProperty(\"p\")]\n\tpublic Vector3 position;\n"
            "\t[DataMember(Name = \"r\")]\n\tpublic float rotation;\n"
            "\t[Key(\"c\")]\n\tpublic int color;\n}\n}\n")
        with tempfile.TemporaryDirectory() as temporary:
            job = Path(temporary)
            (job / "cpp2il_types").mkdir()
            (job / "cpp2il_types" / "Levels.cs").write_text(source, encoding="utf-8")
            level_file = job / "levels" / "pack" / "Level 1.json"
            level_file.parent.mkdir(parents=True)
            level_file.write_text(json.dumps(
                {"id": 7, "t": [{"p": [1, 2, 0], "r": 90.0, "c": 3, "x": 1}]}), encoding="utf-8")
            (job / "levels.json").write_text(json.dumps({"groups": [
                {"levels": [{"file": "levels/pack/Level 1.json"}]}]}), encoding="utf-8")

            self.assertEqual(levels.annotate_level_field_names(job, lambda _: None), 1)
            level = json.loads(level_file.read_text(encoding="utf-8"))
            self.assertEqual(level["levelId"], 7)
            self.assertEqual(level["tiles"], [{"position": [1, 2, 0], "rotation": 90.0,
                                               "color": 3, "x": 1}])
            self.assertEqual(level["ducapk_field_aliases"]["Game.Levels.TileData"]["position"], "p")

            # Running again keeps names stable and the reverse mapping intact.
            levels.annotate_level_field_names(job, lambda _: None)
            again = json.loads(level_file.read_text(encoding="utf-8"))
            self.assertEqual(again["tiles"], level["tiles"])
            self.assertEqual(again["ducapk_field_aliases"], level["ducapk_field_aliases"])

    def test_memory_bundle_xxtea_round_trip(self):
        def encrypt(words, key):
            count = len(words)
            total = 0
            z = words[-1]
            for _ in range(50 // count + 7):
                total = (total + levels._XXTEA_DELTA) & 0xFFFFFFFF
                e = (total >> 2) & 3
                for p in range(count):
                    y = words[(p + 1) % count]
                    mx = ((((y >> 5) ^ (z << 2)) + ((z >> 3) ^ (y << 3)))
                          ^ ((total ^ y) + (key[(p & 3) ^ e] ^ z))) & 0xFFFFFFFF
                    words[p] = z = (words[p] + mx) & 0xFFFFFFFF
            return words

        name = "assets_example_data_config.unity3d"
        plain = b"UnityFS\x00" + bytes(range(37))
        padded = plain + bytes(-len(plain) % 4)
        words = list(struct.unpack(f"<{len(padded) // 4}I", padded)) + [len(plain)]
        key = list(struct.unpack("<4I", levels._MEMORY_BUNDLE_XXTEA_KEY.encode("utf-16-le")))
        body = struct.pack(f"<{len(words)}I", *encrypt(words, key))
        bundle = bytes(len(name) + 4) + body

        self.assertEqual(levels._decrypt_memory_bundle(bundle, name), plain)
        self.assertEqual(levels._decrypt_yooasset_bundle(bundle, name),
                         (plain, "load-from-memory-xxtea"))
        self.assertIsNone(levels._decrypt_memory_bundle(bundle, name + "x"))

    def test_config_payload_aes_decryption(self):
        plain = json.dumps({"rotaId": 216033, "adzList": [], "name": "x" * 64}).encode()
        padding = 16 - (len(plain) % 16)
        key, iv = levels._CONFIG_AES_KEYS[0]
        encrypted = levels.AES.new(key, levels.AES.MODE_CBC, iv).encrypt(
            plain + bytes([padding]) * padding)
        envelope = levels._base64_envelope_bytes(
            levels.base64.b64encode(encrypted) + b"\n")

        self.assertEqual(levels._decrypt_config_payload(envelope),
                         {"rotaId": 216033, "adzList": [], "name": "x" * 64})
        self.assertIsNone(levels._decrypt_config_payload(bytes(range(32))))


if __name__ == "__main__":
    unittest.main()
