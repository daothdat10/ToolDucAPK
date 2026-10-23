import tempfile
import unittest
from pathlib import Path

from ducapk.runner import _metadata_path


def _make_metadata():
    blob = bytearray(1536)
    blob[:4] = b"\xaf\x1b\xb1\xfa"
    blob[4:8] = (24).to_bytes(4, "little")
    for index in range(32):
        pos = 8 + index * 8
        blob[pos:pos + 4] = 0x100.to_bytes(4, "little")
        blob[pos + 4:pos + 8] = (0).to_bytes(4, "little")
    blob[1100:1115] = b"Assembly-CSharp"
    return bytes(blob)


def _encrypt_embedded_xor(metadata, key_length=130):
    key_words = [0xA5A50000 + index for index in range(key_length)]
    encrypted_payload = bytearray()
    payload = metadata[1024:]
    for pos in range(0, len(payload), 4):
        key_index = (pos + (pos // key_length)) % key_length
        chunk = payload[pos:pos + 4]
        word = int.from_bytes(chunk, "little") ^ key_words[key_index]
        # Like the native encoder, only the original byte count is written.
        encrypted_payload.extend(word.to_bytes(4, "little")[:len(chunk)])
    descriptor = (0xA5A50000 | key_length).to_bytes(4, "little")
    key = b"".join(word.to_bytes(4, "little") for word in key_words)
    return metadata[:1024] + descriptor + key + encrypted_payload


class MetadataRecoveryTests(unittest.TestCase):
    def test_recovers_inline_key_xor_metadata_and_keeps_input_unchanged(self):
        original = _make_metadata()
        encoded = _encrypt_embedded_xor(original)
        with tempfile.TemporaryDirectory() as temporary:
            job = Path(temporary)
            input_dir = job / "input"
            input_dir.mkdir()
            source = input_dir / "global-metadata.dat"
            source.write_bytes(encoded)
            (input_dir / "libil2cpp.so").write_bytes(b"matching native library")
            messages = []

            result = _metadata_path(job, messages.append)

            self.assertEqual(result.read_bytes(), original)
            self.assertEqual(source.read_bytes(), encoded)
            self.assertTrue(any("Il2cppEncrtypt" in message and "kl=130" in message
                                for message in messages))

    def test_recovers_inline_key_xor_metadata_with_unaligned_tail(self):
        for tail in (1, 2, 3):
            with self.subTest(tail=tail):
                original = _make_metadata() + bytes(range(0x41, 0x41 + tail))
                encoded = _encrypt_embedded_xor(original, key_length=137)
                with tempfile.TemporaryDirectory() as temporary:
                    job = Path(temporary)
                    input_dir = job / "input"
                    input_dir.mkdir()
                    (input_dir / "global-metadata.dat").write_bytes(encoded)
                    (input_dir / "libil2cpp.so").write_bytes(b"native")

                    result = _metadata_path(job)

                    self.assertEqual(result.read_bytes(), original)

    def test_unsupported_inline_key_length_does_not_create_sidecar(self):
        original = _make_metadata()
        encoded = _encrypt_embedded_xor(original, key_length=129)
        with tempfile.TemporaryDirectory() as temporary:
            job = Path(temporary)
            input_dir = job / "input"
            input_dir.mkdir()
            (input_dir / "global-metadata.dat").write_bytes(encoded)
            (input_dir / "libil2cpp.so").write_bytes(b"native")

            result = _metadata_path(job)

            self.assertEqual(result, input_dir / "global-metadata.dat")
            self.assertFalse((job / "recovered_il2cpp" /
                              "global-metadata.decrypted.dat").exists())


if __name__ == "__main__":
    unittest.main()
