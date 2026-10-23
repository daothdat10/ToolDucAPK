import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import tempfile
import threading
import unittest

from ducapk.api_translation import APIConfig, APIError, complete, export_api, test_connection, translate_file


class TranslationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                payload = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                cls.requests.append((self.path, self.headers.get('Authorization'), payload))
                self.send_response(cls.status)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(cls.response).encode())

            def log_message(self, *_):
                pass
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def setUp(self):
        type(self).requests = []
        type(self).status = 200
        type(self).response = {'choices': [{'finish_reason': 'stop', 'message': {
            'content': '```csharp\npublic class Example { public int Count() => 2; }\n```'}}]}
        self.config = APIConfig(f'http://127.0.0.1:{self.server.server_port}/v1', 'test-model', 'secret-test-key')
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_connection_and_request_shape(self):
        self.assertIn('thành công', test_connection(self.config))
        endpoint, auth, payload = self.requests[0]
        self.assertEqual(endpoint, '/v1/chat/completions')
        self.assertEqual(auth, 'Bearer secret-test-key')
        self.assertEqual(payload['model'], 'test-model')
        self.assertFalse(payload['stream'])
        self.assertNotIn('secret-test-key', repr(self.config))

    def test_ghidra_c_translation_uses_il2cpp_reconstruction_knowledge(self):
        source = self.root / 'PlayerController.c'
        source.write_text('/* IL2CPP class: Game.PlayerController */\nint FUN_00123456() { return 1; }',
                          encoding='utf-8')
        translate_file(self.config, source)
        system_prompt = self.requests[0][2]['messages'][0]['content']
        self.assertIn('not the original Unity C# source', system_prompt)
        self.assertIn('Treat IL2CPP class/method/signature/RVA comments', system_prompt)
        self.assertIn('Do not invent', system_prompt)

    def test_csharp_cleanup_does_not_receive_native_pseudocode_rules(self):
        source = self.root / 'PlayerController.cs'
        source.write_text('public class PlayerController {}', encoding='utf-8')
        translate_file(self.config, source)
        system_prompt = self.requests[0][2]['messages'][0]['content']
        self.assertNotIn('Domain knowledge for Ghidra C pseudocode', system_prompt)

    def test_mixed_tree_preserves_source_and_paths_and_name_collisions(self):
        source = self.root / 'source'
        (source / 'game').mkdir(parents=True)
        (source / 'game' / 'Example.c').write_text('int Count() { return 2; }', encoding='utf-8')
        (source / 'game' / 'Example.cs').write_text('public class Example {}', encoding='utf-8')
        (source / 'ignored.txt').write_text('ignored')
        originals = {p: p.read_bytes() for p in source.rglob('*') if p.is_file()}
        destination = self.root / 'output'
        report = export_api(source, destination, self.config, 'Keep method names')
        self.assertEqual(report['files_written'], 2)
        self.assertEqual(report['files_failed'], 0)
        self.assertEqual(len(list(destination.rglob('*.cs'))), 2)
        for path, content in originals.items():
            self.assertEqual(path.read_bytes(), content)
        for path in destination.rglob('*.cs'):
            self.assertNotIn('```', path.read_text())
        self.assertIn('Keep method names', self.requests[0][2]['messages'][0]['content'])
        self.assertNotIn('secret-test-key', (destination / 'api_translation_report.json').read_text())

    def test_truncated_output_is_not_saved(self):
        type(self).response['choices'][0]['finish_reason'] = 'length'
        source = self.root / 'input.cs'
        source.write_text('public class Example {}')
        report = export_api(source, self.root / 'output', self.config)
        self.assertEqual(report['files_failed'], 1)
        self.assertEqual(report['files_written'], 0)
        self.assertFalse(list((self.root / 'output').glob('*.cs')))

    def test_auth_error_stops_batch_without_leaking_server_body(self):
        type(self).status = 401
        type(self).response = {'error': 'secret-test-key'}
        source = self.root / 'source'
        source.mkdir()
        for name in ['a.c', 'b.c']:
            (source / name).write_text('int f() { return 2; }')
        report = export_api(source, self.root / 'output', self.config)
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(report['files_pending'], 1)
        self.assertTrue(report['stopped_on_api_error'])
        self.assertNotIn('secret-test-key', json.dumps(report))

    def test_cancel_after_current_file_keeps_report(self):
        source = self.root / 'source'
        source.mkdir()
        for name in ['a.c', 'b.cs']:
            (source / name).write_text('public class Example {}')
        cancel = threading.Event()
        def progress(done, total, message):
            if done == 1:
                cancel.set()
        report = export_api(source, self.root / 'output', self.config, cancel=cancel, progress=progress)
        self.assertTrue(report['cancelled'])
        self.assertEqual(report['files_written'], 1)
        self.assertEqual(report['files_pending'], 1)

    def test_reject_nested_destination_and_existing_output(self):
        source = self.root / 'source'
        source.mkdir()
        (source / 'a.c').write_text('int f() { return 2; }')
        with self.assertRaises(ValueError):
            export_api(source, source / 'output', self.config)
        destination = self.root / 'output'
        destination.mkdir()
        with self.assertRaises(FileExistsError):
            export_api(source, destination, self.config)
        self.assertEqual(len(self.requests), 0)

    def test_invalid_response(self):
        type(self).response = {'unexpected': True}
        with self.assertRaises(APIError):
            complete(self.config, [{'role': 'user', 'content': 'OK'}])

    def test_invalid_url_and_model(self):
        for url in ['http://example.com/v1', 'https://name:password@example.com', 'https://example.com/?token=123']:
            with self.assertRaises(ValueError):
                APIConfig(url, 'model', '').validate()
        with self.assertRaises(ValueError):
            APIConfig('https://example.com/v1', '', '').validate()


if __name__ == '__main__':
    unittest.main()
