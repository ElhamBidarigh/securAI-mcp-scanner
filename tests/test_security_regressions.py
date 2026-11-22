import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from mcp_trust_scanner.baseline import diff_against_baseline, save_baseline
from mcp_trust_scanner.models import Finding, ScanResult, ServerInfo, Severity
from mcp_trust_scanner.redaction import _secrets, redact_text
from mcp_trust_scanner.sarif import to_sarif
from mcp_trust_scanner.static_checks import run_static_checks


class SecurityRegressions(unittest.TestCase):
    def test_assignment_redaction_is_idempotent(self):
        for original in ('env.API_KEY = [REDACTED]', 'env.API_KEY = fake-test-secret',
                         'authorization: fake-test-secret'):
            with self.subTest(original=original):
                once = redact_text(original, {'fake-test-secret'})
                twice = redact_text(once, {'fake-test-secret'})
                self.assertEqual(once, twice)
                self.assertNotIn('fake-test-secret', once)
                self.assertNotIn('[REDACTED]]', once)
                self.assertNotIn('[REDACTED]]', twice)

    def test_common_values_do_not_corrupt_identity_or_reports(self):
        config = {'mcpServers': {'files1': {'command': 'npx',
                  'args': ['-y', '@vendor/files-mcp-v1', '--allow-all', '/'],
                  'env': {'DEBUG': '1', 'ENABLED': 'true', 'MODE': 'a'}}}}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / 'config.json'
            path.write_text(json.dumps(config))
            outputs = [root / 'report.md', root / 'report.json', root / 'report.sarif']
            p = subprocess.run([sys.executable, '-m', 'mcp_trust_scanner.cli', 'scan', str(path),
                                '--out', str(outputs[0]), '--json-out', str(outputs[1]),
                                '--sarif-out', str(outputs[2])], capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)
            md, raw_json, raw_sarif = [f.read_text() for f in outputs]
            self.assertIn('files1', md)
            self.assertIn('@vendor/files-mcp-v1', md)
            self.assertIn('--allow-all', md)
            self.assertNotIn('[REDACTED]', md)
            self.assertEqual(json.loads(raw_json)['servers'][0]['name'], 'files1')
            sarif = json.loads(raw_sarif)['runs'][0]['results']
            self.assertTrue(sarif)
            self.assertTrue(all(item['properties']['server'] == 'files1' for item in sarif))

    def test_only_secret_like_values_and_whole_tokens_are_replaced(self):
        s = ServerInfo('files1', 'stdio', env={'DEBUG': '1', 'ENABLED': 'true', 'MODE': 'a',
                        'API_TOKEN': 'alpha', 'OTHER': 'sk-LongKey123456'})
        secrets = _secrets([s])
        self.assertNotIn('1', secrets)
        self.assertNotIn('true', secrets)
        self.assertNotIn('a', secrets)
        self.assertIn('alpha', secrets)
        self.assertIn('sk-LongKey123456', secrets)
        self.assertEqual(redact_text('alpha alpha2 my-alpha-file (alpha)', {'alpha'}),
                         '[REDACTED] alpha2 my-alpha-file ([REDACTED])')

    def test_sarif_fingerprints_are_identity_based_and_distinct(self):
        def make(title, subject):
            return Finding(id='TDX-001', title=title, severity=Severity.HIGH,
                           category='tool-description', server_name='files1',
                           description='description', fingerprint_subject=subject)
        def fingerprints(findings):
            run = to_sarif(ScanResult('now', 'config', [ServerInfo('files1', 'stdio')], findings),
                           'config.json', 'test')['runs'][0]
            return [x['partialFingerprints']['mcpScannerFinding/v2'] for x in run['results']]
        original = fingerprints([make('First title', 'tool-a'), make('Second title', 'tool-b')])
        self.assertEqual(original, fingerprints([make('Changed title', 'tool-a'), make('Other title', 'tool-b')]))
        self.assertNotEqual(original[0], original[1])

    def test_secret_value_is_not_substituted_in_identifiers_or_titles(self):
        server = ServerInfo('files1', 'stdio', env={'API_KEY': 'files1'})
        finding = Finding(id='CFG-004', title='Review files1 credential', severity=Severity.HIGH,
                          category='config', server_name='files1', description='Credential: files1')
        result = ScanResult('now', 'config', [server], [finding])
        item = to_sarif(result, 'config.json', 'test')['runs'][0]['results'][0]
        self.assertEqual(item['properties']['server'], 'files1')
        self.assertEqual(item['ruleId'], 'CFG-004')
        self.assertTrue(item['message']['text'].startswith('Review files1 credential'))

    def test_localhost_matching_is_exact(self):
        cases = {
            'http://127.0.0.1/mcp': False,
            'http://127.0.0.2/mcp': False,
            'http://[::1]/mcp': False,
            'http://localhost./mcp': False,
            'http://127.0.0.1.attacker.invalid/mcp': True,
            'http://localhost.attacker.invalid/mcp': True,
            'http://[2001:db8::1]/mcp': True,
        }
        for url, expect_warning in cases.items():
            with self.subTest(url=url):
                ids = {f.id for f in run_static_checks(ServerInfo('s', 'http', url=url))}
                self.assertEqual('CFG-007' in ids, expect_warning)

    def test_outputs_and_baseline_do_not_include_fixture_secrets(self):
        secrets = ['url-secret-46879', 'shell-secret-99331', 'Qz9', 'header-secret-5237',
                   'userinfo-name-748', 'userinfo-pass-749', 'arg-token-64312']
        config = {'mcpServers': {
            'remote': {'url': 'http://' + secrets[4] + ':' + secrets[5] + '@127.0.0.1.attacker.invalid/mcp?credential=' + secrets[0],
                       'headers': {'Authorization': secrets[3]}},
            'local': {'command': 'sh', 'args': ['-c', 'echo --token ' + secrets[1]],
                      'env': {'API_KEY': secrets[2]}},
            'args': {'command': 'example-server', 'args': ['--token', secrets[6]]},
        }}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / 'config.json'
            path.write_text(json.dumps(config))
            outputs = [root / 'report.md', root / 'report.json', root / 'report.sarif']
            baseline = root / 'baseline'
            p = subprocess.run([sys.executable, '-m', 'mcp_trust_scanner.cli', 'scan', str(path),
                                '--out', str(outputs[0]), '--json-out', str(outputs[1]),
                                '--sarif-out', str(outputs[2]), '--pin', '--baseline-dir', str(baseline)],
                               capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)
            artifacts = [p.stdout, p.stderr] + [f.read_text() for f in outputs]
            artifacts += [f.read_text() for f in baseline.glob('*.json')]
            console = subprocess.run([sys.executable, '-m', 'mcp_trust_scanner.cli', 'scan', str(path)],
                                     capture_output=True, text=True)
            self.assertEqual(console.returncode, 0)
            artifacts += [console.stdout, console.stderr]
            for value in secrets:
                for artifact in artifacts:
                    self.assertNotIn(value, artifact)
            self.assertNotIn('[REDACTED]]', outputs[0].read_text())
            self.assertNotIn('[REDACTED]]', outputs[1].read_text())
            self.assertIn('CFG-007', outputs[0].read_text())

    def test_baseline_hashes_detect_changes_and_legacy_still_loads(self):
        server = ServerInfo('demo', 'stdio', command='node', args=['--token', 'old-value'])
        with tempfile.TemporaryDirectory() as tmp:
            path = save_baseline(tmp, server)
            self.assertNotIn('old-value', path.read_text())
            self.assertFalse(diff_against_baseline(server, tmp))
            server.args[-1] = 'new-value'
            self.assertIn('DRIFT-004', {f.id for f in diff_against_baseline(server, tmp)})
            path.write_text(json.dumps({'server_name': 'demo', 'transport': 'stdio',
                                        'command': 'node', 'args': ['--token', 'new-value'],
                                        'url': None, 'tools': {}}))
            self.assertFalse(diff_against_baseline(server, tmp))

    def test_report_does_not_claim_100_means_safe(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'config.json'
            path.write_text(json.dumps({'mcpServers': {'demo': {'command': 'node'}}}))
            p = subprocess.run([sys.executable, '-m', 'mcp_trust_scanner.cli', 'scan', str(path)],
                               capture_output=True, text=True)
            self.assertEqual(p.returncode, 0)
            self.assertNotIn('100/100', p.stdout + p.stderr)
            self.assertIn('cannot establish', p.stdout)


if __name__ == '__main__':
    unittest.main()
