import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from mcp_trust_scanner.baseline import diff_against_baseline, save_baseline
from mcp_trust_scanner.models import ServerInfo
from mcp_trust_scanner.static_checks import run_static_checks


class SecurityRegressions(unittest.TestCase):
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
        secrets = ['url-secret-46879', 'shell-secret-99331', 'Qz9', 'header-secret-5237']
        config = {'mcpServers': {
            'remote': {'url': 'http://127.0.0.1.attacker.invalid/mcp?credential=' + secrets[0],
                       'headers': {'Authorization': secrets[3]}},
            'local': {'command': 'sh', 'args': ['-c', 'echo --token ' + secrets[1]],
                      'env': {'API_KEY': secrets[2]}},
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
            for value in secrets:
                for artifact in artifacts:
                    self.assertNotIn(value, artifact)
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
