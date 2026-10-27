import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock
from mcp_trust_scanner.config_parser import parse_config_file, ConfigParseError
from mcp_trust_scanner.baseline import save_baseline, diff_against_baseline, baseline_path
from mcp_trust_scanner.models import ServerInfo, ToolInfo
from mcp_trust_scanner.cli import main
from mcp_trust_scanner.live_connector import LiveConnectError
from mcp_trust_scanner.llm_judge import judge_tools, LLMJudgeError
import importlib.util

class Regressions(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'config.json'
    def write(self, obj):
        self.path.write_text(json.dumps(obj))
        return str(self.path)
    def test_invalid_shapes_raise_parse_error(self):
        for obj in [{'mcpServers': []}, {'servers': 'bad'}, ['bad'],
                    {'mcpServers': {'s': {'args': 'bad'}}},
                    {'mcpServers': {'s': {'env': {'KEY': 4}}}},
                    {'mcpServers': {'s': {'tools': [{'name': 'x', 'description': []}]}}},
                    {'mcpServers': {'s': {'tools': [{'name': 'x', 'inputSchema': []}]}}},
                    [{'name':'s','command':'python'}, {'name':'s','command':'python'}]]:
            with self.subTest(obj=obj), self.assertRaises(ConfigParseError):
                parse_config_file(self.write(obj))
    def test_duplicate_tool_names_are_rejected(self):
        self.write({'command': 'python', 'tools': [{'name':'a'}, {'name':'a'}]})
        with self.assertRaises(ConfigParseError): parse_config_file(str(self.path))
    def test_cli_invalid_config_returns_two(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(['scan', self.write(['bad'])]), 2)
    def test_baseline_name_collision_is_avoided(self):
        self.assertNotEqual(baseline_path(self.tmp.name, 'a/b'), baseline_path(self.tmp.name, 'a?b'))
    def test_launch_change_is_detected(self):
        s = ServerInfo(name='s', transport='stdio', command='python', tools=[ToolInfo('ping')])
        save_baseline(self.tmp.name, s)
        s.command = 'other'
        self.assertIn('DRIFT-004', [f.id for f in diff_against_baseline(s, self.tmp.name)])
    def test_live_failure_does_not_overwrite_baseline_or_claim_success(self):
        self.write({'mcpServers': {'s': {'command':'python', 'tools':[{'name':'ping'}]}}})
        s = parse_config_file(str(self.path))[0]
        baseline = save_baseline(self.tmp.name, s)
        before = baseline.read_bytes()
        out = Path(self.tmp.name) / 'report.json'
        with patch('mcp_trust_scanner.live_connector.fetch_live_tools', side_effect=LiveConnectError('offline')):
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                code = main(['scan', str(self.path), '--live', '--pin', '--baseline-dir', self.tmp.name, '--json-out', str(out)])
        self.assertEqual(code, 2)
        self.assertEqual(before, baseline.read_bytes())
        self.assertFalse(json.loads(out.read_text())['live_introspection_used'])
    def test_gate_failure_does_not_pin(self):
        self.write({'mcpServers': {'s': {'command':'sh', 'args':['-c','echo test']}}})
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = main(['scan', str(self.path), '--pin', '--fail-on','high','--baseline-dir',self.tmp.name])
        self.assertEqual(code, 1)
        self.assertFalse(baseline_path(self.tmp.name, 's').exists())
    def test_malformed_baseline_is_controlled_error(self):
        self.write({'mcpServers': {'s': {'command':'python'}}})
        baseline_path(self.tmp.name,'s').write_text('[]')
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(['scan',str(self.path),'--baseline-dir',self.tmp.name]), 2)
    @unittest.skipUnless(importlib.util.find_spec("anthropic"), "optional anthropic SDK not installed")
    def test_invalid_judge_results_are_controlled_errors(self):
        for payload in [{}, [], [{'tool_name':'wrong','verdict':'benign','reasoning':'ok'}],
                        [{'tool_name':'ping','verdict':'other','reasoning':'ok'}]]:
            block = MagicMock(type='text', text=json.dumps(payload))
            with patch('anthropic.Anthropic') as client:
                client.return_value.messages.create.return_value.content = [block]
                with self.assertRaises(LLMJudgeError): judge_tools([ToolInfo('ping')], 'dummy')


class PaginationTests(unittest.IsolatedAsyncioTestCase):
    async def test_all_tool_pages_are_collected(self):
        from types import SimpleNamespace
        from unittest.mock import AsyncMock
        from mcp_trust_scanner.live_connector import _list_all_tools
        session = SimpleNamespace(list_tools=AsyncMock(side_effect=[
            SimpleNamespace(tools=[SimpleNamespace(name="a", description="", inputSchema={})], nextCursor="next"),
            SimpleNamespace(tools=[SimpleNamespace(name="b", description="", inputSchema={})], nextCursor=None)]))
        self.assertEqual([t.name for t in await _list_all_tools(session)], ["a", "b"])
    async def test_repeated_cursor_is_rejected(self):
        from types import SimpleNamespace
        from unittest.mock import AsyncMock
        from mcp_trust_scanner.live_connector import _list_all_tools
        session = SimpleNamespace(list_tools=AsyncMock(return_value=SimpleNamespace(tools=[], nextCursor="same")))
        with self.assertRaises(LiveConnectError): await _list_all_tools(session)

if __name__ == '__main__': unittest.main()
