import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from mcp_trust_scanner import __version__
from mcp_trust_scanner.cli import main
from mcp_trust_scanner.models import Finding, ScanResult, Severity
from mcp_trust_scanner.sarif import _artifact_uri, _server_line, to_sarif

ROOT = Path(__file__).resolve().parent.parent
VULN = ROOT / "examples" / "vulnerable_config.json"


def run_cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


def finding(fid="CFG-003", severity=Severity.HIGH, server="srv", title="A title"):
    return Finding(id=fid, title=title, severity=severity, category="config", server_name=server,
                   description="Description text.", recommendation="Fix it.")


class TestSarifDocument(unittest.TestCase):
    def make(self, findings):
        return ScanResult(scanned_at="2026-01-01T00:00:00Z", target_label="x.json", servers=[], findings=findings)

    def test_empty_result_is_a_valid_empty_run(self):
        doc = to_sarif(self.make([]), "x.json", "0.2.0")
        self.assertEqual(doc["version"], "2.1.0")
        run = doc["runs"][0]
        self.assertEqual(run["results"], [])
        self.assertEqual(run["tool"]["driver"]["rules"], [])
        self.assertEqual(run["tool"]["driver"]["version"], "0.2.0")

    def test_severity_maps_to_level_and_security_severity(self):
        fs = [finding("CFG-001", Severity.CRITICAL), finding("CFG-003", Severity.HIGH),
              finding("DRIFT-001", Severity.MEDIUM), finding("TDX-007", Severity.LOW),
              finding("LIVE-001", Severity.INFO)]
        results = to_sarif(self.make(fs), "x.json", "0.2.0")["runs"][0]["results"]
        self.assertEqual([r["level"] for r in results], ["error", "error", "warning", "note", "note"])
        sev = [float(r["properties"]["security-severity"]) for r in results]
        self.assertTrue(sev[0] > 9.0 and 7.0 <= sev[1] < 9.0 and 4.0 <= sev[2] < 7.0 and sev[3] < 4.0)

    def test_rules_are_deduplicated_and_indexed(self):
        fs = [finding("CFG-003", server="a"), finding("CFG-003", server="b"), finding("CFG-004", server="a")]
        run = to_sarif(self.make(fs), "x.json", "0.2.0")["runs"][0]
        rules = run["tool"]["driver"]["rules"]
        self.assertEqual([r["id"] for r in rules], ["CFG-003", "CFG-004"])
        for res in run["results"]:
            self.assertEqual(rules[res["ruleIndex"]]["id"], res["ruleId"])

    def test_fingerprints_are_stable_and_distinct(self):
        a = to_sarif(self.make([finding(server="a"), finding(server="b")]), "x.json", "0.2.0")["runs"][0]["results"]
        b = to_sarif(self.make([finding(server="a"), finding(server="b")]), "x.json", "0.2.0")["runs"][0]["results"]
        fa = [r["partialFingerprints"]["mcpScannerFinding/v2"] for r in a]
        fb = [r["partialFingerprints"]["mcpScannerFinding/v2"] for r in b]
        self.assertEqual(fa, fb)
        self.assertNotEqual(fa[0], fa[1])

    def test_line_number_points_at_the_server_declaration(self):
        text = '{\n  "mcpServers": {\n    "first": {},\n    "second": {}\n  }\n}\n'
        self.assertEqual(_server_line(text, "first"), 3)
        self.assertEqual(_server_line(text, "second"), 4)
        self.assertEqual(_server_line(text, "missing"), 1)

    def test_uri_is_relative_posix_and_keeps_leading_dot(self):
        self.assertEqual(_artifact_uri("./.mcp.json"), ".mcp.json")
        self.assertEqual(_artifact_uri("dir/sub/cfg.json"), "dir/sub/cfg.json")
        inside = str(Path.cwd() / "inner" / "cfg.json")
        self.assertEqual(_artifact_uri(inside), "inner/cfg.json")


class TestSarifCli(unittest.TestCase):
    def test_sarif_file_written_for_vulnerable_example(self):
        with tempfile.TemporaryDirectory() as d:
            sarif = os.path.join(d, "out.sarif")
            code, _, _ = run_cli("scan", str(VULN), "--no-drift-check", "--sarif-out", sarif,
                                 "--out", os.path.join(d, "r.md"), "--quiet")
            self.assertEqual(code, 0)
            doc = json.loads(Path(sarif).read_text(encoding="utf-8"))
            run = doc["runs"][0]
            self.assertGreater(len(run["results"]), 0)
            ids = {r["ruleId"] for r in run["results"]}
            self.assertIn("CFG-003", ids)
            self.assertTrue(all(r["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1
                                for r in run["results"]))

    def test_sarif_does_not_change_the_gate_exit_code(self):
        with tempfile.TemporaryDirectory() as d:
            code, _, _ = run_cli("scan", str(VULN), "--no-drift-check", "--fail-on", "high",
                                 "--sarif-out", os.path.join(d, "o.sarif"),
                                 "--out", os.path.join(d, "r.md"), "--quiet")
            self.assertEqual(code, 1)
            self.assertTrue(Path(d, "o.sarif").exists())

    def test_version_flag(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), self.assertRaises(SystemExit) as cm:
            main(["--version"])
        self.assertEqual(cm.exception.code, 0)
        self.assertIn(__version__, buf.getvalue())


if __name__ == "__main__":
    unittest.main()
