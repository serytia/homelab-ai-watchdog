"""openai-compat provider against a real local HTTP mock (no requests patching)."""

import json
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import triage as triage_mod  # noqa: E402


def _completion(findings, finish_reason="stop", content_prefix=""):
    """A minimal but faithful chat/completions body, as Ollama returns it."""
    return {
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "model": "qwen3:8b",
        "choices": [{
            "index": 0,
            "finish_reason": finish_reason,
            "message": {
                "role": "assistant",
                "content": content_prefix + json.dumps({"findings": findings}),
            },
        }],
    }


FINDING = {
    "id": "vzdump-104-failed",
    "severity": "warning",
    "title": "Backup job failing on VM 104",
    "detail": "vzdump exited 255",
    "suggested_action": "qm delsnapshot 104 auto",
}


class _Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.server.seen.append((self.path, body))
        status, payload = self.server.script.pop(0)
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):  # keep test output clean
        pass


class OpenAICompatTest(unittest.TestCase):
    def setUp(self):
        self.server = HTTPServer(("127.0.0.1", 0), _Handler)
        self.server.seen = []
        self.server.script = []
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base_url = f"http://127.0.0.1:{self.server.server_address[1]}/v1"
        self.cfg = {"provider": "openai-compat", "base_url": self.base_url,
                    "model": "qwen3:8b"}

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def test_returns_findings_and_sends_openai_shape(self):
        self.server.script.append((200, _completion([FINDING])))
        findings = triage_mod.triage(self.cfg, {"nodes": []})
        self.assertEqual(findings, [FINDING])

        path, body = self.server.seen[0]
        self.assertEqual(path, "/v1/chat/completions")
        self.assertEqual(body["model"], "qwen3:8b")
        self.assertIs(body["stream"], False)
        # The schema must ride along in the standard OpenAI json_schema wrapper
        # (Ollama unwraps json_schema.schema into its native `format` field).
        rf = body["response_format"]
        self.assertEqual(rf["type"], "json_schema")
        self.assertEqual(rf["json_schema"]["schema"], triage_mod.FINDINGS_SCHEMA)
        # System prompt as a proper system message, snapshot as the user turn.
        self.assertEqual(body["messages"][0]["role"], "system")
        self.assertEqual(body["messages"][1]["role"], "user")
        self.assertIn('"current"', body["messages"][1]["content"])

    def test_deep_pass_goes_through_same_provider(self):
        deep = {**FINDING, "detail": "leftover snapshot from 07/28 blocks vzdump",
                "suggested_action": "qm delsnapshot 104 auto-2026-07-28"}
        self.server.script.append((200, _completion([FINDING])))
        self.server.script.append((200, _completion([deep])))

        cfg = {**self.cfg, "deep_model": "qwen3:32b"}
        findings = triage_mod.triage(cfg, {"nodes": []})

        self.assertEqual(len(self.server.seen), 2)
        self.assertEqual(self.server.seen[1][1]["model"], "qwen3:32b")
        self.assertEqual(findings[0]["detail"], deep["detail"])
        self.assertEqual(findings[0]["suggested_action"], deep["suggested_action"])

    def test_deep_pass_failure_keeps_first_pass(self):
        self.server.script.append((200, _completion([FINDING])))
        self.server.script.append((500, {"error": "model exploded"}))
        cfg = {**self.cfg, "deep_model": "qwen3:32b"}
        findings = triage_mod.triage(cfg, {"nodes": []})
        self.assertEqual(findings, [FINDING])

    def test_http_error_raises_triage_error(self):
        self.server.script.append((500, {"error": "boom"}))
        with self.assertRaises(triage_mod.TriageError):
            triage_mod.triage(self.cfg, {"nodes": []})

    def test_think_block_is_stripped(self):
        self.server.script.append(
            (200, _completion([FINDING], content_prefix="<think>hmm, VM 104...</think>")))
        findings = triage_mod.triage(self.cfg, {"nodes": []})
        self.assertEqual(findings, [FINDING])

    def test_truncated_output_raises(self):
        self.server.script.append((200, _completion([FINDING], finish_reason="length")))
        with self.assertRaises(triage_mod.TriageError):
            triage_mod.triage(self.cfg, {"nodes": []})

    def test_missing_model_raises_clear_error(self):
        cfg = {"provider": "openai-compat", "base_url": self.base_url}
        with self.assertRaisesRegex(triage_mod.TriageError, "triage.model"):
            triage_mod.triage(cfg, {"nodes": []})

    def test_unknown_provider_raises(self):
        with self.assertRaises(triage_mod.TriageError):
            triage_mod.triage({"provider": "bedrock"}, {"nodes": []})


if __name__ == "__main__":
    unittest.main()
