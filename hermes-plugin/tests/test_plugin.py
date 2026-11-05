"""Tests with a stub guard. They need no Hermes install and no network."""

import importlib.util
import json
import pathlib
import sys
import types
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location(
    "x402_spend_guard", ROOT / "__init__.py", submodule_search_locations=[str(ROOT)]
)
plugin = importlib.util.module_from_spec(spec)
sys.modules["x402_spend_guard"] = plugin
spec.loader.exec_module(plugin)


class Ctx:
    def __init__(self):
        self.tools, self.hooks = {}, {}

    def get_config(self, key, default=None):
        return default

    def register_tool(self, name, toolset, schema, handler):
        self.tools[name] = handler

    def register_hook(self, name, callback):
        self.hooks[name] = callback


def hook(tool, args, verdict=None, error=None):
    with mock.patch.object(plugin.client, "check", return_value=verdict, side_effect=error):
        return plugin.pre_tool_call(tool_name=tool, args=args, task_id="t")


class Hook(unittest.TestCase):
    URL = {"url": "https://m.example/data"}

    def test_a_tool_outside_the_gate_passes(self):
        self.assertIsNone(hook("read_file", {}))

    def test_own_tools_pass(self):
        self.assertIsNone(hook("guarded_fetch", self.URL))

    def test_an_allowed_payment_passes(self):
        self.assertIsNone(hook("x402_pay", self.URL, {"outcome": "checked", "verdict": {"decision": "ALLOW"}}))

    def test_a_free_url_passes(self):
        self.assertIsNone(hook("x402_pay", self.URL, {"outcome": "checked", "free": True, "verdict": None}))

    def test_a_checked_result_with_no_verdict_blocks(self):
        self.assertEqual(hook("x402_pay", self.URL, {"outcome": "checked"})["action"], "block")

    def test_a_denied_payment_blocks(self):
        self.assertEqual(
            hook("x402_pay", self.URL, {"outcome": "checked", "verdict": {"decision": "DENY"}})["action"], "block"
        )

    def test_a_refused_payment_blocks(self):
        self.assertEqual(hook("x402_pay", self.URL, {"outcome": "refused"})["action"], "block")

    def test_a_confirmation_goes_to_the_approval_gate(self):
        verdict = {"outcome": "checked", "verdict": {"decision": "ESCALATE"}}
        self.assertEqual(hook("x402_pay", self.URL, verdict)["action"], "approve")

    def test_an_unknown_outcome_blocks(self):
        self.assertEqual(hook("x402_pay", self.URL, {"outcome": "new"})["action"], "block")

    def test_no_url_blocks(self):
        self.assertEqual(hook("x402_pay", {})["action"], "block")

    def test_an_unreachable_guard_blocks(self):
        self.assertEqual(hook("x402_pay", self.URL, error=plugin.client.GuardError("down"))["action"], "block")

    def test_an_unexpected_crash_blocks(self):
        self.assertEqual(hook("x402_pay", self.URL, error=RuntimeError("bad"))["action"], "block")

    def test_a_block_has_a_message(self):
        self.assertTrue(hook("x402_pay", {})["message"])


class Handlers(unittest.TestCase):
    def test_register_adds_all_tools_and_the_hook(self):
        ctx = Ctx()
        plugin.register(ctx)
        self.assertEqual(set(ctx.tools), set(plugin.OWN_TOOLS))
        self.assertIn("pre_tool_call", ctx.hooks)

    def test_a_handler_returns_json_for_an_error(self):
        with mock.patch.object(plugin.client, "pay", side_effect=RuntimeError("bad")):
            self.assertEqual(json.loads(plugin.tools.guarded_fetch({"url": "u"})), {"error": "bad"})

    def test_a_bad_limit_returns_json(self):
        self.assertIn("error", json.loads(plugin.tools.spend_audit({"limit": "x"})))

    def test_audit_accepts_a_list(self):
        with mock.patch.object(plugin.client, "_call", return_value=[{"outcome": "paid"}]):
            self.assertEqual(json.loads(plugin.tools.spend_audit({}))["events"], [{"outcome": "paid"}])

    def test_a_missing_token_is_an_error(self):
        scope = types.ModuleType("agent.secret_scope")
        scope.get_secret = lambda name: None
        with mock.patch.dict(sys.modules, {"agent": types.ModuleType("agent"), "agent.secret_scope": scope}):
            self.assertIn("GUARD_HTTP_TOKEN", json.loads(plugin.tools.spend_status({}))["error"])


if __name__ == "__main__":
    unittest.main()
