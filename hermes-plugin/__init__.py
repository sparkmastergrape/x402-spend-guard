"""x402-spend-guard: a Hermes plugin for a local guard-server."""

import hashlib
import re

from . import client, schemas, tools

TOOLSET = "x402_spend_guard"
DEFAULT_GATED = "x402|pay|wallet|transfer|swap|fund|purchase|buy|checkout|withdraw|deposit|remit"
URL_KEYS = ("url", "uri", "endpoint", "resource")
OWN_TOOLS = ("guarded_fetch", "check_payment", "spend_status", "spend_audit")

state = {"gated": re.compile(DEFAULT_GATED, re.IGNORECASE)}


def _block(reason):
    return {"action": "block", "message": "x402-spend-guard blocked this call. " + reason}


def _find_url(args):
    for key in URL_KEYS:
        value = args.get(key) if isinstance(args, dict) else None
        if isinstance(value, str) and value:
            return value
    return None


def _rule_key(tool_name, url, amount, code):
    """Hermes uses the tool name if this is empty, so one yes would cover every later payment."""
    digest = hashlib.sha256("|".join((tool_name, url, amount, code)).encode("utf-8")).hexdigest()
    return tool_name + ":" + digest[:16]


def pre_tool_call(tool_name="", args=None, **kwargs):
    """Check a payment tool against the guard. Every failure blocks the call."""
    try:
        if tool_name in OWN_TOOLS or not state["gated"].search(tool_name or ""):
            return None
        url = _find_url(args)
        if url is None:
            return _block("The tool looks like a payment tool, and the guard found no URL to check.")
        verdict = client.check(url)
        outcome = verdict.get("outcome")
        result = verdict.get("verdict") or {}
        decision = result.get("decision")
        code = str(verdict.get("code"))
        if outcome == "checked" and verdict.get("free") and not result:
            return None
        if outcome == "checked" and decision == "ALLOW":
            return None
        if outcome == "checked" and decision == "ESCALATE":
            amount = str(verdict.get("amount"))
            return {
                "action": "approve",
                "message": "Payment of " + amount + " to " + str(url) + " is outside the mandate: " + code,
                "rule_key": _rule_key(tool_name, url, amount, code),
            }
        return _block("Guard result: " + str(outcome) + " " + str(decision) + " " + code)
    except Exception as error:  # Hermes skips a hook that crashes, so a crash must block.
        return _block("The guard check failed: " + str(error))


def register(ctx):
    client.settings["guard_url"] = ctx.get_config("guard_url", client.DEFAULT_URL)
    state["gated"] = re.compile(ctx.get_config("gated_tools", DEFAULT_GATED), re.IGNORECASE)
    for schema, handler in (
        (schemas.GUARDED_FETCH, tools.guarded_fetch),
        (schemas.CHECK_PAYMENT, tools.check_payment),
        (schemas.SPEND_STATUS, tools.spend_status),
        (schemas.SPEND_AUDIT, tools.spend_audit),
    ):
        ctx.register_tool(name=schema["name"], toolset=TOOLSET, schema=schema, handler=handler)
    ctx.register_hook("pre_tool_call", pre_tool_call)
