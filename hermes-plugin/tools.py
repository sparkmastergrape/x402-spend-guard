"""Tool handlers. Each handler returns a JSON string and never raises."""

import json

from . import client

PAY_FIELDS = ("url", "method", "headers", "body", "grant", "grantSignature")


def _run(action):
    try:
        return json.dumps(action())
    except Exception as error:  # A handler must return JSON for every error.
        return json.dumps({"error": str(error)})


def guarded_fetch(args, **kwargs):
    return _run(lambda: client.pay({k: args[k] for k in PAY_FIELDS if args.get(k) is not None}))


def check_payment(args, **kwargs):
    return _run(lambda: client.check(args.get("url")))


def spend_status(args, **kwargs):
    return _run(client.status)


def spend_audit(args, **kwargs):
    return _run(lambda: client.audit(args.get("limit")))
