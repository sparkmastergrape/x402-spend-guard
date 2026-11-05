"""HTTP client for a local guard-server. It uses the Python standard library only."""

import json
import urllib.error
import urllib.parse
import urllib.request

TIMEOUT_SECONDS = 10
DEFAULT_URL = "http://127.0.0.1:8402"

settings = {"guard_url": DEFAULT_URL}


class GuardError(Exception):
    """The guard did not give a usable answer."""


def _token():
    from agent.secret_scope import get_secret

    token = get_secret("GUARD_HTTP_TOKEN")
    if not token:
        raise GuardError("GUARD_HTTP_TOKEN is not set")
    return token


def _message(error):
    try:
        return "guard-server: " + str(json.loads(error.read().decode("utf-8"))["error"])
    except (OSError, ValueError, KeyError, TypeError):
        return "guard-server: HTTP " + str(error.code)


def _call(method, path, body=None):
    data = None if body is None else json.dumps(body).encode("utf-8")
    request = urllib.request.Request(settings["guard_url"].rstrip("/") + path, data=data, method=method)
    request.add_header("Authorization", "Bearer " + _token())
    if data is not None:
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            parsed = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        raise GuardError(_message(error)) from error
    except (OSError, ValueError) as error:
        raise GuardError("guard-server gave no usable answer: " + str(error)) from error
    return parsed


def _object(parsed):
    if not isinstance(parsed, dict):
        raise GuardError("guard-server sent an answer that is not a JSON object")
    return parsed


def check(url):
    return _object(_call("POST", "/v1/check", {"url": url}))


def pay(request):
    return _object(_call("POST", "/v1/pay", request))


def status():
    return _object(_call("GET", "/v1/status"))


def audit(limit=None):
    query = "" if limit is None else "?" + urllib.parse.urlencode({"limit": int(limit)})
    events = _call("GET", "/v1/audit" + query)
    if not isinstance(events, list):
        raise GuardError("guard-server sent an audit answer that is not a JSON list")
    return {"events": events}
