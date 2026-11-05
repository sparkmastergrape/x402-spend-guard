_URL = {"type": "string", "description": "The http or https URL of the resource."}

GUARDED_FETCH = {
    "name": "guarded_fetch",
    "description": (
        "Fetch a URL. Pay over x402 only if the guard allows the payment under the signed mandate. "
        "If the outcome is refused, stop. Do not retry, and do not look for another way to pay. "
        "If the outcome is requires_confirmation, ask a human to sign grantToSign, then call again with "
        "grant and grantSignature."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "url": _URL,
            "method": {"type": "string", "description": "HTTP method. The default is GET."},
            "headers": {"type": "object", "description": "HTTP headers for the request."},
            "body": {"type": "string", "description": "Request body. The guard ignores it for GET and HEAD."},
            "grant": {"type": "object", "description": "The grant that a human signed."},
            "grantSignature": {"type": "string", "description": "The human signature of the grant."},
        },
        "required": ["url"],
    },
}

CHECK_PAYMENT = {
    "name": "check_payment",
    "description": (
        "Show the verdict that a payment for a URL would get now. "
        "This sends a request to the URL. It reserves, signs and records nothing."
    ),
    "parameters": {
        "type": "object",
        "properties": {"url": _URL},
        "required": ["url"],
    },
}

SPEND_STATUS = {
    "name": "spend_status",
    "description": "Show the mandate, its caps and the spend so far.",
    "parameters": {"type": "object", "properties": {}},
}

SPEND_AUDIT = {
    "name": "spend_audit",
    "description": "List recent payer events.",
    "parameters": {
        "type": "object",
        "properties": {
            "limit": {"type": "integer", "description": "Maximum number of events to show."},
        },
    },
}
