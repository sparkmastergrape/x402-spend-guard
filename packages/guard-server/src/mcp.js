// MCP transport for the guard service. Four tools, one per service operation.
//
// A refusal or an escalation is a normal tool result, not a tool error: the
// agent must read the verdict and stop, or ask a human, and an error result
// invites a retry. Only bad input and unreachable resources are tool errors.

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const result = (obj) => ({
  content: [{ type: "text", text: JSON.stringify(obj, null, 2) }],
});

const failure = (e) => ({
  content: [{ type: "text", text: `error: ${e.message}` }],
  isError: true,
});

const guarded = (fn) => async (args) => {
  try {
    return result(await fn(args ?? {}));
  } catch (e) {
    return failure(e);
  }
};

/**
 * @param {object} service  from createGuardService()
 * @param {object} [info]   MCP server name and version
 */
export function createMcpServer(service, info = { name: "x402-spend-guard", version: "0.1.0" }) {
  const server = new McpServer(info);

  server.registerTool(
    "guarded_fetch",
    {
      title: "Fetch a URL, paying over x402 only if the spend mandate allows",
      description:
        "Fetches the URL. If it answers 402 Payment Required, the Guard checks the price, payee, asset and network against the signed spend mandate. " +
        "outcome=paid: the payment settled and `body` holds the resource. " +
        "outcome=refused: do not retry, and do not try another way to pay. " +
        "outcome=requires_confirmation: a human must sign `grantToSign` on the approval device; call again with `grant` and `grantSignature`.",
      inputSchema: {
        url: z.string().url().describe("http or https URL of the resource"),
        method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"]).optional(),
        headers: z.record(z.string(), z.string()).optional(),
        body: z.string().optional().describe("request body, for methods other than GET and HEAD"),
        grant: z.any().optional().describe("the signed-off Grant: the `grantToSign` object from an earlier escalation"),
        grantSignature: z.string().optional().describe("the approver's signature over `grant`"),
      },
    },
    guarded((a) => service.pay(a)),
  );

  server.registerTool(
    "check_payment",
    {
      title: "Check what the Guard would decide for a URL, without paying",
      description:
        "Requests the URL once without payment and evaluates its 402 challenge. Reserves, signs and records nothing. outcome=checked carries the verdict: ALLOW, ESCALATE or DENY.",
      inputSchema: {
        url: z.string().url(),
        method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"]).optional(),
        headers: z.record(z.string(), z.string()).optional(),
      },
      annotations: { readOnlyHint: true },
    },
    guarded((a) => service.checkPayment(a)),
  );

  server.registerTool(
    "spend_status",
    {
      title: "Show the spend mandate, its caps and the spend so far",
      description: "Returns the mandate in words, its caps in base units, and the spend total, window spend and pending reservations.",
      inputSchema: {},
      annotations: { readOnlyHint: true },
    },
    guarded(() => service.status()),
  );

  server.registerTool(
    "spend_audit",
    {
      title: "List recent payment decisions",
      description: "Returns the most recent payer events: every verdict, payment and failure, newest last.",
      inputSchema: { limit: z.number().int().min(1).max(1000).optional() },
      annotations: { readOnlyHint: true },
    },
    guarded((a) => service.audit(a)),
  );

  return server;
}
