// HTTP transport for the guard service. JSON in, JSON out.
//
//   GET  /healthz     liveness, no auth
//   GET  /v1/status   mandate, caps and spend so far
//   GET  /v1/audit    recent payer events (?limit=)
//   POST /v1/check    {url}: the verdict a payment would get; nothing is spent
//   POST /v1/pay      {url, method?, headers?, body?, grant?, grantSignature?}
//
// Every /v1 route needs `Authorization: Bearer <token>`. This process can move
// the agent's money, so there is no unauthenticated mode, and the default bind
// address is loopback.

import { createServer } from "node:http";
import { timingSafeEqual, createHash } from "node:crypto";

/** Largest request body accepted, in bytes. */
export const MAX_REQUEST_BYTES = 1_048_576;

const digest = (s) => createHash("sha256").update(String(s)).digest();

function authorized(req, token) {
  const h = req.headers.authorization ?? "";
  const m = /^Bearer (.+)$/.exec(h);
  if (!m) return false;
  return timingSafeEqual(digest(m[1]), digest(token));
}

function send(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
  });
  res.end(body);
}

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

async function readJson(req) {
  const type = req.headers["content-type"] ?? "";
  if (!type.startsWith("application/json")) throw new HttpError(415, "Content-Type must be application/json");
  let size = 0;
  const chunks = [];
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_REQUEST_BYTES) throw new HttpError(413, "request body too large");
    chunks.push(chunk);
  }
  try {
    const v = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
    if (typeof v !== "object" || v === null || Array.isArray(v)) throw new Error("not an object");
    return v;
  } catch (e) {
    throw new HttpError(400, `invalid JSON body: ${e.message}`);
  }
}

/**
 * @param {object} service  from createGuardService()
 * @param {object} opts
 * @param {string} opts.token  bearer token every /v1 request must carry
 */
export function createHttpServer(service, { token } = {}) {
  if (!token || String(token).length < 16)
    throw new Error("an HTTP bearer token of at least 16 characters is required");

  async function handle(req, res) {
    const url = new URL(req.url, "http://localhost");
    const route = `${req.method} ${url.pathname}`;

    if (route === "GET /healthz") return send(res, 200, { ok: true });
    if (!url.pathname.startsWith("/v1/")) throw new HttpError(404, "not found");
    if (!authorized(req, token)) throw new HttpError(401, "missing or wrong bearer token");

    switch (route) {
      case "GET /v1/status":
        return send(res, 200, service.status());
      case "GET /v1/audit":
        return send(res, 200, service.audit({ limit: url.searchParams.get("limit") ?? 100 }));
      case "POST /v1/check":
        return send(res, 200, await service.checkPayment(await readJson(req)));
      case "POST /v1/pay":
        return send(res, 200, await service.pay(await readJson(req)));
      default:
        throw new HttpError(404, "not found");
    }
  }

  return createServer((req, res) => {
    handle(req, res).catch((e) => {
      if (res.headersSent) return res.end();
      // Service errors come from the caller's input (a bad URL, a malformed Grant)
      // or from an unreachable resource. Both name their cause to the caller.
      const status = e instanceof HttpError ? e.status : 400;
      send(res, status, { error: e.message });
    });
  });
}
