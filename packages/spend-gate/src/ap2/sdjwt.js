// The SD-JWT delegation chain AP2 v0.2 uses for mandates
// (draft-gco-oauth-delegate-sd-jwt-00, as implemented by the AP2 reference SDK
// at google-agentic-commerce/AP2 v0.2.0, code/sdk/python/ap2/sdk/sdjwt/).
//
// A chain is compact SD-JWTs joined by `~~`:
//   root   signed by the issuer (the user's key). Its delegate payload carries
//          `cnf.jwk`, the key of the next holder (the agent).
//   hop i  a KB-SD-JWT signed by the key in hop i-1's `cnf.jwk`. It binds to
//          hop i-1 by `sd_hash` (hash of hop i-1 with its disclosures) or
//          `issuer_jwt_hash` (hash of hop i-1's issuer JWT only).
//          typ `kb+sd-jwt+kb` = intermediate (carries cnf), `kb+sd-jwt` = terminal.
//
// Only ES256 is accepted. Every check fails closed: a token that cannot be
// fully verified throws, and nothing is returned from it.

import { webcrypto, createHash, randomBytes } from "node:crypto";

const subtle = webcrypto.subtle;
const ES256 = { name: "ECDSA", namedCurve: "P-256" };
const SIGN = { name: "ECDSA", hash: "SHA-256" };

export const TYP_TERMINAL = ["kb+sd-jwt", "kb-sd-jwt"];
export const TYP_INTERMEDIATE = ["kb+sd-jwt+kb", "kb-sd-jwt+kb"];
const HASHES = { "sha-256": "sha256", "sha-384": "sha384", "sha-512": "sha512" };
const DEFAULT_SKEW_SECONDS = 300;

export const b64url = (buf) => Buffer.from(buf).toString("base64url");
const fromB64url = (s) => Buffer.from(s, "base64url");
const jsonB64 = (obj) => b64url(Buffer.from(JSON.stringify(obj), "utf8"));

function decodeJson(segment, what) {
  try {
    return JSON.parse(fromB64url(segment).toString("utf8"));
  } catch (e) {
    throw new Error(`cannot parse ${what}: ${e.message}`);
  }
}

/** base64url(hash(ascii(value))) with the token's `_sd_alg` (sha-256 when absent). */
export function hashAscii(value, sdAlg) {
  const alg = HASHES[sdAlg ?? "sha-256"];
  if (!alg) throw new Error(`unsupported _sd_alg: ${sdAlg}`);
  return b64url(createHash(alg).update(Buffer.from(value, "ascii")).digest());
}

/** Parse one compact SD-JWT: `issuerJwt~disc1~…~discN~[kbJwt]`. */
export function parseToken(token) {
  if (typeof token !== "string" || !token.includes("~")) throw new Error("malformed SD-JWT: no `~`");
  if (token.startsWith("~")) throw new Error("malformed SD-JWT: empty issuer JWT");
  const parts = token.split("~");
  const issuerJwt = parts[0];
  const disclosures = parts.slice(1, -1);
  if (disclosures.some((d) => !d)) throw new Error("malformed SD-JWT: empty disclosure");
  const last = parts[parts.length - 1];
  const kbJwt = token.endsWith("~") ? null : last;
  if (kbJwt !== null && kbJwt.split(".").length !== 3) throw new Error("malformed KB-JWT");
  const jwtParts = issuerJwt.split(".");
  if (jwtParts.length !== 3) throw new Error("malformed SD-JWT: issuer JWT needs 3 parts");
  const header = decodeJson(jwtParts[0], "JWT header");
  const payload = decodeJson(jwtParts[1], "JWT payload");
  if (typeof header !== "object" || typeof payload !== "object" || !header || !payload)
    throw new Error("JWT header and payload must be objects");
  const sdJwt = disclosures.length ? `${issuerJwt}~${disclosures.join("~")}~` : `${issuerJwt}~`;
  return { issuerJwt, disclosures, kbJwt, header, payload, sdJwt, sdAlg: payload._sd_alg };
}

/** Split a `~~`-joined chain, restoring the `~` the join consumed (as the reference SDK does). */
export function splitChain(chain) {
  const segments = chain.split("~~");
  return segments.map((s, i) => {
    if (i === segments.length - 1 || s.endsWith("~")) return s;
    const tail = s.split("~").pop();
    return tail.split(".").length === 3 && s.includes("~") ? s : `${s}~`;
  });
}

/** Join tokens into a chain. */
export const joinChain = (tokens) => tokens.map((t) => (t.endsWith("~") ? t.slice(0, -1) : t)).join("~~") + "~";

async function importJwk(jwk, usage) {
  if (jwk?.kty !== "EC" || jwk?.crv !== "P-256") throw new Error("only EC P-256 keys (ES256) are accepted");
  const { kty, crv, x, y, d } = jwk;
  return subtle.importKey("jwk", usage === "sign" ? { kty, crv, x, y, d } : { kty, crv, x, y }, ES256, false, [usage]);
}

export async function verifyJws(compactJwt, jwk) {
  const [h, p, s] = compactJwt.split(".");
  const header = decodeJson(h, "JWT header");
  if (header.alg !== "ES256") throw new Error(`JWT alg must be ES256, got ${header.alg}`);
  const key = await importJwk(jwk, "verify");
  const ok = await subtle.verify(SIGN, key, fromB64url(s), Buffer.from(`${h}.${p}`, "ascii"));
  if (!ok) throw new Error("JWT signature does not verify");
}

export async function signJws(header, payload, privateJwk) {
  const h = jsonB64({ alg: "ES256", ...header });
  const p = jsonB64(payload);
  const key = await importJwk(privateJwk, "sign");
  const sig = await subtle.sign(SIGN, key, Buffer.from(`${h}.${p}`, "ascii"));
  return `${h}.${p}.${b64url(sig)}`;
}

/**
 * Replace SD-JWT digests with their disclosed values (RFC 9901 §7.1):
 * `_sd` arrays in objects and `{"...": digest}` elements in arrays. A digest
 * with no disclosure stays undisclosed. A disclosure used twice, or never
 * referenced, is an error.
 */
export function resolveDisclosures(payload, token) {
  const byDigest = new Map();
  for (const d of token.disclosures) {
    const digest = hashAscii(d, token.sdAlg);
    if (byDigest.has(digest)) throw new Error("duplicate disclosure");
    const arr = decodeJson(d, "disclosure");
    if (!Array.isArray(arr) || (arr.length !== 2 && arr.length !== 3)) throw new Error("malformed disclosure");
    byDigest.set(digest, arr);
  }
  const used = new Set();
  const take = (digest) => {
    const arr = byDigest.get(digest);
    if (!arr) return undefined;
    if (used.has(digest)) throw new Error("a disclosure is referenced twice");
    used.add(digest);
    return arr;
  };

  const walk = (node) => {
    if (Array.isArray(node)) {
      const out = [];
      for (const el of node) {
        if (el && typeof el === "object" && !Array.isArray(el) && Object.keys(el).length === 1 && "..." in el) {
          const arr = take(el["..."]);
          if (arr) {
            if (arr.length !== 2) throw new Error("array element disclosure must have 2 entries");
            out.push(walk(arr[1]));
          }
        } else if (typeof el === "string" && byDigest.has(el)) {
          // The reference SDK also accepts a bare digest string inside delegate_payload.
          const arr = take(el);
          out.push(walk(arr.length === 2 ? arr[1] : arr[2]));
        } else {
          out.push(walk(el));
        }
      }
      return out;
    }
    if (node && typeof node === "object") {
      const out = {};
      for (const [k, v] of Object.entries(node)) if (k !== "_sd") out[k] = walk(v);
      for (const digest of node._sd ?? []) {
        const arr = take(digest);
        if (!arr) continue;
        if (arr.length !== 3) throw new Error("object property disclosure must have 3 entries");
        if (arr[1] in out || arr[1] === "_sd" || arr[1] === "...") throw new Error(`disclosed claim ${arr[1]} collides`);
        out[arr[1]] = walk(arr[2]);
      }
      return out;
    }
    return node;
  };

  const resolved = walk(payload);
  if (used.size !== byDigest.size) throw new Error("a disclosure is not referenced by the token");
  delete resolved._sd_alg;
  return resolved;
}

/** The effective payload items of a verified hop: its `delegate_payload` objects. */
function delegateItems(payload) {
  const dp = payload.delegate_payload;
  return Array.isArray(dp) ? dp.filter((x) => x && typeof x === "object" && !Array.isArray(x)) : [];
}

function cnfJwk(payload, items) {
  for (const it of items) if (it.cnf?.jwk) return it.cnf.jwk;
  return payload.cnf?.jwk ?? null;
}

function checkTimes(objs, index, now, skew) {
  for (const p of objs) {
    if (p.exp !== undefined) {
      if (typeof p.exp !== "number") throw new Error(`token ${index}: exp is not a number`);
      if (now > p.exp + skew) throw new Error(`token ${index} expired at ${p.exp}`);
    }
    if (p.iat !== undefined) {
      if (typeof p.iat !== "number") throw new Error(`token ${index}: iat is not a number`);
      if (p.iat > now + skew) throw new Error(`token ${index}: iat ${p.iat} is in the future`);
    }
  }
}

/**
 * Verify a whole chain and return each hop's effective payload items.
 *
 * @param {string} chain             `~~`-joined compact chain (or one token)
 * @param {object} rootJwk           the issuer's public key (EC P-256 JWK)
 * @param {object} [o]
 * @param {string} [o.aud]           required `aud` of the terminal hop
 * @param {string} [o.nonce]         required `nonce` of the terminal hop
 * @param {number} [o.now]           unix seconds
 * @param {number} [o.skewSeconds]
 * @returns {Promise<{hops: Array<{header, payload, items}>}>}
 */
export async function verifyChain(chain, rootJwk, { aud, nonce, now = Math.floor(Date.now() / 1000), skewSeconds = DEFAULT_SKEW_SECONDS } = {}) {
  const tokens = splitChain(chain).map(parseToken);
  const hops = [];
  let prevToken = null;
  let prevKey = rootJwk;

  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    const last = i === tokens.length - 1;
    if (t.kbJwt) throw new Error(`token ${i}: a trailing KB-JWT is not used in AP2 chains`);

    if (i > 0) {
      const typ = t.header.typ;
      if (!TYP_TERMINAL.includes(typ) && !TYP_INTERMEDIATE.includes(typ))
        throw new Error(`token ${i}: unexpected typ ${typ}`);
      if (!prevKey) throw new Error(`token ${i}: the previous hop has no cnf.jwk`);
    }
    await verifyJws(t.issuerJwt, prevKey);
    const payload = resolveDisclosures(t.payload, t);
    const items = delegateItems(payload);

    if (i > 0) {
      const hasSd = "sd_hash" in payload;
      const hasIss = "issuer_jwt_hash" in payload;
      if (hasSd === hasIss) throw new Error(`token ${i}: needs exactly one of sd_hash and issuer_jwt_hash`);
      const want = hasSd ? hashAscii(prevToken.sdJwt, prevToken.sdAlg) : hashAscii(prevToken.issuerJwt, prevToken.sdAlg);
      if ((hasSd ? payload.sd_hash : payload.issuer_jwt_hash) !== want) throw new Error(`token ${i}: binding hash mismatch`);

      const terminal = TYP_TERMINAL.includes(t.header.typ);
      const hasCnf = items.some((x) => x.cnf && typeof x.cnf === "object");
      if (terminal && hasCnf) throw new Error(`token ${i}: a terminal hop must not carry cnf`);
      if (!terminal && !hasCnf) throw new Error(`token ${i}: an intermediate hop needs cnf`);
      if (terminal) {
        if (typeof payload.iat !== "number") throw new Error(`token ${i}: iat is required`);
        if (last && aud !== undefined && payload.aud !== aud) throw new Error(`token ${i}: aud mismatch`);
        if (last && nonce !== undefined && payload.nonce !== nonce) throw new Error(`token ${i}: nonce mismatch`);
      }
      if (!last && items.length !== 1) throw new Error(`token ${i}: expected exactly 1 delegate item`);
    } else if (!last && items.length !== 1) {
      throw new Error("token 0: expected exactly 1 delegate item");
    }

    checkTimes([payload, ...items], i, now, skewSeconds);
    hops.push({ header: t.header, payload, items });
    prevToken = t;
    prevKey = cnfJwk(payload, items);
  }
  return { hops };
}

function discloseItem(item) {
  const disclosure = jsonB64([b64url(randomBytes(16)), item]);
  return { disclosure, ref: { "...": hashAscii(disclosure, "sha-256") } };
}

/** Issue a root SD-JWT whose delegate payload is `item`. */
export async function issueRoot(item, issuerPrivateJwk, { typ = "sd-jwt", kid } = {}) {
  const { disclosure, ref } = discloseItem(item);
  const jwt = await signJws({ typ, ...(kid ? { kid } : {}) }, { delegate_payload: [ref], _sd_alg: "sha-256" }, issuerPrivateJwk);
  return `${jwt}~${disclosure}~`;
}

/**
 * Append one key-bound hop to `chain`, signed by `holderPrivateJwk` (the key
 * in the previous hop's cnf). A terminal hop carries no cnf.
 */
export async function appendHop(chain, item, holderPrivateJwk, { aud, nonce, iat = Math.floor(Date.now() / 1000), hashMode = "sd_hash" } = {}) {
  if (!aud || !nonce) throw new Error("aud and nonce are required for a key-bound hop");
  const segments = splitChain(chain);
  const prev = parseToken(segments[segments.length - 1]);
  const terminal = !item.cnf;
  const binding =
    hashMode === "sd_hash" ? { sd_hash: hashAscii(prev.sdJwt, prev.sdAlg) } : { issuer_jwt_hash: hashAscii(prev.issuerJwt, prev.sdAlg) };
  const { disclosure, ref } = discloseItem(item);
  const jwt = await signJws(
    { typ: terminal ? TYP_TERMINAL[0] : TYP_INTERMEDIATE[0] },
    { delegate_payload: [ref], iat, aud, nonce, ...binding, _sd_alg: "sha-256" },
    holderPrivateJwk,
  );
  return joinChain([...segments, `${jwt}~${disclosure}~`]);
}

/** A fresh EC P-256 key pair as JWKs. */
export async function generateEs256Jwk() {
  const { privateKey, publicKey } = await subtle.generateKey(ES256, true, ["sign", "verify"]);
  return { privateJwk: await subtle.exportKey("jwk", privateKey), publicJwk: await subtle.exportKey("jwk", publicKey) };
}
