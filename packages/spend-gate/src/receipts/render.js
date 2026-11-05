// A standalone HTML view of receipt chains: one file, no build, no CDN, opens
// from disk. Judges have no time to install anything, and a demo that needs a
// dev server is a demo that fails on someone else's laptop.
//
// Unverified links are rendered differently from verified ones on purpose. A
// view that makes a merchant's claim look like on-chain proof is worse than no
// view at all.

const esc = (s) =>
  String(s ?? "").replace(
    /[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c],
  );

const EXPLORER = "https://explorer.testnet.xrplevm.org/tx/";

function renderLink(link, i) {
  const fields = Object.entries(link.fields)
    .filter(([, v]) => v !== undefined && v !== null)
    .map(([k, v]) => {
      const value =
        k === "txHash"
          ? `<a href="${EXPLORER}${esc(v)}" target="_blank" rel="noreferrer">${esc(v)}</a>`
          : `<span class="v">${esc(v)}</span>`;
      return `<div class="f"><span class="k">${esc(k)}</span>${value}</div>`;
    })
    .join("");

  return `
    <li class="link ${link.verified ? "ok" : "unverified"}">
      <div class="num">${i + 1}</div>
      <div class="body">
        <h3>${esc(link.title)}
          <span class="badge">${link.verified ? "verified" : "unverified"}</span>
        </h3>
        <p class="detail">${esc(link.detail)}</p>
        <p class="how">${esc(link.how)}</p>
        <div class="fields">${fields}</div>
      </div>
    </li>`;
}

/**
 * @param {Array<{title?: string, chain: object}>} receipts
 * @param {object} [meta]  anything worth stating at the top of the page
 */
export function renderReceiptsHtml(receipts, meta = {}) {
  const chains = receipts
    .map(
      ({ title, chain }, n) => `
      <section class="receipt">
        <h2>${esc(title ?? `Payment ${n + 1}`)}
          <span class="badge ${chain.verified ? "ok" : "unverified"}">
            ${chain.verified ? "every link verified" : `unverified: ${esc(chain.unverified.join(", "))}`}
          </span>
        </h2>
        <ol class="chain">${chain.links.map(renderLink).join("")}</ol>
      </section>`,
    )
    .join("");

  const metaRows = Object.entries(meta)
    .map(([k, v]) => `<div class="f"><span class="k">${esc(k)}</span><span class="v">${esc(v)}</span></div>`)
    .join("");

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Receipt chain — Mandate</title>
<style>
  :root {
    --bg: #0f1115; --panel: #171a21; --line: #272c37;
    --text: #e7e9ee; --dim: #9aa3b2;
    --ok: #4ade80; --warn: #fbbf24; --accent: #7dd3fc;
    --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  }
  @media (prefers-color-scheme: light) {
    :root:not([data-theme="dark"]) {
      --bg: #f7f8fa; --panel: #fff; --line: #e3e6ec;
      --text: #15181d; --dim: #5b6372; --accent: #0369a1;
    }
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 32px 16px 64px; background: var(--bg); color: var(--text);
    font: 15px/1.55 system-ui, -apple-system, Segoe UI, sans-serif;
  }
  .wrap { max-width: 860px; margin: 0 auto; }
  h1 { font-size: 24px; margin: 0 0 4px; letter-spacing: -0.01em; }
  .sub { color: var(--dim); margin: 0 0 24px; }
  .meta { background: var(--panel); border: 1px solid var(--line); border-radius: 10px;
          padding: 12px 14px; margin-bottom: 28px; }
  .receipt { margin-bottom: 36px; }
  h2 { font-size: 17px; margin: 0 0 12px; display: flex; gap: 10px; align-items: baseline;
       flex-wrap: wrap; }
  .badge { font: 600 11px/1 var(--mono); text-transform: uppercase; letter-spacing: .06em;
           padding: 4px 7px; border-radius: 999px; border: 1px solid var(--line);
           color: var(--dim); white-space: nowrap; }
  .badge.ok, .link.ok .badge { color: var(--ok); border-color: color-mix(in srgb, var(--ok) 40%, transparent); }
  .badge.unverified, .link.unverified .badge { color: var(--warn); border-color: color-mix(in srgb, var(--warn) 45%, transparent); }
  ol.chain { list-style: none; margin: 0; padding: 0; }
  .link { display: grid; grid-template-columns: 34px 1fr; gap: 12px; position: relative;
          padding-bottom: 14px; }
  .link:not(:last-child)::before {
    content: ""; position: absolute; left: 16px; top: 34px; bottom: 0; width: 2px;
    background: var(--line);
  }
  .num { width: 34px; height: 34px; border-radius: 50%; display: grid; place-items: center;
         background: var(--panel); border: 1px solid var(--line); font: 600 13px var(--mono);
         position: relative; z-index: 1; }
  .link.ok .num { border-color: color-mix(in srgb, var(--ok) 50%, transparent); }
  .link.unverified .num { border-color: color-mix(in srgb, var(--warn) 55%, transparent); }
  .body { background: var(--panel); border: 1px solid var(--line); border-radius: 10px;
          padding: 12px 14px; min-width: 0; }
  h3 { font-size: 15px; margin: 0 0 4px; display: flex; gap: 8px; align-items: baseline;
       flex-wrap: wrap; }
  .detail { margin: 0 0 6px; }
  .how { margin: 0 0 10px; color: var(--dim); font-size: 13px; font-style: italic; }
  .fields { display: grid; gap: 4px; }
  .f { display: grid; grid-template-columns: 170px 1fr; gap: 10px; font: 12.5px/1.5 var(--mono);
       min-width: 0; }
  .k { color: var(--dim); }
  .v, .f a { overflow-wrap: anywhere; }
  .f a { color: var(--accent); }
  @media (max-width: 620px) { .f { grid-template-columns: 1fr; gap: 0; } }
</style>
</head>
<body>
  <div class="wrap">
    <h1>Receipt chain</h1>
    <p class="sub">Every link from a human's thumb to a transaction. A link says
       <em>verified</em> only when it was checked — a signature recovered, a digest
       recomputed, a receipt read — never because something claimed success.</p>
    ${metaRows ? `<div class="meta">${metaRows}</div>` : ""}
    ${chains}
  </div>
</body>
</html>
`;
}
