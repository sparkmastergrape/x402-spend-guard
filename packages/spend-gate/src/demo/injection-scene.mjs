// The prompt-injection scene.
//
//   npm run injection            — play every scene
//   npm run injection -- --scene payee-swap
//   npm run injection -- --quiet — one line each, for a slide
//
// What the audience should take away is not "look, it blocked it". It is that
// the agent was fully compromised in every single scene — it read the document,
// believed it, and tried to do exactly what the attacker asked — and the money
// still did not move. Nothing here depends on a model being careful.

import { SCENES } from "./poisoned-docs.js";
import { runScene } from "./injection.js";
import { REFUSED, REQUIRES_CONFIRMATION } from "../payer/index.js";

const args = process.argv.slice(2);
const argOf = (name, fallback = null) => {
  const i = args.indexOf(name);
  return i === -1 ? fallback : args[i + 1];
};
const quiet = args.includes("--quiet");
const only = argOf("--scene");

const scenes = only ? SCENES.filter((s) => s.id === only) : SCENES;
if (scenes.length === 0) {
  console.error(`no such scene: ${only}\nhave: ${SCENES.map((s) => s.id).join(", ")}`);
  process.exit(2);
}

const indent = (text, prefix = "    │ ") =>
  text
    .trim()
    .split("\n")
    .map((l) => prefix + l.trim())
    .join("\n");

console.log("\n=== Prompt injection against a signed spend envelope ===\n");
console.log("The agent is assumed compromised in every scene. It reads the");
console.log("document, believes it, and does exactly what the attacker asked.");
console.log("The layer underneath is not a model, and has no instructions to");
console.log("override — only a struct a human signed on a device.\n");

let failures = 0;

for (const [i, scene] of scenes.entries()) {
  const r = await runScene(scene);
  const stopped = !r.paid && r.code === scene.expect;
  if (!stopped) failures++;

  if (quiet) {
    const mark = stopped ? "stopped" : "!! PAID / WRONG CODE";
    console.log(`${String(i + 1).padStart(2)}. ${scene.id.padEnd(22)} ${r.code ?? "-"}  ${mark}`);
    continue;
  }

  console.log(`\n── ${i + 1}. ${scene.title}  [${scene.id}]`);
  console.log(`   where: ${scene.where}`);
  console.log("\n   what the attacker wrote:");
  console.log(indent(scene.document));
  console.log(`\n   what the agent then did: ${scene.agentDoes}`);

  const how =
    r.outcome === REFUSED
      ? "refused outright — no human was asked, because no human answer makes it safe"
      : r.outcome === REQUIRES_CONFIRMATION
        ? "stopped and held for a human — nothing was paid (a Grant can lift a spend cap; an unknown payee or an expired mandate needs a new Mandate)"
        : `UNEXPECTED OUTCOME: ${r.outcome}`;
  console.log(`\n   verdict: ${r.decision} / ${r.code}`);
  console.log(`   ${how}`);
  console.log(`   ${r.message}`);
  console.log(
    `   payments settled at the merchant: ${r.merchantPaymentsAfter}` +
      ` (${r.honestPayments} honest, 0 from the attack)`,
  );
  console.log(`   why: ${scene.why}`);
  if (!stopped)
    console.log(`   !! expected ${scene.expect}, got ${r.code} — the scene no longer holds`);
}

console.log(`\n── ${scenes.length} scenes, ${scenes.length - failures} stopped, ${failures} not`);

console.log(`
Where this ends — the boundary, stated honestly:

  Injection into the agent's REASONING is contained. There is no phrasing of a
  document that widens the envelope, because the envelope is a signed struct and
  the verifier never reads prose.

  Compromise of the PROCESS holding the agent key is NOT contained by the
  Mandate. The agent's own software key signs each EIP-3009 authorization, so
  code running as the agent can sign one the Guard never approved. What bounds
  that is the token balance of the agent's wallet, and nothing else. That is why
  the wallet holds little, is funded deliberately, and is treated as the real
  loss limit.
  Revocation shortens the window; it does not close it.
`);

process.exit(failures === 0 ? 0 : 1);
