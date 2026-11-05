// The approver: a Ledger device that signs EIP-712, wrapped so the rest of the
// system never knows whether it is talking to real hardware or the emulator.
//
// Extracted from src/spike/gate-a-speculos.mjs once the same signing path was
// needed twice (a Mandate at the start, a Grant at every escalation). Every
// workaround in here was paid for once already and is cited to the DX log; none
// of it is speculative.
//
// For a REAL device the screen driving below is what a human does with their
// thumbs, so `autoApprove` is emulator-only and says so loudly.

import "reflect-metadata";
import { createRequire } from "node:module";

// The Ledger packages' published ESM builds contain a bare
// directory import ("./src") that Node refuses with ERR_UNSUPPORTED_DIR_IMPORT.
// Their CJS builds are fine, so load those.
const require = createRequire(import.meta.url);
const {
  ConsoleLogger,
  DeviceManagementKitBuilder,
  DeviceActionStatus,
  DeviceModelId,
  LogLevel,
} = require("@ledgerhq/device-management-kit");
const { speculosTransportFactory } = require("@ledgerhq/device-transport-kit-speculos");
const { SignerEthBuilder } = require("@ledgerhq/device-signer-kit-ethereum");

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export const DEFAULT_ETH_PATH = "44'/60'/0'/0/0";

/**
 * @param {object} [opts]
 * @param {string} [opts.url]        Speculos HTTP API
 * @param {string} [opts.path]       BIP-32 derivation path
 * @param {boolean} [opts.autoApprove] press the buttons for the human (EMULATOR ONLY)
 * @param {(s:string)=>void} [opts.onScreen] every distinct screen, as the device shows it
 */
export async function connectSpeculosApprover({
  url = process.env.SPECULOS_URL ?? "http://localhost:5010",
  path = DEFAULT_ETH_PATH,
  autoApprove = true,
  onScreen = () => {},
  log = () => {},
} = {}) {
  // Redirectable, so a caller can capture the screens of one signature on its
  // own without unpicking the subscription.
  let screenSink = onScreen;
  // ---------------------------------------------------- screen primitives
  const readScreen = async () => {
    const r = await fetch(`${url}/events?currentscreenonly=true`);
    const { events } = await r.json();
    return (events ?? []).map((e) => e.text).join(" | ");
  };

  const press = (key) =>
    fetch(`${url}/button/${key}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "press-and-release" }),
    });

  // Speculos' own POST /automation is deliberately NOT used: its two-button
  // action must be expressed as four button events, and the app reads the lone
  // left-press as "previous", walking the review backwards into "Reject
  // message". POST /button/both is handled natively.
  const clearAutomation = () =>
    fetch(`${url}/automation`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ version: 1, rules: [] }),
    }).catch(() => {});

  /** Press right until `target` matches. Never presses "both" — see resetToHome. */
  async function goto(target, { maxPresses = 12, label = String(target) } = {}) {
    for (let i = 0; i <= maxPresses; i++) {
      const text = await readScreen();
      if (target.test(text)) return text;
      await press("right");
      await sleep(200);
    }
    throw new Error(`could not reach ${label}; last screen: ${await readScreen()}`);
  }

  async function resetToHome({ maxSteps = 30 } = {}) {
    for (let i = 0; i < maxSteps; i++) {
      const text = await readScreen();
      if (/app is ready/i.test(text)) return text;
      if (/reject|cancel|decline/i.test(text) || /^back$/i.test(text.trim())) {
        await press("both");
      } else if (/app settings|app info|quit app/i.test(text)) {
        // The home carousel does not wrap on "right" — "Quit app" is last, and
        // "both" there kills the app and the session with it. Walk left.
        await press("left");
      } else {
        await press("right");
      }
      await sleep(200);
    }
    throw new Error(`could not reach home; stuck at: ${await readScreen()}`);
  }

  /**
   * Without Settings -> "Raw messages" the app refuses to sign
   * unregistered EIP-712 at all, failing with an opaque `6a80 Invalid data`.
   * Enabled here rather than assumed, so a cold container works.
   */
  async function ensureRawMessages() {
    await resetToHome();
    await goto(/app settings/i, { label: "App settings" });
    await press("both");
    await sleep(250);
    const row = await goto(/raw messages/i, { label: "Raw messages" });
    if (/disabled/i.test(row)) {
      await press("both");
      await sleep(250);
      if (/disabled/i.test(await readScreen())) throw new Error("Raw messages toggle did not take");
      log("Raw messages -> Enabled");
    }
    await resetToHome();
  }

  /**
   * What to do with one screen: advance, or confirm.
   *
   * THIS MUST NOT MATCH ON FIELD CONTENT. An earlier version tested the whole
   * screen text for /approve|accept|.../ and pressed both buttons on a match.
   * That worked until a struct appeared with a field named `approver` — the
   * label contains "approve", so a data screen was read as an approval button,
   * "both" meant "skip the message" rather than "yes", and the review stalled
   * until the signer timed out 120 seconds later. The symptom (a timeout) was
   * nowhere near the cause (a substring match), which is why the screen at the
   * moment of failure is now attached to the error.
   *
   * A field screen is `name | value`, and a field screen is NEVER a
   * confirmation. The device's own prompts are matched anchored, not anywhere.
   */
  function decide(text) {
    const t = text.toLowerCase().trim();

    // The blind-signing warning is a prompt that happens to carry a separator.
    if (/blind signing ahead|accept risk/.test(t)) return "confirm";

    // Never confirm a screen that would cancel the signature or kill the app.
    if (/reject|cancel|decline|quit/.test(t)) return "advance";

    // `name | value` — data, not a decision. Keep reading.
    if (text.includes(" | ")) return "advance";

    if (/^(sign message|approve|accept|confirm|hold to sign|allow)\b/.test(t)) return "confirm";
    return "advance";
  }

  /**
   * Walk a review to the end, confirming it.
   *
   * `ready()` gates the first press: pressing while the signer is still
   * exchanging APDUs corrupts it and surfaces as an empty GeneralDmkError
   *. A reject/quit screen is never confirmed — one cancels the
   * signature under test, the other kills the session.
   */
  async function walkReview(done, ready, { maxSteps = 400, delayMs = 120 } = {}) {
    let last = "";
    for (let i = 0; i < maxSteps && !done(); i++) {
      if (!ready()) {
        await sleep(80);
        continue;
      }
      const text = await readScreen();
      if (text && text !== last) {
        screenSink(text);
        last = text;
      }
      await press(decide(text) === "confirm" ? "both" : "right");
      await sleep(delayMs);
    }
  }

  // ---------------------------------------------------- dmk plumbing
  let wantsInteraction = false;
  const steps = [];

  function runAction(label, { observable }, { timeoutMs = 120000 } = {}) {
    return new Promise((res, rej) => {
      const timer = setTimeout(() => rej(new Error(`${label} timed out`)), timeoutMs);
      const settle = (fn) => (v) => {
        clearTimeout(timer);
        fn(v);
      };
      const ok = settle(res);
      const no = settle(rej);
      observable.subscribe({
        next: (s) => {
          const iv = s.intermediateValue ?? {};
          if (iv.step && !steps.includes(iv.step)) steps.push(iv.step);
          if (iv.requiredUserInteraction && iv.requiredUserInteraction !== "none")
            wantsInteraction = true;
          if (s.status === DeviceActionStatus.Completed) ok(s.output);
          if (s.status === DeviceActionStatus.Error)
            no(Object.assign(new Error(`${label} errored`), { detail: s.error }));
          if (s.status === DeviceActionStatus.Stopped) no(new Error(`${label} stopped`));
        },
        error: no,
      });
    });
  }

  await clearAutomation();
  await ensureRawMessages();

  const dmk = new DeviceManagementKitBuilder()
    .addLogger(new ConsoleLogger(LogLevel.Warning))
    .addTransport(speculosTransportFactory(url, false, DeviceModelId.NANO_X))
    .build();

  const device = await new Promise((resolve, reject) => {
    let sub = null;
    let got = false;
    const timer = setTimeout(() => reject(new Error("no device discovered in 15s")), 15000);
    // This transport emits synchronously, so `sub` may still be
    // undefined inside next(). Unsubscribe out of band.
    sub = dmk.startDiscovering({}).subscribe({
      next: (d) => {
        if (got) return;
        got = true;
        clearTimeout(timer);
        resolve(d);
      },
      error: (e) => {
        clearTimeout(timer);
        reject(e);
      },
    });
    queueMicrotask(() => sub?.unsubscribe());
  });

  const sessionId = await dmk.connect({ device });
  const signer = new SignerEthBuilder({ dmk, sessionId }).build();
  const { address } = await runAction("getAddress", signer.getAddress(path, { checkOnDevice: false }));

  /**
   * Sign EIP-712 typed data on the device. Returns a packed 65-byte signature,
   * which is what viem and ethers both expect.
   *
   * @param {object} payload  bigint-free typed data (toSignerPayload / toGrantSignerPayload)
   */
  async function signTypedData(payload) {
    wantsInteraction = false;
    let settled = false;
    const watching = autoApprove
      ? walkReview(
          () => settled,
          () => wantsInteraction,
        )
      : Promise.resolve();
    try {
      const sig = await runAction("signTypedData", signer.signTypedData(path, payload)).finally(
        () => {
          settled = true;
        },
      );
      await watching;
      return `${sig.r}${sig.s.slice(2)}${sig.v.toString(16).padStart(2, "0")}`;
    } catch (e) {
      settled = true;
      await watching.catch(() => {});
      // Capture the evidence BEFORE clearing the prompt. The screen at the
      // moment of failure is the whole diagnosis, and resetToHome destroys it.
      e.screenAtFailure = await readScreen().catch(() => "(unreadable)");
      e.stepsSeen = [...steps];
      e.wantedInteraction = wantsInteraction;
      // An aborted signing wedges the app, and the NEXT call fails
      // with a misleading 6901. Clear the prompt so one failure is not two.
      await resetToHome().catch(() => {});
      throw e;
    }
  }

  return {
    address,
    /** Capture the screens of the next signature into `fn`; returns them after. */
    captureScreens(fn) {
      screenSink = fn;
      return () => {
        screenSink = onScreen;
      };
    },
    signTypedData,
    readScreen,
    resetToHome,
    steps,
    close: async () => {
      await clearAutomation();
      await dmk.disconnect({ sessionId }).catch(() => {});
    },
  };
}
