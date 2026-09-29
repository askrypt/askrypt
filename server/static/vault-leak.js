// "Is this password in a known breach?" — the Have I Been Pwned range check.
//
// The browser port of `core/src/pwned.rs`, and like the password generator it
// is *not* part of the vault format. k-anonymity: only the first five hex
// characters of the secret's SHA-1 leave the page (`GET /range/{prefix}`), and
// the match against the returned suffixes happens here. `Add-Padding` makes
// the server pad the list with count-0 rows, so the response size says nothing
// either.
//
// Held to the same contract as its neighbours — no DOM, no globals, nothing
// persisted — so `scripts/vault-js-parity.mjs` can run it under Node. The one
// network call takes its `fetch` as a parameter for the same reason.

/** The public range endpoint; the prefix is appended. The `/open` page's CSP
 *  names this host in `connect-src` (`CSP_OPEN`), and nothing else does. */
export const RANGE_URL = "https://api.pwnedpasswords.com/range/";

const PREFIX_LEN = 5;

/** The SHA-1 of `secret` as uppercase hex, split into the five-character prefix
 *  that is sent and the 35-character suffix that is looked for. */
export async function rangeQuery(secret) {
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-1", new TextEncoder().encode(secret)));
  const hex = Array.from(digest, (b) => b.toString(16).padStart(2, "0"))
    .join("").toUpperCase();
  return { prefix: hex.slice(0, PREFIX_LEN), suffix: hex.slice(PREFIX_LEN) };
}

/** How many breaches the range response lists for `suffix`; 0 when absent.
 *  Padding rows carry a count of 0 and so read as absent. */
export function countInRange(body, suffix) {
  const wanted = suffix.toUpperCase();
  for (const line of body.split("\n")) {
    const [candidate, count] = line.trim().split(":");
    if (candidate && candidate.toUpperCase() === wanted) {
      const n = Number.parseInt(count, 10);
      return Number.isFinite(n) ? n : 0;
    }
  }
  return 0;
}

/** How many known breaches contain `secret`. Rejects on a transport or server
 *  failure — never on "not found", which is 0. */
export async function breachCount(secret, fetchFn = fetch) {
  const { prefix, suffix } = await rangeQuery(secret);
  const response = await fetchFn(RANGE_URL + prefix, {
    headers: { "Add-Padding": "true" },
    credentials: "omit",
    referrerPolicy: "no-referrer",
    cache: "no-store",
  });
  if (!response.ok) throw new Error(`range lookup answered ${response.status}`);
  return countInRange(await response.text(), suffix);
}
