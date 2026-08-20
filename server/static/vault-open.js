// The `/open` page: pick a vault, answer the questions, browse and edit, save.
//
// All the crypto lives in `vault-format.js`; this file is the DOM around it.
// Nothing here writes to `localStorage`, `sessionStorage`, IndexedDB, the URL
// fragment or the console — a decrypted vault exists only in this page's
// variables and only until it locks.
//
// The CSP is `script-src 'self'` on this page as on every other, so there is
// no inline script anywhere and every value the markup hands over arrives as a
// `data-` attribute, the same way `captcha.js` and `google.js` take theirs.
// Rendered text always goes through `textContent`, never `innerHTML`: entry
// names come out of a file that anybody could have written.

import {
  CARD_KEYS, MAX_VAULT_BYTES, VaultError, blankEntry, createVault,
  decryptWithMaster, getQuestionsData, isCard, parseVault,
} from "./vault-format.js";

// How long the tab may sit in the background before the vault locks. The
// mobile app locks the instant it is backgrounded; a browser tab fires the
// same event when you merely switch tabs, and locking there would make it
// impossible to paste a password anywhere. The grace period is the
// compromise: a phone put down still locks promptly.
const HIDDEN_GRACE_MS = 60 * 1000;
// Idle timeout, matching `kInactivityTimeout` in app/lib/screens/auto_lock.dart.
const IDLE_MS = 3 * 60 * 1000;
// Matches `kClipboardClearTimeout` in app/lib/platform/secure_clipboard.dart.
const CLIPBOARD_MS = 30 * 1000;

const VAULT_EXTENSION = ".askrypt";

const $ = (id) => document.getElementById(id);

// ---------------------------------------------------------------------------
// State — everything a lock has to drop
// ---------------------------------------------------------------------------

let state = emptyState();

function emptyState() {
  return {
    // Where the bytes came from: {kind:"server", id, name, etag} or
    // {kind:"file", name}.
    source: null,
    file: null, // the parsed, still-encrypted header
    qd: null, // the remaining questions and salt1, once the first answer is in
    answer0: null,
    questions: null, // every question, first included
    // The answers, kept because re-encrypting on save needs them. There is no
    // way around it: a save re-wraps the master key under the same answers.
    answers: null,
    masterKey: null,
    entries: null,
    dirty: false,
    // Index into `entries`, or -1 for an entry being added.
    editing: null,
    draft: null,
  };
}

// ---------------------------------------------------------------------------
// Chrome: status, busy, section visibility
// ---------------------------------------------------------------------------

function show(id, visible) {
  const el = $(id);
  if (el) el.hidden = !visible;
}

function say(text, kind = "status") {
  const el = $("open-status");
  el.textContent = text;
  el.className = kind === "error" ? "error" : "status-line";
  el.hidden = text === "";
}

let busyDepth = 0;

function busy(on, label) {
  busyDepth = Math.max(0, busyDepth + (on ? 1 : -1));
  const working = busyDepth > 0;
  for (const button of document.querySelectorAll("#open-first-form button, #open-rest-form button, #open-save button")) {
    button.disabled = working;
  }
  if (on && label) say(label);
}

/// Runs `fn` with the busy state held, turning any failure into one sentence.
async function attempt(label, fn) {
  busy(true, label);
  try {
    await fn();
  } catch (err) {
    // A VaultError is already worded for a person. Anything else is a bug or a
    // network failure, and its message is not something to put on screen.
    say(err instanceof VaultError ? err.message : "Something went wrong.", "error");
  } finally {
    busy(false);
  }
}

// ---------------------------------------------------------------------------
// Step 1 — choosing a vault
// ---------------------------------------------------------------------------

function bindPicker() {
  const list = $("open-vault-list");
  if (!list) return;
  for (const button of list.querySelectorAll("button.pick")) {
    button.addEventListener("click", () => openStored(button));
  }
}

function openStored(button) {
  const source = {
    kind: "server",
    id: button.getAttribute("data-vault-id"),
    name: button.getAttribute("data-vault-name") || "vault",
    etag: button.getAttribute("data-vault-etag") || "",
  };
  attempt("Fetching the encrypted file…", async () => {
    const res = await fetch(`/vaults/${encodeURIComponent(source.id)}/download`, {
      credentials: "same-origin",
    });
    if (!res.ok) {
      throw new VaultError(
        res.status === 404
          ? "That vault is no longer on this account."
          : "Could not fetch that vault. Try signing in again.",
      );
    }
    await loadBytes(new Uint8Array(await res.arrayBuffer()), source);
  });
}

function openLocal(file) {
  if (file.size > MAX_VAULT_BYTES) {
    say("That file is too large to be a vault.", "error");
    return;
  }
  attempt("Reading the file…", async () => {
    const bytes = new Uint8Array(await file.arrayBuffer());
    await loadBytes(bytes, { kind: "file", name: file.name });
  });
}

async function loadBytes(bytes, source) {
  // `question0` and `params` are stored unencrypted, so the first question can
  // be put on screen before a single derivation has run.
  state.file = await parseVault(bytes);
  state.source = source;
  say("");
  show("open-source", false);
  show("open-first", true);
  $("open-first-title").textContent = `Unlock ${source.name}`;
  $("open-first-question").textContent = state.file.question0;
  $("open-answer0").value = "";
  $("open-answer0").focus();
}

async function refreshPicker() {
  const res = await fetch("/open/vaults", { credentials: "same-origin" });
  if (!res.ok) return false;
  const parsed = new DOMParser().parseFromString(await res.text(), "text/html");
  const fresh = parsed.getElementById("open-vault-list");
  const current = $("open-vault-list");
  if (!fresh || !current) return false;
  current.replaceWith(fresh);
  bindPicker();
  return true;
}

// ---------------------------------------------------------------------------
// Steps 2 and 3 — the layered unlock
// ---------------------------------------------------------------------------

function revealQuestions(event) {
  event.preventDefault();
  const answer0 = $("open-answer0").value;
  attempt("Deriving the key… this takes a moment.", async () => {
    let qd;
    try {
      qd = await getQuestionsData(state.file, answer0);
    } catch {
      // Wrong answer and an altered file are indistinguishable in this format
      // (SPEC.md, "Integrity: not provided"), and the common case by far is a
      // typo, so that is what it says.
      throw new VaultError("That is not the right answer to the first question.");
    }
    state.qd = qd;
    state.questions = [state.file.question0, ...qd.questions];
    state.answer0 = answer0;
    buildAnswerFields(qd.questions);
    say("");
    show("open-first", false);
    show("open-rest", true);
  });
}

function buildAnswerFields(questions) {
  const holder = $("open-rest-fields");
  holder.replaceChildren();
  questions.forEach((question, i) => {
    const label = document.createElement("label");
    label.setAttribute("for", `open-answer-${i}`);
    label.textContent = question;

    const input = document.createElement("input");
    input.id = `open-answer-${i}`;
    input.type = "password";
    input.required = true;
    // A phone keyboard will otherwise autocorrect an answer into a different
    // one, and normalization only strips spaces, dashes and capitals.
    for (const [k, v] of Object.entries({
      autocomplete: "off", autocapitalize: "off", autocorrect: "off",
      spellcheck: "false",
    })) input.setAttribute(k, v);

    holder.append(label, input);
  });
  holder.querySelector("input")?.focus();
}

function unlock(event) {
  event.preventDefault();
  const rest = state.qd.questions.map((_, i) => $(`open-answer-${i}`).value);
  attempt("Deriving the key… this takes a moment.", async () => {
    let opened;
    try {
      opened = await decryptWithMaster(state.file, state.qd, rest);
    } catch {
      throw new VaultError("One of those answers is not right.");
    }
    state.entries = opened.entries;
    state.masterKey = opened.masterKey;
    state.answers = [state.answer0, ...rest];
    state.dirty = false;
    say("");
    show("open-rest", false);
    show("open-vault", true);
    show("open-save", true);
    $("open-vault-title").textContent = state.source.name;
    $("open-save-server").hidden = state.source.kind !== "server";
    refreshTags();
    renderEntries();
    renderSaveState();
    armIdle();
  });
}

// ---------------------------------------------------------------------------
// Step 4 — the entry list
// ---------------------------------------------------------------------------

/// The search over an entry's *visible* fields. The secret, card number, CVV
/// and PIN are left out on purpose, as in `src/data.rs::entry_matches_filter`:
/// typing a secret into a search box and watching a row appear confirms the
/// secret.
function matches(entry, query) {
  if (query === "") return true;
  const q = query.toLowerCase();
  const tagQuery = q.startsWith("#") ? q.slice(1) : q;
  return [entry.name, entry.user_name, entry.url, entry.notes,
    entry.card_holder, entry.card_brand]
    .some((field) => field.toLowerCase().includes(q))
    || entry.tags.some((tag) => tag.toLowerCase().includes(tagQuery));
}

function visibleEntries() {
  const query = $("open-search").value.trim();
  const tag = $("open-tag").value;
  const showHidden = $("open-hidden").checked;
  return state.entries
    .map((entry, index) => ({ entry, index }))
    .filter(({ entry }) => (showHidden || !entry.hidden)
      && (tag === "" || entry.tags.includes(tag))
      && matches(entry, query));
}

function renderEntries() {
  const list = $("open-entries");
  list.replaceChildren();
  const rows = visibleEntries();
  show("open-empty", rows.length === 0);

  for (const { entry, index } of rows) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "pick";
    button.addEventListener("click", () => editEntry(index));

    const name = document.createElement("span");
    name.className = "pick-name";
    name.textContent = entry.name || "(no name)";

    const meta = document.createElement("span");
    meta.className = "pick-meta";
    meta.textContent = [
      entry.type || "Login",
      isCard(entry) ? entry.card_brand : entry.user_name,
      entry.hidden ? "hidden" : "",
      entry.tags.map((t) => `#${t}`).join(" "),
    ].filter(Boolean).join(" · ");

    button.append(name, meta);
    const item = document.createElement("li");
    item.append(button);
    list.append(item);
  }
}

function refreshTags() {
  const select = $("open-tag");
  const chosen = select.value;
  const tags = [...new Set(state.entries.flatMap((e) => e.tags))].sort();
  select.replaceChildren(new Option("All tags", ""));
  for (const tag of tags) select.append(new Option(`#${tag}`, tag));
  select.value = tags.includes(chosen) ? chosen : "";
}

// ---------------------------------------------------------------------------
// Step 5 — one entry
// ---------------------------------------------------------------------------

const CARD_INPUTS = {
  card_holder: "entry-card-holder", card_brand: "entry-card-brand",
  card_number: "entry-card-number", card_expiry: "entry-card-expiry",
  card_cvv: "entry-card-cvv", card_pin: "entry-card-pin",
};

function editEntry(index) {
  state.editing = index;
  state.draft = index < 0 ? blankEntry() : { ...state.entries[index] };
  fillEditor(state.draft);
  $("open-editor-title").textContent = index < 0 ? "New entry" : "Edit entry";
  $("entry-delete").hidden = index < 0;
  show("open-vault", false);
  show("open-editor", true);
}

function fillEditor(entry) {
  $("entry-name").value = entry.name;
  $("entry-user").value = entry.user_name;
  $("entry-secret").value = entry.secret;
  $("entry-url").value = entry.url;
  $("entry-notes").value = entry.notes;
  $("entry-tags").value = entry.tags.join(", ");
  $("entry-hidden").checked = entry.hidden;
  for (const [key, id] of Object.entries(CARD_INPUTS)) $(id).value = entry[key];

  // The type is a free string in the format and the three clients spell it
  // differently — `src/` writes "password", the mobile app "login" — so a type
  // this select has never heard of is added rather than silently rewritten.
  const select = $("entry-type");
  const type = entry.type || "Login";
  if (![...select.options].some((o) => o.value === type)) {
    select.append(new Option(type, type));
  }
  select.value = type;
  syncTypeFields();

  $("entry-stamp").textContent = entry.created
    ? `Created ${localTime(entry.created)} · last changed ${localTime(entry.modified)}`
    : "";
  // Secrets start masked whatever they were left as last time.
  for (const id of ["entry-secret", "entry-card-number", "entry-card-cvv", "entry-card-pin"]) {
    $(id).type = "password";
  }
  for (const button of document.querySelectorAll("[data-reveal]")) {
    button.textContent = "Show";
  }
}

function syncTypeFields() {
  const card = $("entry-type").value.toLowerCase() === "card";
  show("entry-card-fields", card);
  show("entry-login-fields", !card);
}

function applyEntry(event) {
  event.preventDefault();
  const entry = { ...state.draft };
  entry.name = $("entry-name").value;
  entry.type = $("entry-type").value;
  entry.user_name = $("entry-user").value;
  entry.secret = $("entry-secret").value;
  entry.url = $("entry-url").value;
  entry.notes = $("entry-notes").value;
  entry.hidden = $("entry-hidden").checked;
  entry.tags = $("entry-tags").value.split(",")
    .map((t) => t.trim().replace(/^#/, "")).filter(Boolean);
  for (const [key, id] of Object.entries(CARD_INPUTS)) entry[key] = $(id).value;
  entry.modified = Math.floor(Date.now() / 1000);

  if (state.editing < 0) state.entries.push(entry);
  else state.entries[state.editing] = entry;

  markDirty();
  closeEditor();
}

function deleteEntry() {
  if (state.editing < 0) return closeEditor();
  state.entries.splice(state.editing, 1);
  markDirty();
  closeEditor();
}

function closeEditor() {
  state.editing = null;
  state.draft = null;
  // Leaving the fields populated would keep a secret on screen behind a hidden
  // section, and in the DOM after a lock.
  clearEditorFields();
  show("open-editor", false);
  show("open-vault", true);
  refreshTags();
  renderEntries();
}

function clearEditorFields() {
  for (const id of ["entry-name", "entry-user", "entry-secret", "entry-url",
    "entry-notes", "entry-tags", ...Object.values(CARD_INPUTS)]) {
    $(id).value = "";
  }
  $("entry-hidden").checked = false;
}

function markDirty() {
  state.dirty = true;
  renderSaveState();
}

function localTime(unixSeconds) {
  return new Date(unixSeconds * 1000).toLocaleString();
}

// ---------------------------------------------------------------------------
// Step 6 — saving
// ---------------------------------------------------------------------------

function renderSaveState() {
  $("open-save-state").textContent = state.dirty
    ? "You have changes that are not saved yet."
    : "No changes since you opened this vault.";
}

/// Re-encrypts the whole vault. Everything but the entries is carried over
/// from the file that was opened: the same master key (re-wrapped, never
/// rotated — see SPEC.md, "Master key lifetime"), the same questions and
/// answers, the same work factor and the same normalization setting.
async function rebuild() {
  return createVault({
    questions: state.questions,
    answers: state.answers,
    entries: state.entries,
    iterations: state.file.iterations,
    translit: state.file.translit,
    kdf: state.file.kdf,
    masterKey: state.masterKey,
    host: hostStamp(),
  });
}

/// The write stamp's `os@host` label. A browser cannot know the machine's
/// name, so the host half is `web`; the OS half is whatever the platform will
/// admit to, and when it admits to nothing the field is omitted entirely
/// rather than written as a dangling `@web`.
function hostStamp() {
  const raw = navigator.userAgentData?.platform || guessPlatform();
  const os = raw.toLowerCase().replace(/[^a-z0-9._-]/g, "");
  return os ? `${os}@web` : null;
}

function guessPlatform() {
  const ua = navigator.userAgent || "";
  if (/iPhone|iPad|iPod/.test(ua)) return "ios";
  if (/Android/.test(ua)) return "android";
  if (/Mac OS X/.test(ua)) return "macos";
  if (/Windows/.test(ua)) return "windows";
  if (/Linux/.test(ua)) return "linux";
  return "";
}

function saveToServer() {
  attempt("Encrypting and uploading…", async () => {
    const bytes = await rebuild();
    const form = new FormData();
    // The CSRF part must come first: `web::csrf::CsrfMultipart` verifies it as
    // it reads the parts, before any file bytes are buffered.
    form.append("csrf", $("open-csrf").value);
    // The version this page was handed. A stale one is refused rather than
    // quietly overwriting what another device saved in the meantime.
    form.append("etag", state.source.etag);
    form.append(
      "file",
      new Blob([bytes], { type: "application/octet-stream" }),
      withExtension(state.source.name),
    );

    const res = await fetch(`/vaults/${encodeURIComponent(state.source.id)}/replace`, {
      method: "POST",
      body: form,
      credentials: "same-origin",
      // On this route the status is the verdict: a change that went through is
      // a 303, and a refused one re-renders the page at 200. Following the
      // redirect would erase the difference.
      redirect: "manual",
    });

    // A browser turns the 303 into an opaque-redirect response with no status
    // at all; the status is only visible outside one, which is where this is
    // exercised from a script.
    const saved = res.type === "opaqueredirect" || (res.status >= 300 && res.status < 400);
    if (!saved) {
      throw new VaultError(res.status === 200
        ? refusalReason(await res.text())
        : "The server would not accept the save.");
    }

    state.dirty = false;
    // The ETag moved, so the value this page holds is now the one the *next*
    // save would be refused for. Adopt the new one before allowing another.
    if (await refreshPicker()) adoptFreshEtag();
    renderSaveState();
    say("Saved.");
  });
}

/// Pulls the sentence `web::vaults::refused` rendered — a stale ETag, a full
/// quota — out of the page it came back on, rather than inventing our own
/// wording for a refusal the server already explained.
function refusalReason(html) {
  const doc = new DOMParser().parseFromString(html, "text/html");
  const notice = doc.querySelector("#vault-list p.error");
  const text = notice?.textContent.trim();
  return text || "The server refused the save.";
}

function adoptFreshEtag() {
  const button = $("open-vault-list")
    ?.querySelector(`button.pick[data-vault-id="${CSS.escape(state.source.id)}"]`);
  const etag = button?.getAttribute("data-vault-etag");
  if (etag) state.source.etag = etag;
}

function saveDownload() {
  attempt("Encrypting…", async () => {
    const bytes = await rebuild();
    const name = withExtension(state.source.name);
    const blob = new Blob([bytes], { type: "application/octet-stream" });

    if (typeof window.showSaveFilePicker === "function") {
      try {
        const handle = await window.showSaveFilePicker({ suggestedName: name });
        const writable = await handle.createWritable();
        await writable.write(blob);
        await writable.close();
        state.dirty = false;
        renderSaveState();
        say("Saved.");
        return;
      } catch (err) {
        if (err?.name === "AbortError") return; // the picker was dismissed
        // Fall through to the download link, which every browser has.
      }
    }

    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = name;
    link.click();
    URL.revokeObjectURL(url);
    state.dirty = false;
    renderSaveState();
    say("Downloaded a new copy — a browser cannot write back over the file you picked.");
  });
}

/// Mirrors `web::vaults::download_filename`: a stored name is not required to
/// carry the extension (the desktop stores server vaults under a bare name),
/// and nothing should ever land as `.askrypt.askrypt`.
function withExtension(name) {
  const base = name.trim() || "vault";
  return base.toLowerCase().endsWith(VAULT_EXTENSION) ? base : base + VAULT_EXTENSION;
}

// ---------------------------------------------------------------------------
// Locking
// ---------------------------------------------------------------------------

function lock(reason) {
  clearEditorFields();
  $("open-answer0").value = "";
  $("open-rest-fields").replaceChildren();
  $("open-entries").replaceChildren();
  $("open-search").value = "";
  $("open-hidden").checked = false;
  $("open-file").value = "";

  // Dropping the references is all a garbage-collected runtime allows; there
  // is no `zeroize` here, and the desktop and mobile cores say so about their
  // own immutable strings too.
  state = emptyState();
  disarmIdle();
  clearClipboardSoon.cancel();

  for (const id of ["open-first", "open-rest", "open-vault", "open-editor", "open-save"]) {
    show(id, false);
  }
  show("open-source", true);
  say(reason || "Locked.");
}

// --- auto-lock -------------------------------------------------------------

let idleTimer = null;
let hiddenTimer = null;

function unlocked() {
  return state.entries !== null;
}

function armIdle() {
  disarmIdle();
  if (unlocked()) idleTimer = setTimeout(() => lock("Locked after a few minutes idle."), IDLE_MS);
}

function disarmIdle() {
  clearTimeout(idleTimer);
  idleTimer = null;
}

function onActivity() {
  if (unlocked()) armIdle();
}

function onVisibility() {
  clearTimeout(hiddenTimer);
  if (document.visibilityState !== "hidden" || !unlocked()) return;
  hiddenTimer = setTimeout(() => lock("Locked while the page was in the background."), HIDDEN_GRACE_MS);
}

// --- clipboard -------------------------------------------------------------

const clearClipboardSoon = (() => {
  let timer = null;
  const fn = () => {
    clearTimeout(timer);
    timer = setTimeout(() => {
      // Best effort, and weaker than the mobile app's: that one checks the
      // clipboard still holds what it put there, which a page cannot do
      // without a read permission Safari will not grant.
      navigator.clipboard?.writeText("").catch(() => {});
    }, CLIPBOARD_MS);
  };
  fn.cancel = () => clearTimeout(timer);
  return fn;
})();

async function copyField(id) {
  const value = $(id).value;
  if (!value) return;
  try {
    await navigator.clipboard.writeText(value);
    clearClipboardSoon();
    say("Copied. The clipboard clears in 30 seconds.");
  } catch {
    say("This browser would not let the page use the clipboard.", "error");
  }
}

// ---------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------

function init() {
  // Web Crypto is unavailable outside a secure context, and `deflate-raw` is
  // what reads the ZIP the apps wrote. Without either there is nothing to do
  // but say so.
  if (!window.isSecureContext || !window.crypto?.subtle
      || typeof DecompressionStream !== "function") {
    show("open-unsupported", true);
    show("open-source", false);
    return;
  }

  bindPicker();
  $("open-refresh")?.addEventListener("click", () => attempt("Refreshing…", async () => {
    if (!await refreshPicker()) throw new VaultError("Could not refresh the list.");
    say("");
  }));
  $("open-file").addEventListener("change", (e) => {
    const file = e.target.files?.[0];
    if (file) openLocal(file);
  });

  $("open-first-form").addEventListener("submit", revealQuestions);
  $("open-rest-form").addEventListener("submit", unlock);
  for (const button of document.querySelectorAll("[data-action='cancel']")) {
    button.addEventListener("click", () => lock(""));
  }

  for (const id of ["open-search", "open-tag", "open-hidden"]) {
    $(id).addEventListener("input", renderEntries);
  }
  $("open-add").addEventListener("click", () => editEntry(-1));
  $("open-lock").addEventListener("click", () => lock());

  $("open-editor-form").addEventListener("submit", applyEntry);
  $("entry-cancel").addEventListener("click", closeEditor);
  $("entry-delete").addEventListener("click", deleteEntry);
  $("entry-type").addEventListener("change", syncTypeFields);

  for (const button of document.querySelectorAll("[data-reveal]")) {
    button.addEventListener("click", () => {
      const field = $(button.getAttribute("data-reveal"));
      const hiddenNow = field.type === "password";
      field.type = hiddenNow ? "text" : "password";
      button.textContent = hiddenNow ? "Hide" : "Show";
    });
  }
  for (const button of document.querySelectorAll("[data-copy]")) {
    button.addEventListener("click", () => copyField(button.getAttribute("data-copy")));
  }

  $("open-save-server").addEventListener("click", saveToServer);
  $("open-save-download").addEventListener("click", saveDownload);

  document.addEventListener("visibilitychange", onVisibility);
  for (const event of ["pointerdown", "keydown"]) {
    document.addEventListener(event, onActivity, { passive: true });
  }
  window.addEventListener("beforeunload", (e) => {
    if (!state.dirty) return;
    e.preventDefault();
    e.returnValue = "";
  });

  // The deep link from the file manager's row.
  const wanted = new URLSearchParams(location.search).get("vault");
  if (wanted) {
    const button = $("open-vault-list")
      ?.querySelector(`button.pick[data-vault-id="${CSS.escape(wanted)}"]`);
    if (button) openStored(button);
  }
}

init();
