// The `/open` page: pick a vault, answer the questions, browse and edit, save.
//
// All the crypto lives in `vault-format.js` and `vault-smartlock.js`, and the
// password generator in `vault-passgen.js`; this file is the DOM around the
// three of them. Nothing here writes to `localStorage`,
// `sessionStorage`, IndexedDB, the URL fragment or the console — a decrypted
// vault exists only in this page's variables and only until it locks.
//
// The CSP is `script-src 'self'` on this page as on every other, so there is
// no inline script anywhere and every value the markup hands over arrives as a
// `data-` attribute, the same way `captcha.js` and `google.js` take theirs.
// Rendered text always goes through `textContent`, never `innerHTML`: entry
// names come out of a file that anybody could have written.

import {
  CARD_KEYS, DEFAULT_ITERATIONS, MAX_VAULT_BYTES, VaultError, blankEntry,
  createVault, decryptWithMaster, generateMasterKey, getQuestionsData, isCard,
  parseVault,
} from "./vault-format.js";
import {
  SMART_LOCK_TIMEOUT_MS, createSmartLock, recoverSmartLock, smartLockRemaining,
} from "./vault-smartlock.js";
import {
  MAX_LENGTH, MIN_LENGTH, clampLength, defaultConfig, generatePassword,
} from "./vault-passgen.js";

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
    // Where the bytes came from: {kind:"server", id, name, etag},
    // {kind:"file", name}, or {kind:"new", name} for a vault this page has
    // just created and that has therefore never been written anywhere.
    source: null,
    file: null, // the parsed, still-encrypted header; null for a new vault
    // The format parameters a save has to reproduce: read off the file that
    // was opened, or chosen once when a vault is created. Held apart from
    // `file` precisely because a new vault has no file to read them from.
    params: null,
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
    // When this session's eight-hour Smart Lock ceiling runs out, or null when
    // it did not come out of a Smart Lock and therefore has no ceiling. It
    // doubles as the answer to "did the user ask for this vault to be
    // reachable from one answer?", which is what an automatic lock consults.
    smartDeadline: null,
  };
}

/// The armed Smart Lock, or null. Deliberately *outside* `state`, because
/// arming is a lock: it runs the whole of `lock`, which replaces `state`
/// wholesale, and the bundle is what is put back afterwards. A full lock
/// clears this too — there is nowhere else for a secret to be.
let smart = null;

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
  for (const button of document.querySelectorAll(
    "#open-create-form button, #open-first-form button, #open-rest-form button,"
      + " #open-smart-form button, #open-vault .row-actions button, #open-save button",
  )) {
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
  state.params = {
    iterations: state.file.iterations,
    translit: state.file.translit,
    kdf: state.file.kdf,
  };
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
// Step 1b — a brand-new vault
// ---------------------------------------------------------------------------

const utf8 = new TextEncoder();

/// Whether there is an account behind this page. The picker is rendered for a
/// signed-in visitor and for nobody else — including one whose account holds
/// no vaults yet, whose list says so rather than being left out — so its
/// presence is the answer, and no separate flag has to be kept in step.
function signedIn() {
  return $("open-vault-list") !== null;
}

/// Two empty rows, like `panes::questions::State::begin_new`: a vault needs at
/// least two questions, so starting with two says so without a sentence.
function beginCreate() {
  $("open-create-name").value = "";
  $("open-create-show").checked = false;
  $("open-create-translit").checked = false;
  $("open-create-questions").replaceChildren();
  addQuestionRow();
  addQuestionRow();
  say("");
  show("open-source", false);
  show("open-create", true);
  $("open-create-name").focus();
}

function addQuestionRow() {
  const row = document.createElement("div");
  row.className = "qa-row";

  const question = document.createElement("input");
  question.type = "text";
  question.className = "qa-question";
  question.required = true;
  question.autocomplete = "off";
  question.spellcheck = false;

  const answer = document.createElement("input");
  answer.className = "qa-answer";
  answer.required = true;
  // Masked unless the visitor asks otherwise, and never autocorrected: a phone
  // keyboard would otherwise store an answer that is not the one being typed,
  // and normalization only strips spaces, dashes and capitals.
  answer.type = $("open-create-show").checked ? "text" : "password";
  for (const [k, v] of Object.entries({
    autocomplete: "off", autocapitalize: "off", autocorrect: "off",
    spellcheck: "false",
  })) answer.setAttribute(k, v);

  const remove = document.createElement("button");
  remove.type = "button";
  remove.className = "linklike danger qa-remove";
  remove.textContent = "Remove this question";
  remove.addEventListener("click", () => removeQuestionRow(row));

  const questionLabel = document.createElement("label");
  const answerLabel = document.createElement("label");
  row.append(questionLabel, question, answerLabel, answer, remove);
  $("open-create-questions").append(row);
  numberQuestionRows();
  question.focus();
}

function removeQuestionRow(row) {
  row.remove();
  numberQuestionRows();
}

/// Labels, ids and the removability of each row, recomputed whenever the set
/// changes. The last two rows carry no Remove button rather than a refusal:
/// the format's floor is two questions, and a control that cannot be used is
/// better not offered.
function numberQuestionRows() {
  const rows = [...$("open-create-questions").querySelectorAll(".qa-row")];
  rows.forEach((row, i) => {
    const question = row.querySelector(".qa-question");
    const answer = row.querySelector(".qa-answer");
    question.id = `create-q-${i}`;
    answer.id = `create-a-${i}`;
    const [questionLabel, answerLabel] = row.querySelectorAll("label");
    questionLabel.setAttribute("for", question.id);
    questionLabel.textContent = `Question ${i + 1}`;
    answerLabel.setAttribute("for", answer.id);
    answerLabel.textContent = `Answer ${i + 1}`;
    row.querySelector(".qa-remove").hidden = rows.length <= 2;
  });
}

function toggleCreateAnswers() {
  const shown = $("open-create-show").checked;
  for (const answer of document.querySelectorAll("#open-create-questions .qa-answer")) {
    answer.type = shown ? "text" : "password";
  }
}

/// Brings a vault into existence. Nothing is derived or encrypted here: the
/// entry list is empty, and a save re-encrypts the whole vault anyway, so the
/// derivation would only be thrown away. What *is* decided here and never
/// again is the master key — this is the page's one mint, the counterpart of
/// `RekeyInputs::run` in the desktop app — along with the work factor and the
/// normalization setting, which a later save reproduces out of `state.params`.
function createNew(event) {
  event.preventDefault();
  const name = $("open-create-name").value.trim();
  const rows = [...$("open-create-questions").querySelectorAll(".qa-row")];
  const questions = rows.map((row) => row.querySelector(".qa-question").value.trim());
  const answers = rows.map((row) => row.querySelector(".qa-answer").value);

  const problem = createProblem(name, questions, answers);
  if (problem) {
    say(problem, "error");
    return;
  }

  state.source = { kind: "new", name };
  state.file = null;
  state.params = {
    iterations: DEFAULT_ITERATIONS,
    translit: $("open-create-translit").checked,
    // The Rust core writes this and no implementation reads it; a vault born
    // here declares what it actually used, like every other writer does.
    kdf: "pbkdf2",
  };
  state.questions = questions;
  state.answer0 = answers[0];
  state.answers = answers;
  state.masterKey = generateMasterKey();
  state.entries = [];
  // Unsaved from its first instant: this vault exists only in this page until
  // one of the two save buttons is pressed, which is what the state line says
  // and what the unload guard is armed by.
  state.dirty = true;

  show("open-create", false);
  clearCreateFields();
  enterVault();
  say("Vault created. Add your entries, then save it.");
}

/// The same rules as `panes::questions::save`, plus the name — which this page
/// needs and the desktop asks for at its own save dialog instead. The 500-byte
/// question ceiling is `createVault`'s, checked here so it lands next to the
/// field rather than after a save that got as far as encrypting.
function createProblem(name, questions, answers) {
  if (name === "") return "Give the vault a name.";
  if (utf8.encode(name).length > 255 || /[\\/\u0000-\u001f\u007f]/.test(name)) {
    return "That name will not work as a file name. Keep it short and plain.";
  }
  if (questions.length < 2) return "At least two questions are required.";
  const blankQuestion = questions.findIndex((question) => question === "");
  if (blankQuestion >= 0) return `Question ${blankQuestion + 1} cannot be empty.`;
  const longQuestion = questions.findIndex((q) => utf8.encode(q).length > 500);
  if (longQuestion >= 0) return `Question ${longQuestion + 1} is too long.`;
  const blankAnswer = answers.findIndex((answer) => answer.trim() === "");
  if (blankAnswer >= 0) return `Answer ${blankAnswer + 1} cannot be empty.`;
  return null;
}

function clearCreateFields() {
  $("open-create-name").value = "";
  $("open-create-questions").replaceChildren();
  $("open-create-show").checked = false;
  $("open-create-translit").checked = false;
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
    enterVault();
  });
}

/// The unlocked view, reached from an unlock and from a creation alike —
/// everything below this point works the same whether the entries came out of
/// a file or have yet to be typed.
function enterVault() {
  show("open-vault", true);
  show("open-save", true);
  $("open-vault-title").textContent = state.source.name;
  // A vault that lives on this account can be written back to it, and so can
  // one this page has just created — as a new file, through the same upload
  // the file manager uses. A vault opened from a local file cannot: the
  // account has no row for it, and inventing one would silently turn "I opened
  // a file" into "I uploaded my vault".
  $("open-save-server").hidden = !(state.source.kind === "server"
    || (state.source.kind === "new" && signedIn()));
  refreshTags();
  renderEntries();
  renderSaveState();
  armIdle();
  // A session reached through a Smart Lock inherits its ceiling; one reached by
  // answering every question has none.
  if (state.smartDeadline !== null) armCeiling(state.smartDeadline);
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
  // An entry always opens with the generator shut, whatever the last one left.
  closePassgen();
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
  // A generated password is a secret like any other field's, and this is the
  // one funnel closing the editor and every lock path both reach.
  closePassgen();
}

function markDirty() {
  state.dirty = true;
  renderSaveState();
}

function localTime(unixSeconds) {
  return new Date(unixSeconds * 1000).toLocaleString();
}

// ---------------------------------------------------------------------------
// The password generator — the panel under the Secret field
// ---------------------------------------------------------------------------
//
// The port of `src/panes/passgen.rs`, over `vault-passgen.js` the way that
// pane sits over `askrypt::passgen`. It is a panel rather than a screen of its
// own because there is only one place a generated password is wanted here: the
// entry being edited. The desktop's rail button has no counterpart.

/// The character sets and length, which are a preference rather than a secret
/// and so live for as long as the page does — the pane's `State` does the
/// same. `passgenValue` beside it is the secret half, and the counterpart of
/// that struct's `Drop`/`forget`: `closePassgen` is the only way it is dropped
/// and every lock path reaches it.
let passgenConfig = defaultConfig();
let passgenValue = "";

/// Opens the panel with a password already in it.
///
/// The one deliberate difference from the pane, which opens showing `—` until
/// Generate is pressed: there the generator is a screen you navigated to on
/// purpose, here it is a panel that appeared under a field, and an empty one
/// reads as broken.
function openPassgen() {
  syncPassgenControls();
  show("entry-passgen", true);
  regeneratePassgen();
}

/// Hides the panel and forgets the password — `State::forget`. Called from
/// `clearEditorFields`, which is the funnel both closing the editor and every
/// lock path already go through.
function closePassgen() {
  passgenValue = "";
  $("passgen-value").textContent = "—";
  show("entry-passgen", false);
}

/// Writes the controls out of `passgenConfig`, so the markup's own values are
/// only ever the initial ones and the panel comes back the way it was left.
function syncPassgenControls() {
  const slider = $("passgen-length");
  slider.min = String(MIN_LENGTH);
  slider.max = String(MAX_LENGTH);
  slider.value = String(passgenConfig.length);
  $("passgen-length-value").textContent = String(passgenConfig.length);
  $("passgen-upper").checked = passgenConfig.useUppercase;
  $("passgen-lower").checked = passgenConfig.useLowercase;
  $("passgen-numbers").checked = passgenConfig.useNumbers;
  $("passgen-symbols").checked = passgenConfig.useSymbols;
}

/// `State::regenerate`: a fresh password, or the reason there isn't one on the
/// status line — where the pane puts it in `session.error_message`.
function regeneratePassgen() {
  try {
    passgenValue = generatePassword(passgenConfig);
    $("passgen-value").textContent = passgenValue;
    say("");
  } catch (err) {
    passgenValue = "";
    $("passgen-value").textContent = "—";
    say(err instanceof VaultError ? err.message : "Something went wrong.", "error");
  }
}

/// Every control regenerates immediately, exactly as in the pane — the length
/// clamps in `vault-passgen.js`, so nothing here has to.
function onPassgenControl() {
  passgenConfig = {
    length: clampLength($("passgen-length").value),
    useUppercase: $("passgen-upper").checked,
    useLowercase: $("passgen-lower").checked,
    useNumbers: $("passgen-numbers").checked,
    useSymbols: $("passgen-symbols").checked,
  };
  $("passgen-length-value").textContent = String(passgenConfig.length);
  regeneratePassgen();
}

async function copyPassgen() {
  if (!passgenValue) {
    say("No password to copy.", "error");
    return;
  }
  await copyText(passgenValue);
}

/// `Msg::CopyAndUse`: the clipboard *and* the field, then forget it. The field
/// is left masked — revealing it would be a second decision, and the Show
/// button is right there.
async function usePassgen() {
  if (!passgenValue) {
    say("No password to copy.", "error");
    return;
  }
  const password = passgenValue;
  $("entry-secret").value = password;
  closePassgen();
  await copyText(password);
}

// ---------------------------------------------------------------------------
// Step 6 — saving
// ---------------------------------------------------------------------------

function renderSaveState() {
  // A created vault has never been written anywhere, so "no changes since you
  // opened it" would be true and useless: what matters is that closing the tab
  // would be the end of it.
  const fresh = state.source.kind === "new";
  $("open-save-state").textContent = state.dirty
    ? (fresh
      ? "This vault exists only in this page until you save it."
      : "You have changes that are not saved yet.")
    : (fresh
      ? "Downloaded, and not stored on this account."
      : "No changes since you opened this vault.");
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
    iterations: state.params.iterations,
    translit: state.params.translit,
    kdf: state.params.kdf,
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

/// Writes the vault to the account: a replace for one that is stored there, an
/// upload for one this page created. Both are routes `web::vaults` already
/// owns and both run its `check_upload`, quota and versioning rules — `/open`
/// deliberately has no POST of its own, so there is no second place for any of
/// that to drift.
function saveToServer() {
  const fresh = state.source.kind === "new";
  attempt("Encrypting and uploading…", async () => {
    const bytes = await rebuild();
    const form = new FormData();
    // The CSRF part must come first: `web::csrf::CsrfMultipart` verifies it as
    // it reads the parts, before any file bytes are buffered.
    form.append("csrf", $("open-csrf").value);
    if (fresh) {
      // What the file is stored under. The upload would otherwise fall back to
      // the *file* name, which carries the extension a stored name need not.
      form.append("name", state.source.name);
    } else {
      // The version this page was handed. A stale one is refused rather than
      // quietly overwriting what another device saved in the meantime.
      form.append("etag", state.source.etag);
    }
    form.append(
      "file",
      new Blob([bytes], { type: "application/octet-stream" }),
      withExtension(state.source.name),
    );

    const res = await fetch(fresh
      ? "/vaults"
      : `/vaults/${encodeURIComponent(state.source.id)}/replace`, {
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
    const listed = await refreshPicker();
    if (fresh) {
      // The upload made a row that this page has no id or ETag for, and both
      // are what a further save needs. Adopting it turns the created vault
      // into a stored one; failing to find it is not a lost save, only a
      // second upload that the server would refuse for a name it already has.
      const adopted = listed && adoptCreated();
      renderSaveState();
      say(adopted
        ? "Saved to your account."
        : "Saved to your account — reload this page before saving it again.");
      return;
    }
    if (listed) adoptFreshEtag();
    renderSaveState();
    say("Saved.");
  });
}

/// Finds the row the upload just created and takes over its id and ETag, so
/// the vault carries on as an ordinary stored one. Matched by name, which is
/// what was just sent and what the server stores it under.
function adoptCreated() {
  const button = [...($("open-vault-list")?.querySelectorAll("button.pick") ?? [])]
    .find((row) => row.getAttribute("data-vault-name") === state.source.name);
  if (!button) return false;
  state.source = {
    kind: "server",
    id: button.getAttribute("data-vault-id"),
    name: button.getAttribute("data-vault-name"),
    etag: button.getAttribute("data-vault-etag") || "",
  };
  return true;
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
    say(state.source.kind === "file"
      ? "Downloaded a new copy — a browser cannot write back over the file you picked."
      : "Downloaded. Keep it somewhere you will find it again.");
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

/// A full lock: every secret dropped, the Smart Lock bundle among them.
function lock(reason) {
  clearEditorFields();
  // The answers typed into the create form are key material as much as the
  // ones typed into an unlock, and a cancelled creation leaves them there.
  clearCreateFields();
  $("open-answer0").value = "";
  $("open-smart-answer").value = "";
  $("open-rest-fields").replaceChildren();
  $("open-entries").replaceChildren();
  $("open-search").value = "";
  $("open-hidden").checked = false;
  $("open-file").value = "";

  // Dropping the references is all a garbage-collected runtime allows; there
  // is no `zeroize` here, and the desktop and mobile cores say so about their
  // own immutable strings too.
  state = emptyState();
  smart = null;
  disarmIdle();
  disarmHidden();
  disarmCeiling();
  stopCountdown();
  clearClipboardSoon.cancel();

  for (const id of ["open-create", "open-first", "open-rest", "open-smart",
    "open-vault", "open-editor", "open-save"]) {
    show(id, false);
  }
  show("open-source", true);
  say(reason || "Locked.");
}

// ---------------------------------------------------------------------------
// Smart Lock — the answers held encrypted under one of themselves
// ---------------------------------------------------------------------------

/// Arms Smart Lock. The port of `App::start_smart_lock`, with one deliberate
/// difference, in the bytes the bundle re-opens.
///
/// The desktop re-reads the file the vault was opened from, which is why
/// arming there drops unsaved edits and why `App::auto_smart_lock` saves first
/// or refuses. A browser tab has no file to re-read — a vault opened from a
/// local file cannot be written back to it, and one created here may never
/// have been written at all — so this re-encrypts what is in the page instead,
/// under the same master key and the same answers a save would use. It costs
/// one save's worth of derivation, and it means arming loses nothing and can
/// refuse nothing.
///
/// The security property is unchanged: the bundle still holds answers and no
/// master key, so on its own it opens nothing — recovering the vault is still
/// the ordinary layered unlock, run against these bytes.
async function armSmartLock() {
  if (!unlocked()) return;
  // Smart Lock keys on an answer other than the first, so a one-question vault
  // has nothing to key on. Every vault this page can *write* has at least two
  // questions; one written by something else need not.
  if (state.answers.length < 2) {
    throw new VaultError("Smart Lock needs a vault with at least two questions.");
  }

  const bytes = await rebuild();
  const bundle = await createSmartLock({
    answer0: state.answers[0],
    answers: state.answers.slice(1),
    questions: state.questions.slice(1),
    translit: state.params.translit,
  });
  // What survives the lock, besides the bundle: where the vault came from, the
  // bytes it re-opens, and whether it still owes a save. Everything else is
  // re-derived on the way back in.
  const carried = { bundle, source: state.source, bytes, dirty: state.dirty };

  // A full lock first — it drops every secret and clears every field, which is
  // exactly what arming has to do as well. The bundle goes back afterwards,
  // because `lock` is also what *ends* a Smart Lock.
  lock("");
  smart = carried;
  showSmart();
}

function showSmart() {
  show("open-source", false);
  show("open-smart", true);
  $("open-smart-question").textContent = smart.bundle.keyQuestion;
  $("open-smart-answer").value = "";
  renderCountdown();
  countdownTimer = setInterval(renderCountdown, 30 * 1000);
  armCeiling(smart.bundle.armedAt + SMART_LOCK_TIMEOUT_MS);
  $("open-smart-answer").focus();
}

/// One answer recovers the whole set, which then opens the vault the ordinary
/// way: 2M iterations to get the answers back, then the format's own 600k
/// twice. Mirrors `SmartUnlockInputs::run`.
function smartUnlock(event) {
  event.preventDefault();
  const answer = $("open-smart-answer").value;
  const carried = smart;
  if (!carried) return;
  attempt("Deriving the key… this takes a moment.", async () => {
    // Parsed first, and not only for the ciphertext: `translit` decides how the
    // answer normalizes, and it is a property of the vault rather than of the
    // bundle — the same reason `Vault<SmartLocked>` reads it off its file.
    const file = await parseVault(carried.bytes);
    let recovered;
    try {
      recovered = await recoverSmartLock(carried.bundle, answer, file.translit);
    } catch {
      throw new VaultError("That is not the answer this Smart Lock was keyed on.");
    }
    // These bytes were written by this page from these answers, so nothing
    // below can fail over a wrong answer — only over a bug.
    const qd = await getQuestionsData(file, recovered.answer0);
    const opened = await decryptWithMaster(file, qd, recovered.answers);

    smart = null;
    stopCountdown();
    state = emptyState();
    state.source = carried.source;
    state.file = file;
    state.params = {
      iterations: file.iterations, translit: file.translit, kdf: file.kdf,
    };
    state.qd = qd;
    state.answer0 = recovered.answer0;
    state.questions = [file.question0, ...qd.questions];
    state.answers = [recovered.answer0, ...recovered.answers];
    state.masterKey = opened.masterKey;
    state.entries = opened.entries;
    // The bundle was armed over these very entries, so whatever was owed to a
    // save before the lock is still owed now.
    state.dirty = carried.dirty;
    // The ceiling restarts on the way through, exactly as `smart_unlock` does
    // it: a session reached from one answer stays time-limited.
    state.smartDeadline = Date.now() + SMART_LOCK_TIMEOUT_MS;

    $("open-smart-answer").value = "";
    show("open-smart", false);
    say("");
    enterVault();
  });
}

function renderCountdown() {
  if (!smart) return;
  const minutes = Math.floor(smartLockRemaining(smart.bundle) / (60 * 1000));
  $("open-smart-countdown").textContent =
    `Time until full lock: ${Math.floor(minutes / 60)}h ${minutes % 60}m`;
}

function stopCountdown() {
  clearInterval(countdownTimer);
  countdownTimer = null;
}

/// The eight-hour ceiling, which outlives the bundle: a vault re-opened from a
/// Smart Lock carries one too, so being reachable from a single answer stays
/// time-limited however often it is re-armed. `setTimeout` tops out at about
/// 25 days, so eight hours is well inside what one timer can hold.
function armCeiling(at) {
  disarmCeiling();
  ceilingTimer = setTimeout(
    () => lock("Smart Lock expired — the vault is fully locked."),
    Math.max(0, at - Date.now()),
  );
}

function disarmCeiling() {
  clearTimeout(ceilingTimer);
  ceilingTimer = null;
}

// --- auto-lock -------------------------------------------------------------

let idleTimer = null;
let hiddenTimer = null;
let ceilingTimer = null;
let countdownTimer = null;

function unlocked() {
  return state.entries !== null;
}

/// What a lock the *page* decided on does — as opposed to one the user asked
/// for by pressing a button.
///
/// It keeps nothing, which is the promise `/open` makes and the desktop does
/// not have to: there, an idle timeout arms Smart Lock. The exception is a
/// session that came out of a Smart Lock, which `smartDeadline` is what marks:
/// the user asked for this vault to be reachable from one answer, the ceiling
/// they started is still running, and throwing the answers away every three
/// idle minutes would make the feature useless. Arming is best effort — a
/// failure still locks, because a timeout that leaves a vault open is the one
/// outcome that must not happen.
function autoLock(reason) {
  // Something is already deriving or uploading. `App::start_smart_lock` bails
  // on `session.busy` for the same reason: replacing the state object out from
  // under a save in flight leaves its continuation reading a locked vault.
  // Come back to it on the next idle turn instead.
  if (busyDepth > 0) {
    armIdle();
    return;
  }
  if (state.smartDeadline === null) {
    lock(reason);
    return;
  }
  busy(true, reason);
  armSmartLock()
    .then(() => say(`${reason} Smart Lock is armed.`))
    .catch(() => lock(reason))
    .finally(() => busy(false));
}

function armIdle() {
  disarmIdle();
  if (unlocked()) {
    idleTimer = setTimeout(() => autoLock("Locked after a few minutes idle."), IDLE_MS);
  }
}

function disarmIdle() {
  clearTimeout(idleTimer);
  idleTimer = null;
}

/// Cleared by every lock, not only by a visibility change: a background timer
/// armed before the vault was Smart Locked would otherwise come due afterwards
/// and throw the bundle away, sixty seconds after the user asked for it.
function disarmHidden() {
  clearTimeout(hiddenTimer);
  hiddenTimer = null;
}

function onActivity() {
  if (unlocked()) armIdle();
}

function onVisibility() {
  disarmHidden();
  if (document.visibilityState !== "hidden" || !unlocked()) return;
  hiddenTimer = setTimeout(
    () => autoLock("Locked while the page was in the background."), HIDDEN_GRACE_MS,
  );
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

/// The one clipboard path: a field's value, or the generator's password.
async function copyText(value) {
  try {
    await navigator.clipboard.writeText(value);
    clearClipboardSoon();
    say("Copied. The clipboard clears in 30 seconds.");
  } catch {
    say("This browser would not let the page use the clipboard.", "error");
  }
}

async function copyField(id) {
  const value = $(id).value;
  if (!value) return;
  await copyText(value);
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

  $("open-new").addEventListener("click", beginCreate);
  $("open-create-add").addEventListener("click", addQuestionRow);
  $("open-create-show").addEventListener("change", toggleCreateAnswers);
  $("open-create-form").addEventListener("submit", createNew);

  $("open-first-form").addEventListener("submit", revealQuestions);
  $("open-rest-form").addEventListener("submit", unlock);
  for (const button of document.querySelectorAll("[data-action='cancel']")) {
    button.addEventListener("click", () => lock(""));
  }

  for (const id of ["open-search", "open-tag", "open-hidden"]) {
    $(id).addEventListener("input", renderEntries);
  }
  $("open-add").addEventListener("click", () => editEntry(-1));
  $("open-smart-arm").addEventListener("click", () => attempt("Locking…", async () => {
    await armSmartLock();
    say("Smart Lock is armed. One answer re-opens this vault.");
  }));
  $("open-lock").addEventListener("click", () => lock());

  $("open-smart-form").addEventListener("submit", smartUnlock);
  $("open-smart-full").addEventListener("click", () => lock());

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

  $("entry-generate").addEventListener("click", openPassgen);
  for (const id of ["passgen-length", "passgen-upper", "passgen-lower",
    "passgen-numbers", "passgen-symbols"]) {
    $(id).addEventListener("input", onPassgenControl);
  }
  $("passgen-generate").addEventListener("click", regeneratePassgen);
  $("passgen-copy").addEventListener("click", copyPassgen);
  $("passgen-use").addEventListener("click", usePassgen);
  $("passgen-close").addEventListener("click", closePassgen);

  $("open-save-server").addEventListener("click", saveToServer);
  $("open-save-download").addEventListener("click", saveDownload);

  document.addEventListener("visibilitychange", onVisibility);
  for (const event of ["pointerdown", "keydown"]) {
    document.addEventListener(event, onActivity, { passive: true });
  }
  window.addEventListener("beforeunload", (e) => {
    // A Smart Locked vault still owes whatever it owed when it was armed, and
    // closing the tab is the end of the bundle as much as of the entries.
    if (!state.dirty && !smart?.dirty) return;
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
