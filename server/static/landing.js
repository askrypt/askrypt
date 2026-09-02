/*
 * The landing page's typing demo: a strong master password typed out, the
 * question it raises, and the answers you already know flashed past.
 *
 * It lives here rather than in a <script> block because the CSP is
 * `script-src 'self'` with no 'unsafe-inline' (see server/src/hardening.rs),
 * and it is written as a plain script with no imports and no dependencies,
 * like the rest of server/static/.
 *
 * Progressive enhancement, in both directions: the panel's markup already
 * carries every line in full, so a visitor without JavaScript reads the same
 * message all at once, and a visitor who asked for reduced motion gets that
 * static reading too — the script simply never starts. Once it does start it
 * marks the panel `aria-hidden`, because a screen reader is served by the
 * transcript beside it rather than by text that arrives a character at a
 * time.
 */

const TYPE_MS = 55; // per character, for the password
const NOTE_MS = 24; // per character, for the sentences under it
const QUESTION_MS = 240; // between questions, once they start
const HOLD_MS = 5200; // how long the finished panel stays up
const FADE_MS = 500;

/** Whether the panel is on screen; the loop parks itself when it is not. */
let inView = true;

const panel = document.querySelector("[data-landing-demo]");
const reduced = window.matchMedia("(prefers-reduced-motion: reduce)");

// Started here, below everything it reads: `run` is synchronous up to its
// first await, so a `let` declared after this line would still be in its
// temporal dead zone when the loop first asks whether the panel is visible.
if (panel && !reduced.matches) {
  run(panel);
}

async function run(panel) {
  const secret = panel.querySelector("[data-demo-secret]");
  const verdict = panel.querySelector("[data-demo-verdict]");
  const notes = Array.from(panel.querySelectorAll("[data-demo-note]"));
  const questions = Array.from(panel.querySelectorAll("[data-demo-question]"));
  const close = panel.querySelector("[data-demo-close]");
  if (!secret || !verdict || notes.length === 0 || questions.length === 0) {
    return;
  }

  // The final text is what the markup shipped with; the script only replays
  // it, so the two can never drift. Runs of whitespace collapse first — a
  // template wraps its sentences, and typing the indentation that follows a
  // newline would stall the caret on characters that render as one space.
  const typed = [secret].concat(notes);
  const script = new Map(
    typed.map((el) => [el, el.textContent.replace(/\s+/g, " ").trim()]),
  );
  const revealed = [verdict].concat(questions);
  if (close) {
    revealed.push(close);
  }

  panel.setAttribute("aria-hidden", "true");
  panel.classList.add("is-live");
  watch(panel);
  reserve(script);
  window.addEventListener("resize", () => reserve(script));

  for (;;) {
    for (const el of typed) {
      el.textContent = "";
      el.classList.remove("is-typing", "is-shown");
    }
    for (const el of revealed) {
      el.classList.remove("is-shown");
    }
    panel.classList.remove("is-fading");

    await awake();
    await sleep(700);
    await type(secret, script.get(secret), TYPE_MS);
    await sleep(400);
    show(verdict);
    await sleep(900);

    for (const note of notes) {
      show(note);
      await type(note, script.get(note), NOTE_MS);
      await sleep(750);
    }

    for (const question of questions) {
      show(question);
      await sleep(QUESTION_MS);
    }
    if (close) {
      await sleep(500);
      show(close);
    }

    await sleep(HOLD_MS);
    panel.classList.add("is-fading");
    await sleep(FADE_MS);
  }
}

function show(el) {
  el.classList.add("is-shown");
}

/**
 * Hold each typed line at the height its finished text needs. A sentence
 * wraps to a second line partway through being typed, and without this the
 * panel — and the hero laid out beside it — grows by a line as it does. The
 * height comes from the markup's own text, so it follows the column width;
 * hence the re-measure on resize.
 */
function reserve(script) {
  for (const [el, text] of script) {
    const typed = el.textContent;
    el.style.minHeight = "";
    el.textContent = text;
    const height = el.getBoundingClientRect().height;
    el.textContent = typed;
    el.style.minHeight = `${Math.ceil(height)}px`;
  }
}

/** Type `text` into `el` one character at a time, carrying the caret. */
async function type(el, text, pace) {
  el.classList.add("is-typing");
  for (const char of text) {
    el.textContent += char;
    // A flat cadence reads as a machine printing; the jitter is what makes it
    // read as someone at a keyboard.
    await sleep(pace + Math.random() * pace);
  }
  el.classList.remove("is-typing");
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Resolve once the panel is both on screen and in a foreground tab. */
async function awake() {
  while (document.hidden || !inView) {
    await sleep(400);
  }
}

function watch(el) {
  if (typeof IntersectionObserver !== "function") {
    return;
  }
  const observer = new IntersectionObserver(
    (entries) => {
      for (const entry of entries) {
        inView = entry.isIntersecting;
      }
    },
    { threshold: 0.25 },
  );
  observer.observe(el);
}
