/*
 * "Sign in with Google" for the sign-in and registration forms.
 *
 * Loaded only by `auth_page.html`, and only when a web client id is
 * configured. An external file rather than an inline script because the CSP
 * forbids inline script even on the two pages that carry the widened policy;
 * the client id therefore arrives on the button's container as a data
 * attribute, and the callback is a function this file defines rather than a
 * global name a `<script>` block would set.
 *
 * What it does is deliberately small. Google Identity Services draws the
 * button and runs the sign-in popup; when that yields a credential — a signed
 * ID token — this fills it into the hidden field of the little form beside the
 * button and submits it to our own origin. Everything after that is ordinary
 * server-rendered navigation: the POST carries the page's CSRF token, and the
 * server answers with a redirect.
 *
 * Two things it has to survive:
 *
 *   - htmx swaps. A refused submit replaces the whole `#auth-form` card, so
 *     the container and the form are new elements and the button has to be
 *     drawn again. The listener is on `document` for exactly that reason —
 *     the element it would otherwise be bound to is the one htmx replaces.
 *   - load order. `gsi/client` is deferred like this file, so it may not have
 *     defined `google.accounts.id` yet; we poll briefly rather than assume.
 */
(function () {
  "use strict";

  /* Matches `captcha.js`: the library defines itself on its own schedule. */
  var READY_RETRY_MS = 200;
  var READY_ATTEMPTS = 50;
  /* Marks a container whose button has already been drawn, so a swap
     elsewhere on the page doesn't stack a second one into it. */
  var RENDERED = "data-google-rendered";

  var initialized = false;

  function container() {
    return document.querySelector("[data-google-client-id]");
  }

  /* Google hands us `{credential, select_by}`. Anything else — a dismissed
     popup, a shape from a future version — is not a sign-in and is ignored. */
  function submit(response) {
    if (!response || !response.credential) {
      return;
    }
    var form = document.getElementById("google-form");
    var field = document.getElementById("google-credential");
    if (!form || !field) {
      return;
    }
    field.value = response.credential;
    /* `requestSubmit` so the browser treats it as a real submission;
       `submit` is the fallback for anything that lacks it. */
    if (typeof form.requestSubmit === "function") {
      form.requestSubmit();
    } else {
      form.submit();
    }
  }

  function render() {
    var el = container();
    if (!el || el.hasAttribute(RENDERED)) {
      return;
    }
    if (!window.google || !window.google.accounts || !window.google.accounts.id) {
      return;
    }
    if (!initialized) {
      window.google.accounts.id.initialize({
        client_id: el.getAttribute("data-google-client-id"),
        callback: submit,
        /* A popup, not a redirect: a redirect would post the credential to us
           cross-site, where none of our SameSite=Lax cookies — the CSRF token
           among them — would be sent. See `web::google`. */
        ux_mode: "popup",
        /* Never sign someone in just because they landed on the page. */
        auto_select: false,
        cancel_on_tap_outside: true
      });
      initialized = true;
    }
    window.google.accounts.id.renderButton(el, {
      type: "standard",
      theme: "outline",
      size: "large",
      shape: "rectangular",
      logo_alignment: "left",
      text: el.getAttribute("data-google-text") || "signin_with"
    });
    el.setAttribute(RENDERED, "true");
  }

  function whenReady(attempts) {
    render();
    if (initialized || attempts <= 0) {
      return;
    }
    window.setTimeout(function () {
      whenReady(attempts - 1);
    }, READY_RETRY_MS);
  }

  whenReady(READY_ATTEMPTS);
  document.addEventListener("htmx:afterSwap", render);
})();
