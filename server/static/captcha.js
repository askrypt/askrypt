/*
 * reCAPTCHA v3 for the sign-in and registration forms.
 *
 * Loaded only by `auth_page.html`, and only when a site key is configured.
 * An external file rather than an inline script because the CSP forbids
 * inline script even on the two pages that carry the widened policy; the
 * site key therefore arrives on the hidden input as a data attribute.
 *
 * Why tokens are minted ahead of the submit rather than during it: htmx
 * serializes the form synchronously, and `grecaptcha.execute` is a promise.
 * There is no hook that can await one and still let the request go out, so
 * the field is kept freshly populated instead — on load, on a timer, and
 * after every htmx swap. A v3 token lasts two minutes and is single-use,
 * which is what each of those three cases is about:
 *
 *   - load    — the first submit has a token to send.
 *   - timer   — a form left open past two minutes still works.
 *   - swap    — a refused submit spends its token and htmx replaces the
 *               whole form, so the new field starts out empty.
 *
 * When a mint fails the field is cleared rather than left stale: an expired
 * token would be refused anyway, and an empty one gets the same message.
 */
(function () {
  "use strict";

  /* Comfortably inside the two-minute lifetime. */
  var REFRESH_MS = 90 * 1000;
  /* `api.js` defines `grecaptcha` on its own schedule; poll briefly for it
     rather than assuming script order held. */
  var READY_RETRY_MS = 200;
  var READY_ATTEMPTS = 50;

  function fields() {
    return document.querySelectorAll("input[data-captcha-key]");
  }

  function fill(field) {
    var key = field.getAttribute("data-captcha-key");
    var action = field.getAttribute("data-captcha-action");
    if (!key || !action) {
      return;
    }
    window.grecaptcha.execute(key, { action: action }).then(
      function (token) {
        field.value = token;
      },
      function () {
        field.value = "";
      }
    );
  }

  function refresh() {
    if (!window.grecaptcha || !window.grecaptcha.execute) {
      return;
    }
    Array.prototype.forEach.call(fields(), fill);
  }

  function whenReady(attempts) {
    if (window.grecaptcha && window.grecaptcha.ready) {
      window.grecaptcha.ready(refresh);
      return;
    }
    if (attempts <= 0) {
      return;
    }
    window.setTimeout(function () {
      whenReady(attempts - 1);
    }, READY_RETRY_MS);
  }

  whenReady(READY_ATTEMPTS);
  window.setInterval(refresh, REFRESH_MS);
  /* Delegated from the document: the form this listener would otherwise be
     bound to is the very element htmx replaces. */
  document.addEventListener("htmx:afterSwap", refresh);
})();
