// Splash screen while the engine starts. The shell calls
// window.piiReviewSplash.status(text); a first status can come as
// ?status=<text> (on a restart), errors as ?error=<text>.
// Everything is shown with textContent, never as HTML.

const $ = (id) => document.getElementById(id);

function status(text) {
  $("status").textContent = text;
}

function error(text) {
  $("spinner").hidden = true;
  $("hint").hidden = true;
  $("status").textContent = "PII Review could not start.";
  $("error").textContent = text;
  $("error").hidden = false;
}

window.piiReviewSplash = Object.freeze({ status, error });

const query = new URLSearchParams(window.location.search);
const first = query.get("status");
if (first) status(first);

const pending = window.piiReviewPending;
if (Array.isArray(pending) && pending[0] === "status") status(String(pending[1]));

const failure = query.get("error");
if (failure) error(failure);
