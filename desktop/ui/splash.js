// Splash screen while the engine starts. The shell calls
// window.piiReviewSplash.status(text); errors arrive as ?error=<text>.
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

const pending = window.piiReviewPending;
if (Array.isArray(pending) && pending[0] === "status") status(String(pending[1]));

const failure = new URLSearchParams(window.location.search).get("error");
if (failure) error(failure);
