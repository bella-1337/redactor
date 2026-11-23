// PII review page. All user data is rendered with textContent, never as HTML.

const MAX_ROWS_PER_GROUP = 200;
const OPERATOR_LABELS = { replace: "Replace with type", mask: "Mask with *", redact: "Remove" };
const $ = (id) => document.getElementById(id);

const state = {
  config: null,
  file: null,
  text: "",
  detections: [], // {id, entity_type, start, end, score, recognizer, selected}
  typeOperators: {}, // entity_type -> "" (use default) | operator
};

function el(tag, props = {}, children = []) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (key === "text") node.textContent = value;
    else if (key === "class") node.className = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else if (key in node) node[key] = value;
    else node.setAttribute(key, value);
  }
  for (const child of children) node.append(child);
  return node;
}

function setStatus(id, message, isError = false) {
  const node = $(id);
  node.textContent = message;
  node.classList.toggle("error", isError);
}

function formatBytes(bytes) {
  return bytes >= 1048576 ? `${(bytes / 1048576).toFixed(1)} MiB` : `${Math.round(bytes / 1024)} KiB`;
}

async function api(path, body, file = null) {
  const key = $("api-key").value.trim();
  if (!key) throw new Error("Enter your LiteLLM virtual key first.");
  // A file goes as the raw request body; only its extension is used server side.
  const headers = file
    ? { "Content-Type": "application/octet-stream", "X-File-Name": encodeURIComponent(file.name), Authorization: `Bearer ${key}` }
    : { "Content-Type": "application/json", Authorization: `Bearer ${key}` };
  let response;
  try {
    response = await fetch(path, {
      method: "POST",
      headers,
      body: file || JSON.stringify(body),
      credentials: "omit",
      cache: "no-store",
      referrerPolicy: "no-referrer",
    });
  } catch {
    throw new Error("The service could not be reached.");
  }
  let payload = null;
  try {
    payload = await response.json();
  } catch {
    payload = null;
  }
  if (!response.ok) {
    throw new Error((payload && typeof payload.error === "string" && payload.error) || `Request failed (${response.status}).`);
  }
  return payload;
}

// -- input ------------------------------------------------------------------

function extensionOf(name) {
  const dot = name.lastIndexOf(".");
  return dot >= 0 ? name.slice(dot).toLowerCase() : "";
}

function describeFileSupport() {
  const config = state.config;
  if (!config) return;
  const types = config.documents
    ? [...config.text_extensions, ...config.document_extensions]
    : config.text_extensions;
  $("input-file").accept = types.join(",");
  const documents = config.documents
    ? ` Images and scanned PDF pages are read with OCR (${(config.ocr_languages || []).join(", ")}).`
    : " Office, PDF, and image files are not available on this server.";
  $("file-hint").textContent = `Supported: ${types.join(" ")} up to ${formatBytes(config.max_file_bytes)}.${documents}`;
}

function onFileChosen() {
  const file = $("input-file").files[0] || null;
  state.file = null;
  $("clear-file").hidden = !file;
  if (!file) return;
  const config = state.config;
  const allowed = config ? [...config.text_extensions, ...(config.documents ? config.document_extensions : [])] : [];
  if (config && !allowed.includes(extensionOf(file.name))) {
    setStatus("analyze-status", "That file type is not supported.", true);
    clearFile();
    return;
  }
  if (config && file.size > config.max_file_bytes) {
    setStatus("analyze-status", `The document is larger than ${formatBytes(config.max_file_bytes)}.`, true);
    clearFile();
    return;
  }
  state.file = file;
  setStatus("analyze-status", "The document will be analysed instead of the pasted text.");
}

function clearFile() {
  $("input-file").value = "";
  state.file = null;
  $("clear-file").hidden = true;
}

async function analyze() {
  const button = $("analyze");
  button.disabled = true;
  setStatus("analyze-status", state.file ? "Reading the document and analysing…" : "Analysing…");
  $("result").hidden = true;
  try {
    const result = state.file
      ? await api("/api/analyze-document", null, state.file)
      : await api("/api/analyze", { text: $("input-text").value });
    state.text = result.text;
    state.detections = result.detections.map((item) => ({ ...item, selected: true }));
    state.typeOperators = {};
    // OCR can misread or split names and numbers so that they are not detected.
    $("ocr-note").hidden = !result.ocr;
    setStatus("analyze-status", "");
    renderReview();
    $("review").hidden = false;
    $("review").scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (error) {
    setStatus("analyze-status", error.message, true);
  } finally {
    button.disabled = false;
  }
}

// -- review -----------------------------------------------------------------

function groupsByType() {
  const groups = new Map();
  for (const item of state.detections) {
    if (!groups.has(item.entity_type)) groups.set(item.entity_type, []);
    groups.get(item.entity_type).push(item);
  }
  return [...groups.entries()].sort((a, b) => b[1].length - a[1].length || a[0].localeCompare(b[0]));
}

function snippet(item) {
  const before = state.text.slice(Math.max(0, item.start - 30), item.start).replace(/\s+/g, " ");
  const value = state.text.slice(item.start, item.end);
  const after = state.text.slice(item.end, item.end + 30).replace(/\s+/g, " ");
  return [before ? `…${before}` : "", value.length > 120 ? `${value.slice(0, 120)}…` : value, after ? `${after}…` : ""];
}

function renderSummary() {
  const selected = state.detections.filter((item) => item.selected).length;
  const types = new Set(state.detections.map((item) => item.entity_type)).size;
  $("summary").textContent = state.detections.length
    ? `Found ${state.detections.length} item(s) of ${types} type(s); ${selected} selected for masking.`
    : "No personal data was detected. You can still add terms to mask below.";
}

function renderGroups() {
  const container = $("groups");
  container.replaceChildren();
  for (const [type, items] of groupsByType()) {
    const selectedCount = items.filter((item) => item.selected).length;
    const toggle = el("input", {
      type: "checkbox",
      checked: selectedCount === items.length,
      indeterminate: selectedCount > 0 && selectedCount < items.length,
      "aria-label": `Mask every ${type}`,
      onchange: (event) => {
        for (const item of items) item.selected = event.target.checked;
        renderReview();
      },
    });
    const operator = el(
      "select",
      {
        "aria-label": `How to mask ${type}`,
        onchange: (event) => {
          state.typeOperators[type] = event.target.value;
        },
      },
      [el("option", { value: "", text: "Default" }), ...Object.entries(OPERATOR_LABELS).map(([value, text]) => el("option", { value, text }))],
    );
    operator.value = state.typeOperators[type] || "";
    // Long lists show their first rows; the group checkbox still covers all.
    const rows = items.slice(0, MAX_ROWS_PER_GROUP).map((item) => {
      const [before, value, after] = snippet(item);
      return el("li", { class: item.selected ? "row selected" : "row" }, [
        el("label", {}, [
          el("input", {
            type: "checkbox",
            checked: item.selected,
            onchange: (event) => {
              item.selected = event.target.checked;
              renderReview();
            },
          }),
          el("span", { class: "context" }, [before, el("mark", { text: value }), after]),
        ]),
        el("span", { class: "score", title: item.recognizer ? `Detected by ${item.recognizer}` : "", text: `${Math.round(item.score * 100)}%` }),
      ]);
    });
    const details = el("details", { class: "group", open: items.length <= 20 }, [
      el("summary", {}, [
        toggle,
        el("span", { class: "type", text: type }),
        el("span", { class: "count", text: `${selectedCount}/${items.length}` }),
        operator,
      ]),
      el("ul", {}, rows),
      ...(items.length > MAX_ROWS_PER_GROUP
        ? [el("p", { class: "hint more", text: `Showing the first ${MAX_ROWS_PER_GROUP} of ${items.length}. Use the checkbox above to include or exclude them all.` })]
        : []),
    ]);
    // Clicks on the controls must not open or close the group.
    toggle.addEventListener("click", (event) => event.stopPropagation());
    operator.addEventListener("click", (event) => event.stopPropagation());
    container.append(details);
  }
}

function renderPreview() {
  const preview = $("preview");
  const parts = [];
  let cursor = 0;
  // Very long texts: only the beginning is drawn, but everything is masked.
  const limit = Math.min(state.text.length, (state.config && state.config.preview_chars) || 1000000);
  // Overlapping detections still appear in the list; the preview shows the first.
  for (const item of state.detections) {
    if (item.start >= limit) break;
    if (item.start < cursor) continue;
    if (item.start > cursor) parts.push(state.text.slice(cursor, item.start));
    parts.push(
      el("mark", {
        class: item.selected ? "hit selected" : "hit",
        title: `${item.entity_type} · ${Math.round(item.score * 100)}%`,
        text: state.text.slice(item.start, item.end),
        onclick: () => {
          item.selected = !item.selected;
          renderReview();
        },
      }),
    );
    cursor = item.end;
  }
  parts.push(state.text.slice(cursor, Math.max(cursor, limit)));
  if (limit < state.text.length) {
    parts.push(el("span", { class: "more", text: `\n\n… the preview stops here; the other ${(state.text.length - limit).toLocaleString()} characters are analysed and masked too.` }));
  }
  preview.replaceChildren(...parts);
}

function renderReview() {
  renderSummary();
  renderGroups();
  renderPreview();
}

function setAll(selected) {
  for (const item of state.detections) item.selected = selected;
  renderReview();
}

async function mask() {
  const button = $("mask");
  button.disabled = true;
  setStatus("mask-status", "Masking…");
  try {
    const operators = { DEFAULT: $("default-operator").value };
    for (const [type, operator] of Object.entries(state.typeOperators)) {
      if (operator) operators[type] = operator;
    }
    const result = await api("/api/mask", {
      text: state.text,
      selections: state.detections
        .filter((item) => item.selected)
        .map(({ entity_type, start, end, score }) => ({ entity_type, start, end, score })),
      custom_terms: $("custom-terms").value.split("\n").map((line) => line.trim()).filter(Boolean),
      operators,
    });
    $("output").value = result.masked_text;
    const counts = Object.entries(result.counts || {});
    const total = counts.reduce((sum, [, count]) => sum + count, 0);
    $("result-summary").textContent = total
      ? `${total} item(s) masked: ${counts.map(([type, count]) => `${type} ${count}`).join(", ")}.`
      : "Nothing was selected, so the text is unchanged.";
    setStatus("mask-status", "");
    setStatus("copy-status", "");
    $("result").hidden = false;
    $("result").scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (error) {
    setStatus("mask-status", error.message, true);
  } finally {
    button.disabled = false;
  }
}

async function copyResult() {
  try {
    await navigator.clipboard.writeText($("output").value);
    setStatus("copy-status", "Copied.");
  } catch {
    $("output").select();
    setStatus("copy-status", "Select the text and copy it manually.", true);
  }
}

function downloadResult() {
  const blob = new Blob([$("output").value], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = el("a", { href: url, download: "masked.txt" });
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function loadConfig() {
  try {
    const response = await fetch("/api/config", { cache: "no-store", credentials: "omit" });
    if (response.ok) state.config = await response.json();
  } catch {
    state.config = null;
  }
  describeFileSupport();
}

$("input-file").addEventListener("change", onFileChosen);
$("clear-file").addEventListener("click", () => {
  clearFile();
  setStatus("analyze-status", "");
});
$("analyze").addEventListener("click", analyze);
$("select-all").addEventListener("click", () => setAll(true));
$("select-none").addEventListener("click", () => setAll(false));
$("mask").addEventListener("click", mask);
$("copy").addEventListener("click", copyResult);
$("download").addEventListener("click", downloadResult);
loadConfig();
