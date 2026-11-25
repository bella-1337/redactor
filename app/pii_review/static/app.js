// PII review page. All user data is rendered with textContent, never as HTML.

import { Decoration, EditorState, EditorView, RangeSetBuilder, StateEffect, ViewPlugin, keymap, search, searchKeymap } from "/codemirror.js";

const LANGUAGE_NAMES = { en: "English", de: "German", fr: "French" };
// Finds scored below this are marked "Unsure" (Presidio's spaCy and the local
// model score 0.8 and more; weak pattern matches score well below).
const UNSURE_SCORE = 0.6;
const ROWS_PER_PAGE = 100; // words drawn at a time; "Show more" adds the next page
const PLACES_PER_PAGE = 50; // places drawn per expanded word
const UNDO_LIMIT = 200;
const $ = (id) => document.getElementById(id);

// The desktop app opens the page with its per-run token in the URL fragment,
// which the browser never sends to a server. It stays there so a reload keeps it.
const LOCAL_TOKEN = new URLSearchParams(window.location.hash.slice(1)).get("token") || "";

const state = {
  config: null,
  file: null,
  text: "",
  languages: {}, // language -> characters analysed in it
  detections: [], // {entity_type, start, end, score}, sorted by start, one per span
  masked: new Uint8Array(0), // detection index -> 1 when it will be masked
  groups: [], // one per distinct word: {label, ids, maskedCount, unsure}
  groupOf: new Int32Array(0), // detection index -> group index
  visible: [], // group indices that pass the search and filter, in list order
  shownRows: ROWS_PER_PAGE,
  checked: new Set(), // group indices ticked for a bulk action
  anchor: -1, // position in `visible` of the last ticked row, for Shift-click
  expanded: new Map(), // group index -> places drawn
  rows: new Map(), // group index -> its list row, while drawn
  longestFind: 0, // characters in the longest find, to look up finds in view
  flash: -1, // detection index outlined in the preview after "Show in text"
  undo: [], // {ids: Int32Array, value}: the detections a decision changed
  redo: [],
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

const formatCount = (count) => count.toLocaleString();
const plural = (count, one, many) => `${formatCount(count)} ${count === 1 ? one : many}`;

function localAuth() {
  return Boolean(state.config && state.config.auth === "local");
}

async function api(path, body, file = null) {
  const key = localAuth() ? LOCAL_TOKEN : $("api-key").value.trim();
  if (!key) throw new Error(localAuth() ? "This window lost its session. Restart PII Review." : "Enter your LiteLLM virtual key first.");
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
    loadResult(result);
    // OCR can misread or split names and numbers so that they are not detected.
    $("ocr-note").hidden = !result.ocr;
    setStatus("analyze-status", "");
    $("review").hidden = false;
    $("review").scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (error) {
    setStatus("analyze-status", error.message, true);
  } finally {
    button.disabled = false;
  }
}

// -- decisions ----------------------------------------------------------------
//
// Every find starts out masked. Decisions are made per word: a word's Mask or
// Keep applies to every place it appears, and a place can be changed on its own.

// The same word in other capitals or with other spacing is one word.
function wordKey(value) {
  return value.replace(/\s+/g, " ").trim().toLocaleLowerCase();
}

function loadResult(result) {
  state.text = result.text;
  state.languages = result.languages || {};

  // One find per span: the same span found twice (by two recognizers) is one
  // place. The server masks overlapping spans as one anyway.
  const bySpan = new Map();
  for (const item of result.detections) {
    const span = `${item.start}:${item.end}`;
    const known = bySpan.get(span);
    if (!known || item.score > known.score) bySpan.set(span, item);
  }
  state.detections = [...bySpan.values()]
    .map(({ entity_type, start, end, score }) => ({ entity_type, start, end, score }))
    .sort((a, b) => a.start - b.start || b.end - a.end);
  state.masked = new Uint8Array(state.detections.length).fill(1);
  state.longestFind = state.detections.reduce((longest, item) => Math.max(longest, item.end - item.start), 0);
  state.flash = -1;

  const groups = new Map();
  state.groupOf = new Int32Array(state.detections.length);
  state.detections.forEach((item, id) => {
    const value = state.text.slice(item.start, item.end);
    const key = wordKey(value);
    let group = groups.get(key);
    if (!group) {
      group = { label: value.replace(/\s+/g, " ").trim(), ids: [], maskedCount: 0, best: 0 };
      groups.set(key, group);
    }
    group.ids.push(id);
    group.maskedCount += 1;
    group.best = Math.max(group.best, item.score);
  });
  state.groups = [...groups.values()]
    .map((group) => ({ ...group, unsure: group.best < UNSURE_SCORE }))
    .sort((a, b) => b.ids.length - a.ids.length || a.label.localeCompare(b.label));
  state.groups.forEach((group, index) => {
    for (const id of group.ids) state.groupOf[id] = index;
  });

  state.undo = [];
  state.redo = [];
  state.checked.clear();
  state.expanded.clear();
  state.anchor = -1;
  $("word-search").value = "";
  $("word-filter").value = "all";
  applyFilter();
  renderPreview();
  renderSummary();
}

// Sets the given finds to masked (1) or kept (0), as one step that can be undone.
function decide(ids, value) {
  const changed = setMasked(ids, value);
  if (!changed.length) return;
  state.undo.push({ ids: changed, value });
  if (state.undo.length > UNDO_LIMIT) state.undo.shift();
  state.redo = [];
  afterChange(changed);
}

function setMasked(ids, value) {
  const changed = [];
  for (const id of ids) {
    if (state.masked[id] === value) continue;
    state.masked[id] = value;
    state.groups[state.groupOf[id]].maskedCount += value ? 1 : -1;
    changed.push(id);
  }
  return Int32Array.from(changed);
}

function undo() {
  const step = state.undo.pop();
  if (!step) return;
  setMasked(step.ids, step.value ? 0 : 1);
  state.redo.push(step);
  afterChange(step.ids);
}

function redo() {
  const step = state.redo.pop();
  if (!step) return;
  setMasked(step.ids, step.value);
  state.undo.push(step);
  afterChange(step.ids);
}

// Redraws only what a decision touched: the highlights in view, its rows, the summary.
function afterChange(ids) {
  const groups = new Set();
  for (const id of ids) groups.add(state.groupOf[id]);
  for (const group of groups) updateRow(group);
  refreshPreview();
  renderSummary();
}

function groupState(group) {
  if (group.maskedCount === group.ids.length) return "masked";
  return group.maskedCount === 0 ? "kept" : "partly";
}

// -- word list --------------------------------------------------------------

const FILTERS = {
  all: { label: "All words", test: () => true },
  unsure: { label: "Unsure", test: (group) => group.unsure },
  masked: { label: "Masked", test: (group) => groupState(group) === "masked" },
  kept: { label: "Kept", test: (group) => groupState(group) === "kept" },
  partly: { label: "Partly masked", test: (group) => groupState(group) === "partly" },
};

// The list is filtered when the search or filter changes, not after each
// decision, so a word does not vanish from under the pointer when it is kept.
function applyFilter() {
  const query = wordKey($("word-search").value);
  const filter = FILTERS[$("word-filter").value] || FILTERS.all;
  state.visible = [];
  state.groups.forEach((group, index) => {
    if (filter.test(group) && (!query || wordKey(group.label).includes(query))) state.visible.push(index);
  });
  const visible = new Set(state.visible);
  for (const index of state.checked) if (!visible.has(index)) state.checked.delete(index);
  state.anchor = -1;
  state.shownRows = ROWS_PER_PAGE;
  renderWords();
}

function renderWords() {
  const list = $("words");
  state.rows.clear();
  const rows = state.visible.slice(0, state.shownRows).map((index) => buildRow(index));
  list.replaceChildren(...rows);
  if (!state.groups.length) {
    list.append(el("li", { class: "empty", text: "Nothing was found. You can still add terms to mask below." }));
  } else if (!state.visible.length) {
    list.append(el("li", { class: "empty", text: "No words match the search or filter." }));
  }
  const remaining = state.visible.length - state.shownRows;
  $("more-words").hidden = remaining <= 0;
  $("more-words").textContent = `Show ${formatCount(Math.min(remaining, ROWS_PER_PAGE))} more of ${formatCount(Math.max(remaining, 0))}`;
  renderBulk();
}

function buildRow(index) {
  const group = state.groups[index];
  const check = el("input", {
    type: "checkbox",
    class: "pick",
    "aria-label": `Select “${group.label}”`,
    onclick: (event) => togglePick(index, event.target.checked, event.shiftKey),
  });
  const expand = el("button", {
    type: "button",
    class: "expand",
    "aria-expanded": "false",
    "aria-label": `Show where “${group.label}” appears`,
    onclick: () => toggleExpanded(index),
  });
  const choice = el("span", { class: "choice", role: "group", "aria-label": `Mask or keep “${group.label}”` }, [
    el("button", { type: "button", class: "mask", text: "Mask", onclick: () => decide(group.ids, 1) }),
    el("button", { type: "button", class: "keep", text: "Keep", onclick: () => decide(group.ids, 0) }),
  ]);
  const row = el("li", { class: "word-row" }, [
    el("div", { class: "word-head" }, [
      check,
      expand,
      el("span", { class: "word", text: group.label, title: group.label }),
      ...(group.unsure ? [el("span", { class: "badge", text: "Unsure", title: "Detection is not confident about this one" })] : []),
      el("span", { class: "count" }),
      choice,
    ]),
    el("ul", { class: "places", hidden: true }),
  ]);
  state.rows.set(index, row);
  updateRow(index);
  return row;
}

function updateRow(index) {
  const row = state.rows.get(index);
  if (!row) return;
  const group = state.groups[index];
  const current = groupState(group);
  row.className = `word-row ${current}`;
  row.querySelector(".pick").checked = state.checked.has(index);
  const total = group.ids.length;
  row.querySelector(".count").textContent =
    current === "partly" ? `${formatCount(group.maskedCount)} of ${plural(total, "place", "places")} masked` : plural(total, "place", "places");
  row.querySelector(".mask").setAttribute("aria-pressed", String(current === "masked"));
  row.querySelector(".keep").setAttribute("aria-pressed", String(current === "kept"));
  const expanded = state.expanded.has(index);
  row.querySelector(".expand").setAttribute("aria-expanded", String(expanded));
  const places = row.querySelector(".places");
  places.hidden = !expanded;
  if (expanded) renderPlaces(index, places);
}

function toggleExpanded(index) {
  if (state.expanded.has(index)) state.expanded.delete(index);
  else state.expanded.set(index, PLACES_PER_PAGE);
  updateRow(index);
}

function snippet(item) {
  const before = state.text.slice(Math.max(0, item.start - 40), item.start).replace(/\s+/g, " ");
  const value = state.text.slice(item.start, item.end);
  const after = state.text.slice(item.end, item.end + 40).replace(/\s+/g, " ");
  return [before ? `…${before}` : "", value.length > 120 ? `${value.slice(0, 120)}…` : value, after ? `${after}…` : ""];
}

function renderPlaces(index, container) {
  const group = state.groups[index];
  const shown = state.expanded.get(index);
  const items = group.ids.slice(0, shown).map((id) => {
    const [before, value, after] = snippet(state.detections[id]);
    return el("li", { class: state.masked[id] ? "place masked" : "place kept" }, [
      el("label", {}, [
        el("input", { type: "checkbox", checked: Boolean(state.masked[id]), onchange: (event) => decide([id], event.target.checked ? 1 : 0) }),
        el("span", { class: "context" }, [before, el("mark", { text: value }), after]),
      ]),
      el("button", { type: "button", class: "link", text: "Show in text", onclick: () => showInText(id) }),
    ]);
  });
  if (group.ids.length > shown) {
    items.push(
      el("li", { class: "place-more" }, [
        el("button", {
          type: "button",
          class: "link",
          text: `Show ${formatCount(Math.min(group.ids.length - shown, PLACES_PER_PAGE))} more places`,
          onclick: () => {
            state.expanded.set(index, shown + PLACES_PER_PAGE);
            updateRow(index);
          },
        }),
      ]),
    );
  }
  container.replaceChildren(...items);
}

// -- bulk actions -------------------------------------------------------------

function togglePick(index, picked, range) {
  const position = state.visible.indexOf(index);
  const indices = range && state.anchor >= 0 && position >= 0
    ? state.visible.slice(Math.min(state.anchor, position), Math.max(state.anchor, position) + 1)
    : [index];
  for (const each of indices) {
    if (picked) state.checked.add(each);
    else state.checked.delete(each);
    updateRow(each);
  }
  state.anchor = position;
  renderBulk();
}

function pickAll(picked) {
  state.checked.clear();
  if (picked) for (const index of state.visible) state.checked.add(index);
  for (const index of state.rows.keys()) updateRow(index);
  renderBulk();
}

function decideChecked(value) {
  const ids = [];
  for (const index of state.checked) ids.push(...state.groups[index].ids);
  decide(ids, value);
}

function renderBulk() {
  const count = state.checked.size;
  const all = $("pick-all");
  all.checked = count > 0 && count === state.visible.length;
  all.indeterminate = count > 0 && count < state.visible.length;
  all.disabled = !state.visible.length;
  $("pick-all-label").textContent = `Select all ${plural(state.visible.length, "word", "words")}`;
  $("bulk-count").textContent = count ? `${plural(count, "word", "words")} selected` : "";
  for (const id of ["mask-picked", "keep-picked", "clear-picked"]) $(id).disabled = !count;
}

function renderUndo() {
  $("undo").disabled = !state.undo.length;
  $("redo").disabled = !state.redo.length;
}

// -- preview and summary --------------------------------------------------------

// The preview is a read-only CodeMirror view of the whole text. CodeMirror
// draws only the lines in view, and the highlights are worked out for those
// lines alone, so a text of any length stays quick to scroll and to change.

const refreshEffect = StateEffect.define();
let previewView = null;

// Index of the first find that starts at or after `position`.
function firstFindFrom(position) {
  let low = 0;
  let high = state.detections.length;
  while (low < high) {
    const middle = (low + high) >> 1;
    if (state.detections[middle].start < position) low = middle + 1;
    else high = middle;
  }
  return low;
}

function highlightsInView(view) {
  const builder = new RangeSetBuilder();
  for (const { from, to } of view.visibleRanges) {
    // A find that starts before the visible range can still reach into it.
    for (let id = firstFindFrom(from - state.longestFind); id < state.detections.length; id++) {
      const item = state.detections[id];
      if (item.start >= to) break;
      if (item.end <= from) continue;
      const masked = Boolean(state.masked[id]);
      builder.add(
        item.start,
        item.end,
        Decoration.mark({
          class: `hit${masked ? " selected" : ""}${id === state.flash ? " flash" : ""}`,
          attributes: { "data-find": String(id), title: masked ? "Will be masked. Click to keep it." : "Will stay. Click to mask it." },
        }),
      );
    }
  }
  return builder.finish();
}

const highlights = ViewPlugin.fromClass(
  class {
    constructor(view) {
      this.decorations = highlightsInView(view);
    }

    update(update) {
      if (update.viewportChanged || update.transactions.some((tr) => tr.effects.some((effect) => effect.is(refreshEffect)))) {
        this.decorations = highlightsInView(update.view);
      }
    }
  },
  { decorations: (plugin) => plugin.decorations },
);

// The innermost find under the cursor, for the keyboard.
function findAt(position) {
  let found = -1;
  for (let id = firstFindFrom(position - state.longestFind); id < state.detections.length; id++) {
    const item = state.detections[id];
    if (item.start > position) break;
    if (item.end >= position && (found < 0 || item.end - item.start < state.detections[found].end - state.detections[found].start)) found = id;
  }
  return found;
}

function toggleFind(id) {
  if (id >= 0) decide([id], state.masked[id] ? 0 : 1);
  return id >= 0;
}

// The view lives in a shadow root: there CodeMirror adds its styles as a
// constructed style sheet, which the page's CSP (style-src 'self') allows,
// instead of a <style> element, which it blocks. preview.css styles the inside.
function createPreview(host) {
  const shadow = host.attachShadow({ mode: "open" });
  const parent = el("div", { class: "preview-body" });
  shadow.append(el("link", { rel: "stylesheet", href: "/preview.css" }), parent);
  return new EditorView({
    parent,
    root: shadow,
    state: EditorState.create({
      doc: "",
      extensions: [
        EditorState.readOnly.of(true),
        // Only "\n" ends a line, so "\r\n" stays two characters and the
        // positions of the finds match the text exactly.
        EditorState.lineSeparator.of("\n"),
        EditorView.lineWrapping,
        EditorView.contentAttributes.of({ "aria-label": "Preview of the text", spellcheck: "false" }),
        search({ top: true }),
        highlights,
        keymap.of([
          // Enter or Space changes the find at the cursor.
          { key: "Enter", run: (view) => toggleFind(findAt(view.state.selection.main.head)) },
          { key: "Space", run: (view) => toggleFind(findAt(view.state.selection.main.head)) },
          ...searchKeymap,
        ]),
        EditorView.domEventHandlers({
          click(event, view) {
            // A click changes a find; a drag that selects text does not.
            const hit = event.target instanceof Element && event.target.closest("[data-find]");
            if (!hit || event.detail > 1 || !view.state.selection.main.empty) return false;
            return toggleFind(Number(hit.getAttribute("data-find")));
          },
        }),
      ],
    }),
  });
}

function refreshPreview() {
  if (previewView) previewView.dispatch({ effects: refreshEffect.of(null) });
}

function renderPreview() {
  if (!previewView) previewView = createPreview($("preview"));
  previewView.dispatch({ changes: { from: 0, to: previewView.state.doc.length, insert: state.text }, selection: { anchor: 0 }, scrollIntoView: true });
  refreshPreview();
}

let flashTimer = 0;
function showInText(id) {
  const item = state.detections[id];
  state.flash = id;
  previewView.dispatch({
    selection: { anchor: item.start },
    effects: [EditorView.scrollIntoView(item.start, { y: "center" }), refreshEffect.of(null)],
  });
  $("preview").scrollIntoView({ behavior: "smooth", block: "nearest" });
  previewView.focus();
  clearTimeout(flashTimer);
  flashTimer = setTimeout(() => {
    state.flash = -1;
    refreshPreview();
  }, 1500);
}

function describeLanguages() {
  // Shown only for mixed texts: each section was analysed in its own language.
  const entries = Object.entries(state.languages);
  if (entries.length < 2) return "";
  const total = entries.reduce((sum, [, chars]) => sum + chars, 0) || 1;
  const parts = entries.map(([code, chars]) => `${LANGUAGE_NAMES[code] || code} ${Math.max(1, Math.round((chars / total) * 100))}%`);
  return ` Each section was analysed in its language: ${parts.join(", ")}.`;
}

function renderSummary() {
  const places = state.detections.length;
  let masked = 0;
  for (const value of state.masked) masked += value;
  const unsure = state.groups.filter((group) => group.unsure).length;
  $("summary").textContent = places
    ? `Found ${plural(places, "place", "places")}: ${plural(state.groups.length, "different word or phrase", "different words or phrases")}` +
      `${unsure ? `, ${formatCount(unsure)} unsure` : ""}. ${formatCount(masked)} will be masked, ${formatCount(places - masked)} kept.`
    : "No personal data was detected. You can still add terms to mask below.";
  $("summary-languages").textContent = describeLanguages();
  $("word-tools").hidden = !places;
  // Each filter shows how many words it would list.
  for (const option of $("word-filter").options) {
    const filter = FILTERS[option.value];
    option.textContent = `${filter.label} (${formatCount(state.groups.filter(filter.test).length)})`;
  }
  renderUndo();
}

// -- masking ------------------------------------------------------------------

async function mask() {
  const button = $("mask");
  button.disabled = true;
  setStatus("mask-status", "Masking…");
  try {
    const result = await api("/api/mask", {
      text: state.text,
      selections: state.detections
        .filter((item, id) => state.masked[id])
        .map(({ entity_type, start, end, score }) => ({ entity_type, start, end, score })),
      custom_terms: $("custom-terms").value.split("\n").map((line) => line.trim()).filter(Boolean),
      operators: { DEFAULT: $("default-operator").value },
    });
    $("output").value = result.masked_text;
    const total = Object.values(result.counts || {}).reduce((sum, count) => sum + count, 0);
    $("result-summary").textContent = total
      ? `${plural(total, "place", "places")} masked.`
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
  if (localAuth()) {
    // The desktop app signs the window in: no key step, the others move up.
    $("key-card").hidden = true;
    for (const step of document.querySelectorAll(".step")) step.textContent = String(Number(step.textContent) - 1);
  }
  describeFileSupport();
}

// Ctrl/Cmd+Z and Ctrl/Cmd+Shift+Z (or Ctrl+Y) undo and redo decisions, except
// while typing in a text field, which keeps its own undo.
function onKeyDown(event) {
  if ($("review").hidden || !(event.ctrlKey || event.metaKey) || event.altKey) return;
  const target = event.target;
  if (target instanceof HTMLTextAreaElement || (target instanceof HTMLInputElement && target.type !== "checkbox")) return;
  const key = event.key.toLowerCase();
  if (key === "z" && !event.shiftKey) undo();
  else if ((key === "z" && event.shiftKey) || (key === "y" && !event.metaKey)) redo();
  else return;
  event.preventDefault();
}

let searchTimer = 0;
$("input-file").addEventListener("change", onFileChosen);
$("clear-file").addEventListener("click", () => {
  clearFile();
  setStatus("analyze-status", "");
});
$("analyze").addEventListener("click", analyze);
$("word-search").addEventListener("input", () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(applyFilter, 150);
});
$("word-filter").addEventListener("change", applyFilter);
$("pick-all").addEventListener("change", (event) => pickAll(event.target.checked));
$("mask-picked").addEventListener("click", () => decideChecked(1));
$("keep-picked").addEventListener("click", () => decideChecked(0));
$("clear-picked").addEventListener("click", () => pickAll(false));
$("undo").addEventListener("click", undo);
$("redo").addEventListener("click", redo);
$("more-words").addEventListener("click", () => {
  state.shownRows += ROWS_PER_PAGE;
  renderWords();
});
document.addEventListener("keydown", onKeyDown);
$("mask").addEventListener("click", mask);
$("copy").addEventListener("click", copyResult);
$("download").addEventListener("click", downloadResult);
loadConfig();
