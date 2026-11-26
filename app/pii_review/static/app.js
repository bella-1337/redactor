// PII review page. All user data is rendered with textContent, never as HTML.

import { Decoration, EditorState, EditorView, RangeSetBuilder, StateEffect, ViewPlugin, WidgetType, keymap, search, searchKeymap } from "/codemirror.js";

const LANGUAGE_NAMES = { en: "English", de: "German", fr: "French" };
// Finds scored below this are marked "Unsure" (Presidio's spaCy and the local
// model score 0.8 and more; weak pattern matches score well below).
const UNSURE_SCORE = 0.6;
const MAX_SELECTIONS = 1000000; // as review.MAX_SELECTIONS on the server
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
  // The user's lists, kept for the life of this page: "always" terms are
  // masked wherever they appear, "ignore" terms are never masked when found.
  lists: { always: [], ignore: [] },
  always: { spans: [], counts: new Map(), longest: 0 }, // where "always" terms match
  manual: [], // {start, end}: places the user marked in the preview, sorted, for this text
  analysed: false, // a text has been analysed, so the review step can be opened
  // What a step changed: the finds it set, the list terms, the words it
  // marked as checked (groups get `reviewed` once a decision touches them).
  undo: [], // {ids: Int32Array, value, lists: [{name, term, added}], reviewed: Int32Array, manual: [{start, end, added}]}
  redo: [],
  maskConfirmed: false, // "Mask anyway" pressed since the last decision
  // The one-at-a-time check: a queue of words, each with the place to show first.
  check: { open: false, title: "", items: [], index: 0, skipped: 0 }, // items: [{group, place}]
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
  try {
    const result = state.file
      ? await api("/api/analyze-document", null, state.file)
      : await api("/api/analyze", { text: $("input-text").value });
    // The review step is shown first, so the preview is laid out while it fills.
    maskedResult.text = "";
    state.analysed = true;
    goToStep("review");
    loadResult(result);
    // OCR can misread or split names and numbers so that they are not detected.
    $("ocr-note").hidden = !result.ocr;
    setStatus("analyze-status", "");
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
    .map((group) => ({ ...group, unsure: group.best < UNSURE_SCORE, reviewed: false }))
    .sort((a, b) => b.ids.length - a.ids.length || a.label.localeCompare(b.label));
  state.groups.forEach((group, index) => {
    for (const id of group.ids) state.groupOf[id] = index;
  });
  // The ignore list carries over from earlier texts: its words start out kept.
  markIgnored();
  for (const group of state.groups) {
    if (group.ignoredBy) {
      setMasked(group.ids, 0);
      group.reviewed = true;
    }
  }
  findAlwaysTerms();

  state.undo = [];
  state.redo = [];
  state.maskConfirmed = false;
  state.manual = [];
  renderManual();
  closeCheck();
  state.checked.clear();
  state.expanded.clear();
  state.anchor = -1;
  $("word-search").value = "";
  $("word-filter").value = "all";
  applyFilter();
  renderPreview();
  renderLists();
  renderSummary();
}

// Sets the given finds to masked (1) or kept (0), and changes the lists, as
// one step that can be undone.
// Every word a step touches counts as checked, even when its finds were
// already as asked: choosing Mask for a masked word confirms it.
function decide(ids, value, lists = [], manual = []) {
  const touched = new Set();
  for (const id of ids) touched.add(state.groupOf[id]);
  const reviewed = Int32Array.from([...touched].filter((index) => !state.groups[index].reviewed));
  const changed = setMasked(ids, value);
  setReviewed(reviewed, true);
  for (const change of lists) applyListChange(change, true);
  for (const change of manual) applyManualChange(change, true);
  if (!changed.length && !lists.length && !reviewed.length && !manual.length) return;
  state.undo.push({ ids: changed, value, lists, reviewed, manual });
  if (state.undo.length > UNDO_LIMIT) state.undo.shift();
  state.redo = [];
  afterChange(changed, lists.length > 0, reviewed, manual.length > 0);
}

// Places marked by hand, kept sorted by position.
function applyManualChange({ start, end, added }, forward) {
  const index = state.manual.findIndex((span) => span.start === start && span.end === end);
  if (added === forward && index < 0) {
    state.manual.push({ start, end });
    state.manual.sort((a, b) => a.start - b.start || b.end - a.end);
  }
  if (added !== forward && index >= 0) state.manual.splice(index, 1);
}

function setReviewed(groups, value) {
  for (const index of groups) state.groups[index].reviewed = value;
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
  setReviewed(step.reviewed, false);
  for (const change of [...step.lists].reverse()) applyListChange(change, false);
  for (const change of [...step.manual].reverse()) applyManualChange(change, false);
  state.redo.push(step);
  afterChange(step.ids, step.lists.length > 0, step.reviewed, step.manual.length > 0);
}

function redo() {
  const step = state.redo.pop();
  if (!step) return;
  setMasked(step.ids, step.value);
  setReviewed(step.reviewed, true);
  for (const change of step.lists) applyListChange(change, true);
  for (const change of step.manual) applyManualChange(change, true);
  state.undo.push(step);
  afterChange(step.ids, step.lists.length > 0, step.reviewed, step.manual.length > 0);
}

// Redraws only what a step touched: the highlights in view, its rows, the
// lists, the summary, the check panel, the overview beside the preview.
function afterChange(ids, listsChanged = false, reviewed = [], manualChanged = false) {
  const groups = new Set(reviewed);
  for (const id of ids) groups.add(state.groupOf[id]);
  state.maskConfirmed = false;
  markResultStale();
  renderCheck();
  if (manualChanged) renderManual();
  scheduleOverview(true);
  if (listsChanged) {
    markIgnored();
    findAlwaysTerms();
    renderLists();
    // An "Ignored" badge can come or go on any row.
    for (const index of state.rows.keys()) groups.add(index);
  }
  for (const group of groups) updateRow(group);
  refreshPreview();
  renderSummary();
}

// -- lists ----------------------------------------------------------------------
//
// Terms match without regard to case. A * at the start or end of a term stands
// for the rest of that word, as on the server (review.parse_custom_term):
// "*@example.com" or "Project *".

const MAX_WILDCARD_CHARS = 200;
const LIST_NAMES = { always: "Always mask", ignore: "Never mask" };

function maxTerms() {
  return (state.config && state.config.max_custom_terms) || 200;
}

// Returns {leading, literal, trailing}, or throws an Error saying what is wrong.
function parseTerm(term) {
  const maxChars = (state.config && state.config.max_custom_term_chars) || 200;
  if (term.length > maxChars) throw new Error(`A term can be at most ${maxChars} characters.`);
  const leading = term.startsWith("*");
  const trailing = term.length > 1 && term.endsWith("*");
  const literal = term.slice(leading ? 1 : 0, trailing ? -1 : undefined);
  if (literal.includes("*")) throw new Error("A * can only start or end a term.");
  if ((leading || trailing) && literal.trim().length < 2) throw new Error("A term with * needs at least two other characters.");
  return { leading, literal, trailing };
}

const escapeRegExp = (value) => value.replace(/[\\^$.*+?()[\]{}|/]/g, "\\$&");
const isSpace = (char) => /\s/.test(char);

// [start, end] of every place `term` matches in `text`, at most `limit` of them.
function findTerm(text, term, limit = Infinity) {
  const { leading, literal, trailing } = parseTerm(term);
  const pattern = new RegExp(escapeRegExp(literal), "giu");
  const spans = [];
  for (let match = pattern.exec(text); match && spans.length < limit; match = pattern.exec(text)) {
    let start = match.index;
    let end = start + match[0].length;
    if (leading) {
      const floor = Math.max(0, start - MAX_WILDCARD_CHARS);
      while (start > floor && !isSpace(text[start - 1])) start--;
    }
    if (trailing) {
      const ceiling = Math.min(text.length, end + MAX_WILDCARD_CHARS);
      while (end < ceiling && !isSpace(text[end])) end++;
    }
    spans.push([start, end]);
  }
  return spans;
}

// A found word is on the ignore list when a term matches all of it.
function ignoredBy(label) {
  return state.lists.ignore.find((term) => matchesAll(term, label)) || "";
}

function markIgnored() {
  for (const group of state.groups) group.ignoredBy = ignoredBy(group.label);
}

// Where the "always" terms match: highlighted in the preview, counted on their chips.
function findAlwaysTerms() {
  const seen = new Set();
  const spans = [];
  state.always.counts = new Map();
  for (const term of state.lists.always) {
    const found = findTerm(state.text, term, MAX_SELECTIONS);
    state.always.counts.set(term, found.length);
    for (const [start, end] of found) {
      const key = `${start}:${end}`;
      if (!seen.has(key)) {
        seen.add(key);
        spans.push({ start, end, term });
      }
    }
  }
  spans.sort((a, b) => a.start - b.start || b.end - a.end);
  state.always.spans = spans;
  state.always.longest = spans.reduce((longest, span) => Math.max(longest, span.end - span.start), 0);
}

const sameTerm = (a, b) => a.toLocaleLowerCase() === b.toLocaleLowerCase();

function applyListChange({ name, term, added }, forward) {
  const list = state.lists[name];
  const index = list.findIndex((each) => sameTerm(each, term));
  if (added === forward && index < 0) list.push(term);
  if (added !== forward && index >= 0) list.splice(index, 1);
}

// Adds terms to a list. Adding to the ignore list keeps the words it matches;
// a term moves out of the other list. Returns an error message, or "".
function addTerms(name, terms) {
  const other = name === "always" ? "ignore" : "always";
  const changes = [];
  for (const raw of terms) {
    const term = raw.replace(/\s+/g, " ").trim();
    if (!term || state.lists[name].some((each) => sameTerm(each, term)) || changes.some((change) => sameTerm(change.term, term))) continue;
    try {
      parseTerm(term);
    } catch (error) {
      return `“${term.slice(0, 40)}”: ${error.message}`;
    }
    const known = state.lists[other].find((each) => sameTerm(each, term));
    if (known) changes.push({ name: other, term: known, added: false });
    changes.push({ name, term, added: true });
  }
  if (state.lists[name].length + changes.filter((change) => change.name === name).length > maxTerms()) {
    return `${LIST_NAMES[name]} can hold at most ${formatCount(maxTerms())} terms.`;
  }
  if (!changes.length) return "";
  if (name === "ignore") {
    // The words the new terms match are kept.
    const ids = [];
    for (const group of state.groups) {
      if (changes.some((change) => change.added && matchesAll(change.term, group.label))) ids.push(...group.ids);
    }
    decide(ids, 0, changes);
  } else {
    // A term that moves here from the ignore list masks its words again.
    const moved = changes.filter((change) => !change.added).map((change) => change.term);
    decide(onlyIgnoredBy(moved), 1, changes);
  }
  return "";
}

const matchesAll = (term, label) => findTerm(label, term).some(([start, end]) => start === 0 && end === label.length);

// The finds of the words that these ignore terms, and no other, keep.
function onlyIgnoredBy(terms) {
  const ids = [];
  if (!terms.length) return ids;
  const rest = state.lists.ignore.filter((each) => !terms.some((term) => sameTerm(each, term)));
  for (const group of state.groups) {
    if (terms.some((term) => matchesAll(term, group.label)) && !rest.some((term) => matchesAll(term, group.label))) ids.push(...group.ids);
  }
  return ids;
}

// Removes a term. Words that only this ignore term kept are masked again.
function removeTerm(name, term) {
  decide(name === "ignore" ? onlyIgnoredBy([term]) : [], 1, [{ name, term, added: false }]);
}

function renderLists() {
  for (const name of ["always", "ignore"]) {
    const chips = state.lists[name].map((term) => {
      const count = name === "always" ? state.always.counts.get(term) || 0 : state.groups.filter((group) => group.ignoredBy && sameTerm(group.ignoredBy, term)).length;
      const what = name === "always" ? plural(count, "place", "places") : plural(count, "word", "words");
      return el("li", { class: "chip" }, [
        el("span", { class: "chip-term", text: term, title: term }),
        el("span", { class: "chip-count", text: what }),
        el("button", { type: "button", class: "chip-remove", text: "×", "aria-label": `Remove “${term}” from ${LIST_NAMES[name]}`, onclick: () => removeTerm(name, term) }),
      ]);
    });
    $(`${name}-chips`).replaceChildren(...chips);
    $(`${name}-empty`).hidden = chips.length > 0;
  }
}

function onAddTerm(name) {
  const input = $(`${name}-input`);
  const error = addTerms(name, [input.value]);
  setStatus(`${name}-status`, error, Boolean(error));
  if (!error) input.value = "";
}

function groupState(group) {
  if (group.maskedCount === group.ids.length) return "masked";
  return group.maskedCount === 0 ? "kept" : "partly";
}

// -- word list --------------------------------------------------------------

const FILTERS = {
  all: { label: "All words", test: () => true },
  unsure: { label: "Unsure", test: (group) => group.unsure },
  unchecked: { label: "Not checked", test: (group) => !group.reviewed },
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
      el("span", { class: "badge ignored", text: "Never mask" }),
      el("span", { class: "checked-mark", text: "✓", title: "Checked", "aria-label": "Checked" }),
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
  const badge = row.querySelector(".badge.ignored");
  badge.hidden = !group.ignoredBy;
  badge.title = group.ignoredBy ? `On your Never mask list as “${group.ignoredBy}”` : "";
  row.querySelector(".checked-mark").hidden = !group.reviewed;
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

function ignoreChecked() {
  const error = addTerms("ignore", [...state.checked].map((index) => state.groups[index].label));
  setStatus("ignore-status", error, Boolean(error));
  if (error) $("ignore-status").scrollIntoView({ block: "nearest" });
}

// -- checking one word at a time ------------------------------------------------
//
// A queue of words shown one by one with their context, decided with M, K,
// Space (skip), and Backspace (back). The preview follows along.

const SPOT_CHECK_PLACES = 20;
const CONTEXTS_SHOWN = 3;

// Least confident first, then the most frequent.
const byConcern = (a, b) => state.groups[a].best - state.groups[b].best || state.groups[b].ids.length - state.groups[a].ids.length;

function checkQueue(kind) {
  const indices = state.groups.map((_, index) => index).filter((index) => !state.groups[index].reviewed);
  if (kind === "unsure") return indices.filter((index) => state.groups[index].unsure).sort(byConcern).map((group) => ({ group, place: state.groups[group].ids[0] }));
  if (kind === "unchecked") {
    const unsure = indices.filter((index) => state.groups[index].unsure).sort(byConcern);
    const rest = indices.filter((index) => !state.groups[index].unsure);
    return [...unsure, ...rest].map((group) => ({ group, place: state.groups[group].ids[0] }));
  }
  // Spot check: random places, one per word, in text order. Frequent words
  // come up more often, as they would when reading the text.
  const places = new Set();
  const wanted = Math.min(SPOT_CHECK_PLACES, state.detections.length);
  while (places.size < wanted) places.add(Math.floor(Math.random() * state.detections.length));
  const seen = new Set();
  const items = [];
  for (const place of [...places].sort((a, b) => a - b)) {
    const group = state.groupOf[place];
    if (!seen.has(group)) {
      seen.add(group);
      items.push({ group, place });
    }
  }
  return items;
}

const CHECK_TITLES = { unsure: "Checking unsure words", unchecked: "Checking words not yet checked", spot: "Spot check of random places" };

function startCheck(kind) {
  const items = checkQueue(kind);
  if (!items.length) return;
  Object.assign(state.check, { open: true, title: CHECK_TITLES[kind], items, index: 0 });
  $("check-panel").hidden = false;
  renderCheck();
  $("check-panel").scrollIntoView({ behavior: "smooth", block: "start" });
  $("check-panel").focus({ preventScroll: true });
}

function closeCheck() {
  state.check.open = false;
  $("check-panel").hidden = true;
}

function checkStep(action) {
  const check = state.check;
  if (!check.open) return;
  const item = check.items[check.index];
  if (action === "back") check.index = Math.max(0, check.index - 1);
  else if (item) {
    if (action === "mask" || action === "keep") decide(state.groups[item.group].ids, action === "mask" ? 1 : 0);
    check.index += 1;
  }
  renderCheck();
  // Keys go to the panel again, not to the button just pressed.
  $("check-panel").focus({ preventScroll: true });
}

function renderCheck() {
  renderCheckRow();
  const check = state.check;
  if (!check.open) return;
  const total = check.items.length;
  const done = check.index >= total;
  $("check-title").textContent = check.title;
  $("check-count").textContent = done ? `${formatCount(total)} of ${formatCount(total)}` : `Word ${formatCount(check.index + 1)} of ${formatCount(total)}`;
  $("check-bar").max = total;
  $("check-bar").value = Math.min(check.index, total);
  for (const id of ["check-mask", "check-keep", "check-skip"]) $(id).hidden = done;
  $("check-back").disabled = check.index === 0;
  const body = $("check-body");
  if (done) {
    const skipped = check.items.filter((item) => !state.groups[item.group].reviewed).length;
    body.replaceChildren(
      el("p", { class: "check-done", text: `Done: ${plural(total - skipped, "word", "words")} checked${skipped ? `, ${formatCount(skipped)} skipped` : ""}.` }),
    );
    return;
  }
  const item = check.items[check.index];
  const group = state.groups[item.group];
  const current = groupState(group);
  $("check-mask").setAttribute("aria-pressed", String(group.reviewed && current === "masked"));
  $("check-keep").setAttribute("aria-pressed", String(group.reviewed && current === "kept"));
  const status = { masked: "will be masked", kept: "will stay", partly: `${formatCount(group.maskedCount)} of ${formatCount(group.ids.length)} places will be masked` }[current];
  // The place that brought the word up first, then its other places.
  const places = [item.place, ...group.ids.filter((id) => id !== item.place)].slice(0, CONTEXTS_SHOWN);
  body.replaceChildren(
    el("div", { class: "check-word-line" }, [
      el("span", { class: "check-word", text: group.label }),
      ...(group.unsure ? [el("span", { class: "badge", text: "Unsure" })] : []),
      ...(group.ignoredBy ? [el("span", { class: "badge ignored", text: "Never mask" })] : []),
      el("span", { class: "count", text: `${plural(group.ids.length, "place", "places")} · ${status}${group.reviewed ? " · checked" : ""}` }),
    ]),
    el(
      "ul",
      { class: "check-contexts" },
      places.map((id) => {
        const [before, value, after] = snippet(state.detections[id]);
        return el("li", {}, [
          el("span", { class: "context" }, [before, el("mark", { text: value }), after]),
          el("button", { type: "button", class: "link", text: "Show in text", onclick: () => showInText(id) }),
        ]);
      }),
    ),
    ...(group.ids.length > CONTEXTS_SHOWN ? [el("p", { class: "hint", text: `Mask or Keep applies to all ${plural(group.ids.length, "place", "places")}. Open the word in the list to change single places.` })] : []),
  );
  revealInPreview(item.place);
}

function renderCheckRow() {
  const total = state.groups.length;
  const checked = state.groups.filter((group) => group.reviewed).length;
  const unsure = state.groups.filter((group) => group.unsure);
  const unsureLeft = unsure.filter((group) => !group.reviewed).length;
  $("check-progress").textContent =
    `Checked ${formatCount(checked)} of ${plural(total, "word", "words")}` +
    (unsure.length ? ` (${formatCount(unsure.length - unsureLeft)} of ${formatCount(unsure.length)} unsure).` : ".");
  $("check-unsure").textContent = `Unsure words (${formatCount(unsureLeft)})`;
  $("check-unsure").disabled = !unsureLeft;
  $("check-unchecked").textContent = `Not checked (${formatCount(total - checked)})`;
  $("check-unchecked").disabled = checked === total;
  $("check-spot").textContent = `Spot check (${formatCount(Math.min(SPOT_CHECK_PLACES, state.detections.length))})`;
  $("check-spot").disabled = !state.detections.length;
  $("mask").textContent = state.maskConfirmed ? "Mask anyway →" : "Mask the text →";
  $("mask-check").hidden = !state.maskConfirmed;
  if (!state.maskConfirmed && $("mask-status").classList.contains("error") && $("mask-status").dataset.unchecked) {
    setStatus("mask-status", "");
    delete $("mask-status").dataset.unchecked;
  }
}

// Keys while the check panel is open: M or Enter masks, K keeps, Space skips,
// Backspace goes back, Escape closes. Typing in a field and the preview keep their keys.
function onCheckKey(event) {
  const target = event.target;
  if (!state.check.open || event.ctrlKey || event.metaKey || event.altKey) return false;
  if (target instanceof HTMLTextAreaElement || target instanceof HTMLSelectElement || (target instanceof HTMLInputElement && target.type !== "checkbox")) return false;
  if (target === $("preview")) return false;
  // A focused button keeps Enter and Space for itself.
  if (target instanceof HTMLButtonElement && (event.key === "Enter" || event.key === " ")) return false;
  const action = { m: "mask", Enter: "mask", k: "keep", " ": "skip", Backspace: "back", ArrowLeft: "back", ArrowRight: "skip" }[event.key.length === 1 ? event.key.toLowerCase() : event.key];
  if (event.key === "Escape") closeCheck();
  else if (action) checkStep(action);
  else return false;
  event.preventDefault();
  return true;
}

// Unsure finds, all at once: Mask or Keep is pressed when all of them are.
function unsureIds() {
  const ids = [];
  for (const group of state.groups) if (group.unsure) ids.push(...group.ids);
  return ids;
}

function renderUnsure() {
  const groups = state.groups.filter((group) => group.unsure);
  $("unsure-row").hidden = !groups.length;
  if (!groups.length) return;
  const masked = groups.reduce((sum, group) => sum + group.maskedCount, 0);
  const total = groups.reduce((sum, group) => sum + group.ids.length, 0);
  $("unsure-label").textContent = `${plural(groups.length, "unsure word", "unsure words")} (${plural(total, "place", "places")}):`;
  $("unsure-mask").setAttribute("aria-pressed", String(masked === total));
  $("unsure-keep").setAttribute("aria-pressed", String(masked === 0));
}

function renderBulk() {
  const count = state.checked.size;
  const all = $("pick-all");
  all.checked = count > 0 && count === state.visible.length;
  all.indeterminate = count > 0 && count < state.visible.length;
  all.disabled = !state.visible.length;
  $("pick-all-label").textContent = `Select all ${plural(state.visible.length, "word", "words")}`;
  $("bulk-count").textContent = count ? `${plural(count, "word", "words")} selected` : "";
  for (const id of ["mask-picked", "keep-picked", "ignore-picked", "clear-picked"]) $(id).disabled = !count;
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

// Where the Always mask terms match, drawn as their own layer.
function alwaysInView(view) {
  const builder = new RangeSetBuilder();
  const spans = state.always.spans;
  for (const { from, to } of view.visibleRanges) {
    let low = 0;
    let high = spans.length;
    while (low < high) {
      const middle = (low + high) >> 1;
      if (spans[middle].start < from - state.always.longest) low = middle + 1;
      else high = middle;
    }
    for (let index = low; index < spans.length && spans[index].start < to; index++) {
      const span = spans[index];
      if (span.end <= from) continue;
      builder.add(span.start, span.end, Decoration.mark({ class: "added", attributes: { title: `Masked by your Always mask list: “${span.term}”` } }));
    }
  }
  return builder.finish();
}

const alwaysHighlights = ViewPlugin.fromClass(
  class {
    constructor(view) {
      this.decorations = alwaysInView(view);
    }

    update(update) {
      if (update.viewportChanged || update.transactions.some((tr) => tr.effects.some((effect) => effect.is(refreshEffect)))) {
        this.decorations = alwaysInView(update.view);
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
// Places marked by hand, drawn as their own layer. There are few, so all are checked.
function manualInView(view) {
  const builder = new RangeSetBuilder();
  for (const { from, to } of view.visibleRanges) {
    for (const span of state.manual) {
      if (span.start >= to || span.end <= from) continue;
      builder.add(span.start, span.end, Decoration.mark({ class: "manual", attributes: { "data-manual": `${span.start}:${span.end}`, title: "Marked by you. Click to unmark it." } }));
    }
  }
  return builder.finish();
}

const manualHighlights = ViewPlugin.fromClass(
  class {
    constructor(view) {
      this.decorations = manualInView(view);
    }

    update(update) {
      if (update.viewportChanged || update.transactions.some((tr) => tr.effects.some((effect) => effect.is(refreshEffect)))) {
        this.decorations = manualInView(update.view);
      }
    }
  },
  { decorations: (plugin) => plugin.decorations },
);

// -- selecting text in the preview ----------------------------------------------

const isWordChar = (char) => char !== undefined && /[\p{L}\p{N}]/u.test(char);

// A selection that starts or ends inside a word takes in the whole word, without
// the spaces around it.
function snapToWords(from, to) {
  const text = state.text;
  while (from > 0 && isWordChar(text[from - 1]) && isWordChar(text[from])) from--;
  while (to < text.length && isWordChar(text[to]) && isWordChar(text[to - 1])) to++;
  while (from < to && isSpace(text[from])) from++;
  while (to > from && isSpace(text[to - 1])) to--;
  return [from, to];
}

function currentSelection() {
  if (!previewView) return null;
  const { from, to } = previewView.state.selection.main;
  if (from === to) return null;
  const [start, end] = snapToWords(from, to);
  return start < end ? { start, end } : null;
}

function afterSelectionAction() {
  const head = previewView.state.selection.main.to;
  previewView.dispatch({ selection: { anchor: head } });
  previewView.focus();
}

// Mask this: the selected text is masked here, and only here.
function maskSelection() {
  const span = currentSelection();
  if (!span) return false;
  if (!state.manual.some((each) => each.start === span.start && each.end === span.end)) decide([], 1, [], [{ ...span, added: true }]);
  afterSelectionAction();
  return true;
}

// Mask everywhere: the selected text goes on the Always mask list.
function maskSelectionEverywhere() {
  const span = currentSelection();
  if (!span) return false;
  const error = addTerms("always", [state.text.slice(span.start, span.end)]);
  setStatus("selection-status", error, Boolean(error));
  if (!error) afterSelectionAction();
  return true;
}

// Keep finds here: every find and hand-marked place the selection touches stays.
function keepSelection() {
  if (!previewView) return false;
  const { from, to } = previewView.state.selection.main;
  if (from === to) return false;
  const ids = [];
  for (let id = firstFindFrom(from - state.longestFind); id < state.detections.length && state.detections[id].start < to; id++) {
    if (state.detections[id].end > from) ids.push(id);
  }
  const manual = state.manual.filter((span) => span.start < to && span.end > from).map((span) => ({ ...span, added: false }));
  decide(ids, 0, [], manual);
  afterSelectionAction();
  return true;
}

function renderSelectionBar() {
  const span = currentSelection();
  const shown = span ? state.text.slice(span.start, span.end).replace(/\s+/g, " ") : "";
  $("selection-text").textContent = span ? `“${shown.length > 60 ? `${shown.slice(0, 60)}…` : shown}”` : "Select text in the preview to mask it.";
  $("selection-text").classList.toggle("hint", !span);
  for (const id of ["sel-mask", "sel-mask-all", "sel-keep"]) $(id).disabled = !span;
  if (!span) setStatus("selection-status", "");
}

// -- moving between finds -------------------------------------------------------

// The next (or previous) find from the cursor; with `unsure`, only unsure ones.
// It wraps around at the end of the text.
function moveToFind(direction, unsure = false) {
  if (!previewView || !state.detections.length) return true;
  const head = previewView.state.selection.main.head;
  const count = state.detections.length;
  let id = direction > 0 ? firstFindFrom(head + 1) : firstFindFrom(head) - 1;
  for (let tries = 0; tries < count; tries++, id += direction) {
    id = (id + count) % count;
    if (!unsure || state.groups[state.groupOf[id]].unsure) {
      const item = state.detections[id];
      state.flash = id;
      previewView.dispatch({ selection: { anchor: item.start }, effects: [EditorView.scrollIntoView(item.start, { y: "center" }), refreshEffect.of(null)] });
      previewView.focus();
      unflashLater();
      return true;
    }
  }
  return true;
}

// -- the overview beside the preview ---------------------------------------------
//
// A strip as tall as the preview with a mark wherever there are finds in the
// whole text, in proportion to their position: masked, kept, or added by the
// user. The part in view is outlined; a click or drag scrolls there.

let overview = null; // {canvas, rows: Uint8Array}
let overviewFrame = 0;
let overviewStale = true;

function scheduleOverview(stale = false) {
  overviewStale = overviewStale || stale;
  if (!overview || overviewFrame) return;
  overviewFrame = requestAnimationFrame(() => {
    overviewFrame = 0;
    drawOverview();
  });
}

function overviewRows(height) {
  // Per pixel row: 0 nothing, 1 kept, 2 masked, 3 masked by the user.
  const rows = new Uint8Array(height);
  const length = Math.max(1, state.text.length);
  const mark = (position, kind) => {
    const row = Math.min(height - 1, Math.floor((position / length) * height));
    if (rows[row] < kind) rows[row] = kind;
  };
  state.detections.forEach((item, id) => mark(item.start, state.masked[id] ? 2 : 1));
  for (const span of state.always.spans) mark(span.start, 3);
  for (const span of state.manual) mark(span.start, 3);
  return rows;
}

function drawOverview() {
  const { canvas } = overview;
  const ratio = window.devicePixelRatio || 1;
  const width = Math.round(canvas.clientWidth * ratio);
  const height = Math.round(canvas.clientHeight * ratio);
  if (!width || !height) return;
  if (canvas.width !== width || canvas.height !== height) {
    canvas.width = width;
    canvas.height = height;
    overviewStale = true;
  }
  if (overviewStale) {
    overview.rows = overviewRows(height);
    overviewStale = false;
  }
  const styles = getComputedStyle(canvas);
  const colours = [null, styles.getPropertyValue("--muted"), styles.getPropertyValue("--hit-selected"), styles.getPropertyValue("--accent")];
  const context = canvas.getContext("2d");
  context.clearRect(0, 0, width, height);
  const mark = Math.max(2, Math.round(2 * ratio));
  overview.rows.forEach((kind, row) => {
    if (!kind) return;
    context.fillStyle = colours[kind];
    context.fillRect(kind === 1 ? width / 2 : 0, row, kind === 1 ? width / 2 : width, mark);
  });
  // The part of the text in view.
  const ranges = previewView.visibleRanges;
  if (ranges.length && state.text.length) {
    const top = (ranges[0].from / state.text.length) * height;
    const bottom = (ranges[ranges.length - 1].to / state.text.length) * height;
    context.fillStyle = styles.getPropertyValue("--view-box");
    context.fillRect(0, top, width, Math.max(mark * 2, bottom - top));
  }
}

function scrollFromOverview(event) {
  const { canvas } = overview;
  const box = canvas.getBoundingClientRect();
  const fraction = Math.min(1, Math.max(0, (event.clientY - box.top) / box.height));
  const block = previewView.lineBlockAt(Math.round(fraction * state.text.length));
  const scroller = previewView.scrollDOM;
  scroller.scrollTop = Math.max(0, block.top - scroller.clientHeight / 2);
}

function createOverview(parent) {
  const canvas = el("canvas", { class: "overview", "aria-hidden": "true", title: "Where the finds are in the whole text. Click to go there." });
  parent.append(canvas);
  overview = { canvas, rows: new Uint8Array(0) };
  canvas.addEventListener("pointerdown", (event) => {
    canvas.setPointerCapture(event.pointerId);
    scrollFromOverview(event);
  });
  canvas.addEventListener("pointermove", (event) => {
    if (canvas.hasPointerCapture(event.pointerId)) scrollFromOverview(event);
  });
  new ResizeObserver(() => scheduleOverview()).observe(canvas);
}

// A read-only text view lives in a shadow root of `host`: there CodeMirror
// adds its styles as a constructed style sheet, which the page's CSP allows.
function mountInShadow(host) {
  const shadow = host.attachShadow({ mode: "open" });
  const body = el("div", { class: "preview-body" });
  const parent = el("div", { class: "preview-editor" });
  body.append(parent);
  shadow.append(el("link", { rel: "stylesheet", href: "/preview.css" }), body);
  return { shadow, body, parent };
}

const textViewBasics = () => [
  EditorState.readOnly.of(true),
  // Only "\n" ends a line, so "\r\n" stays two characters and positions match the text.
  EditorState.lineSeparator.of("\n"),
  EditorView.lineWrapping,
  search({ top: true }),
];

function createPreview(host) {
  const { shadow, body, parent } = mountInShadow(host);
  createOverview(body);
  // Shift+M masks the selection everywhere. Caught before CodeMirror sees it:
  // some keyboards report the key as "m" with Shift, which its keymap reads as M.
  host.addEventListener(
    "keydown",
    (event) => {
      if (event.key.toLowerCase() !== "m" || !event.shiftKey || event.ctrlKey || event.metaKey || event.altKey) return;
      if (maskSelectionEverywhere()) {
        event.preventDefault();
        event.stopPropagation();
      }
    },
    true,
  );
  return new EditorView({
    parent,
    root: shadow,
    state: EditorState.create({
      doc: "",
      extensions: [
        ...textViewBasics(),
        EditorView.contentAttributes.of({ "aria-label": "Preview of the text", spellcheck: "false" }),
        manualHighlights,
        alwaysHighlights,
        highlights,
        keymap.of([
          // Enter or Space changes the find at the cursor.
          { key: "Enter", run: (view) => toggleFind(findAt(view.state.selection.main.head)) },
          { key: "Space", run: (view) => toggleFind(findAt(view.state.selection.main.head)) },
          // With text selected: M masks it here, K keeps the finds in it.
          // (Shift+M, everywhere, is caught on the host in createPreview.)
          { key: "m", run: () => maskSelection() },
          { key: "k", run: () => keepSelection() },
          // N and P go to the next and previous find, U to the next unsure one.
          { key: "n", run: () => moveToFind(1) },
          { key: "p", run: () => moveToFind(-1) },
          { key: "u", run: () => moveToFind(1, true) },
          ...searchKeymap,
        ]),
        EditorView.updateListener.of((update) => {
          if (update.selectionSet || update.docChanged) renderSelectionBar();
          if (update.viewportChanged || update.geometryChanged) scheduleOverview();
        }),
        EditorView.domEventHandlers({
          click(event, view) {
            // A click changes a find, or unmarks a place marked by hand; a
            // drag that selects text does neither.
            if (!(event.target instanceof Element) || event.detail > 1 || !view.state.selection.main.empty) return false;
            const hit = event.target.closest("[data-find]");
            if (hit) return toggleFind(Number(hit.getAttribute("data-find")));
            const manual = event.target.closest("[data-manual]");
            if (!manual) return false;
            const [start, end] = manual.getAttribute("data-manual").split(":").map(Number);
            decide([], 0, [], [{ start, end, added: false }]);
            return true;
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
  scheduleOverview(true);
}

// The places marked by hand, as chips: a click shows one, × unmarks it.
const MANUAL_CHIPS_SHOWN = 50;
function renderManual() {
  const chips = state.manual.slice(0, MANUAL_CHIPS_SHOWN).map((span) => {
    const value = state.text.slice(span.start, span.end).replace(/\s+/g, " ");
    const label = value.length > 40 ? `${value.slice(0, 40)}…` : value;
    return el("li", { class: "chip" }, [
      el("button", { type: "button", class: "chip-term link", text: label, title: "Show in the preview", onclick: () => showRange(span.start) }),
      el("button", { type: "button", class: "chip-remove", text: "×", "aria-label": `Unmark “${label}”`, onclick: () => decide([], 0, [], [{ ...span, added: false }]) }),
    ]);
  });
  if (state.manual.length > MANUAL_CHIPS_SHOWN) chips.push(el("li", { class: "hint", text: `and ${formatCount(state.manual.length - MANUAL_CHIPS_SHOWN)} more` }));
  $("manual-chips").replaceChildren(...chips);
  $("manual-row").hidden = !state.manual.length;
}

function showRange(position) {
  const show = () => {
    previewView.dispatch({ selection: { anchor: position }, effects: EditorView.scrollIntoView(position, { y: "center" }) });
    $("preview").scrollIntoView({ behavior: "smooth", block: "nearest" });
    previewView.focus();
  };
  if (currentStep === "review") show();
  else {
    // From the result: go back to the review, and scroll once the preview is laid out again.
    goToStep("review", false);
    requestAnimationFrame(show);
  }
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
  unflashLater();
}

// Scrolls the preview, not the page, to a find and outlines it for a moment.
// (CodeMirror's own scrollIntoView would scroll the page to the preview too.)
function revealInPreview(id) {
  const item = state.detections[id];
  state.flash = id;
  previewView.dispatch({ selection: { anchor: item.start }, effects: refreshEffect.of(null) });
  const block = previewView.lineBlockAt(item.start);
  const scroller = previewView.scrollDOM;
  scroller.scrollTop = Math.max(0, block.top - scroller.clientHeight / 2 + Math.min(block.height, scroller.clientHeight) / 2);
  unflashLater();
}

function unflashLater() {
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
  const added = state.always.spans.length;
  $("summary").textContent =
    (places
      ? `Found ${plural(places, "place", "places")}: ${plural(state.groups.length, "different word or phrase", "different words or phrases")}` +
        `${unsure ? `, ${formatCount(unsure)} unsure` : ""}. ${formatCount(masked)} will be masked, ${formatCount(places - masked)} kept.`
      : "No personal data was detected. You can still add words to mask to the Always mask list.") +
    (added ? ` Your Always mask list masks ${plural(added, "more place", "more places")}.` : "") +
    (state.manual.length ? ` You marked ${plural(state.manual.length, "place", "places")} by hand.` : "");
  renderUnsure();
  renderCheckRow();
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
  // Unchecked unsure words: say so once; a second press masks anyway.
  const unchecked = state.groups.filter((group) => group.unsure && !group.reviewed).length;
  if (unchecked && !state.maskConfirmed) {
    state.maskConfirmed = true;
    setStatus("mask-status", `${plural(unchecked, "unsure word has", "unsure words have")} not been checked yet.`, true);
    $("mask-status").dataset.unchecked = "1";
    renderCheckRow();
    return;
  }
  const button = $("mask");
  button.disabled = true;
  setStatus("mask-status", "Masking…");
  try {
    const result = await api("/api/mask", {
      text: state.text,
      selections: [
        ...state.detections.filter((item, id) => state.masked[id]).map(({ entity_type, start, end, score }) => ({ entity_type, start, end, score })),
        // Places marked by hand have no type of their own.
        ...state.manual.map(({ start, end }) => ({ entity_type: "PII", start, end, score: 1 })),
      ],
      custom_terms: state.lists.always,
      operators: { DEFAULT: $("default-operator").value },
    });
    const total = Object.values(result.counts || {}).reduce((sum, count) => sum + count, 0);
    $("result-summary").textContent = total
      ? `${plural(total, "place", "places")} masked.`
      : "Nothing was selected, so the text is unchanged.";
    setStatus("mask-status", "");
    setStatus("copy-status", "");
    goToStep("result");
    showResult(result);
  } catch (error) {
    setStatus("mask-status", error.message, true);
  } finally {
    button.disabled = false;
  }
}

// -- the masked result ---------------------------------------------------------
//
// The masked text in a read-only view. Each replacement can be highlighted;
// a click on one says what it replaced and leads back to it in the preview.

const maskedResult = { text: "", replacements: null, stale: false }; // replacements: [start, end, maskedStart, maskedEnd], in order
let resultView = null;
let showReplacements = true;

// A removed span leaves nothing in the masked text, so a small mark stands in for it.
class RemovedMark extends WidgetType {
  constructor(index) {
    super();
    this.index = index;
  }

  eq(other) {
    return other.index === this.index;
  }

  toDOM() {
    const [start, end] = maskedResult.replacements[this.index];
    return el("span", { class: "replaced removed", text: "⌫", "data-replacement": String(this.index), title: replacementTitle(start, end) });
  }

  ignoreEvent() {
    return false;
  }
}

function replacementTitle(start, end) {
  const original = state.text.slice(start, end).replace(/\s+/g, " ");
  return `Replaced “${original.length > 80 ? `${original.slice(0, 80)}…` : original}”. Click for more.`;
}

function replacementsInView(view) {
  const builder = new RangeSetBuilder();
  const list = maskedResult.replacements;
  if (!showReplacements || !list) return builder.finish();
  for (const { from, to } of view.visibleRanges) {
    let low = 0;
    let high = list.length;
    while (low < high) {
      const middle = (low + high) >> 1;
      if (list[middle][3] < from) low = middle + 1;
      else high = middle;
    }
    for (let index = low; index < list.length && list[index][2] <= to; index++) {
      const [start, end, maskedStart, maskedEnd] = list[index];
      if (maskedStart === maskedEnd) {
        builder.add(maskedStart, maskedStart, Decoration.widget({ widget: new RemovedMark(index), side: 1 }));
      } else {
        builder.add(maskedStart, maskedEnd, Decoration.mark({ class: "replaced", attributes: { "data-replacement": String(index), title: replacementTitle(start, end) } }));
      }
    }
  }
  return builder.finish();
}

const replacementHighlights = ViewPlugin.fromClass(
  class {
    constructor(view) {
      this.decorations = replacementsInView(view);
    }

    update(update) {
      if (update.docChanged || update.viewportChanged || update.transactions.some((tr) => tr.effects.some((effect) => effect.is(refreshEffect)))) {
        this.decorations = replacementsInView(update.view);
      }
    }
  },
  { decorations: (plugin) => plugin.decorations },
);

function describeReplacement(index) {
  const [start, end, maskedStart, maskedEnd] = maskedResult.replacements[index];
  const original = state.text.slice(start, end).replace(/\s+/g, " ");
  const now = maskedResult.text.slice(maskedStart, maskedEnd);
  const was = el("mark", { text: original.length > 200 ? `${original.slice(0, 200)}…` : original });
  $("result-detail").replaceChildren(
    ...(now ? [el("mark", { class: "detail-new", text: now }), " replaced ", was] : [was, " was removed"]),
    ". ",
    el("button", { type: "button", class: "link", text: "Show in the preview", onclick: () => showRange(start) }),
  );
}

// N and P move between the replacements in the result.
function moveToReplacement(direction) {
  const list = maskedResult.replacements;
  if (!list || !list.length) return true;
  const head = resultView.state.selection.main.head;
  let index = direction > 0 ? list.findIndex((item) => item[2] > head) : list.findLastIndex((item) => item[2] < head);
  if (index < 0) index = direction > 0 ? 0 : list.length - 1;
  resultView.dispatch({ selection: { anchor: list[index][2] }, effects: EditorView.scrollIntoView(list[index][2], { y: "center" }) });
  describeReplacement(index);
  return true;
}

function createResultView(host) {
  const { shadow, parent } = mountInShadow(host);
  return new EditorView({
    parent,
    root: shadow,
    state: EditorState.create({
      doc: "",
      extensions: [
        ...textViewBasics(),
        EditorView.contentAttributes.of({ "aria-label": "Masked text", spellcheck: "false" }),
        replacementHighlights,
        keymap.of([{ key: "n", run: () => moveToReplacement(1) }, { key: "p", run: () => moveToReplacement(-1) }, ...searchKeymap]),
        EditorView.domEventHandlers({
          click(event, view) {
            const hit = event.target instanceof Element && event.target.closest("[data-replacement]");
            if (!hit || !view.state.selection.main.empty) return false;
            describeReplacement(Number(hit.getAttribute("data-replacement")));
            return true;
          },
        }),
      ],
    }),
  });
}

function showResult(result) {
  maskedResult.stale = false;
  $("result-stale").hidden = true;
  maskedResult.text = result.masked_text;
  renderStepper();
  maskedResult.replacements = Array.isArray(result.replacements) ? result.replacements : null;
  if (!resultView) resultView = createResultView($("output"));
  resultView.dispatch({ changes: { from: 0, to: resultView.state.doc.length, insert: maskedResult.text }, selection: { anchor: 0 }, scrollIntoView: true });
  $("show-replacements").disabled = !maskedResult.replacements;
  $("result-detail").textContent = maskedResult.replacements
    ? maskedResult.replacements.length
      ? "Click a highlighted part to see what it replaced. In the text, N and P go to the next and previous one."
      : ""
    : "This server does not say where the replacements are, so they are not highlighted.";
}

async function copyResult() {
  try {
    await navigator.clipboard.writeText(maskedResult.text);
    setStatus("copy-status", "Copied.");
  } catch {
    resultView.dispatch({ selection: { anchor: 0, head: maskedResult.text.length } });
    resultView.focus();
    setStatus("copy-status", "The text is selected: copy it with Ctrl+C (⌘C).", true);
  }
}

function downloadResult() {
  const blob = new Blob([maskedResult.text], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = el("a", { href: url, download: "masked.txt" });
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// -- the wizard -------------------------------------------------------------------
//
// One step at a time: the text, the review, the result. A step can be opened
// from the stepper once it has something to show.

const STEPS = ["input", "review", "result"];
let currentStep = "input";

function goToStep(name, focus = true) {
  currentStep = name;
  for (const section of document.querySelectorAll(".wizard-step")) section.hidden = section.dataset.step !== name;
  renderStepper();
  if (name === "result") $("result-stale").hidden = !maskedResult.stale;
  window.scrollTo(0, 0);
  const title = document.querySelector(`.wizard-step[data-step="${name}"] .step-title`);
  if (focus && title) title.focus({ preventScroll: true });
}

function renderStepper() {
  const reached = { input: true, review: Boolean(state.analysed), result: Boolean(maskedResult.text) };
  for (const link of document.querySelectorAll(".step-link")) {
    const step = link.dataset.step;
    link.disabled = !reached[step];
    link.classList.toggle("done", STEPS.indexOf(step) < STEPS.indexOf(currentStep));
    if (step === currentStep) link.setAttribute("aria-current", "step");
    else link.removeAttribute("aria-current");
  }
}

// A decision after masking makes the result out of date: the result step says so.
function markResultStale() {
  if (maskedResult.text) maskedResult.stale = true;
}

function startOver() {
  goToStep("input", false);
  $("input-text").focus();
}

// A document dropped anywhere on the first step is taken as the upload.
function onDrop(event) {
  event.preventDefault();
  $("input-step").classList.remove("dragging");
  const files = event.dataTransfer && event.dataTransfer.files;
  if (!files || !files.length) return;
  $("input-file").files = files;
  onFileChosen();
}

async function loadConfig() {
  try {
    const response = await fetch("/api/config", { cache: "no-store", credentials: "omit" });
    if (response.ok) state.config = await response.json();
  } catch {
    state.config = null;
  }
  // The desktop app signs the window in: no key to enter.
  if (localAuth()) $("key-card").hidden = true;
  describeFileSupport();
}

// Ctrl/Cmd+Z and Ctrl/Cmd+Shift+Z (or Ctrl+Y) undo and redo decisions, except
// while typing in a text field, which keeps its own undo.
function onKeyDown(event) {
  if ($("review").hidden || onCheckKey(event) || !(event.ctrlKey || event.metaKey) || event.altKey) return;
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
$("ignore-picked").addEventListener("click", ignoreChecked);
$("check-unsure").addEventListener("click", () => startCheck("unsure"));
$("check-unchecked").addEventListener("click", () => startCheck("unchecked"));
$("check-spot").addEventListener("click", () => startCheck("spot"));
$("mask-check").addEventListener("click", () => startCheck("unsure"));
$("check-close").addEventListener("click", closeCheck);
for (const button of document.querySelectorAll(".step-link, .step-back")) button.addEventListener("click", () => goToStep(button.dataset.step));
$("start-over").addEventListener("click", startOver);
$("remask").addEventListener("click", mask);
$("default-operator").addEventListener("change", markResultStale);
$("input-text").addEventListener("keydown", (event) => {
  if (event.key === "Enter" && (event.ctrlKey || event.metaKey)) {
    event.preventDefault();
    analyze();
  }
});
$("input-step").addEventListener("dragover", (event) => {
  event.preventDefault();
  $("input-step").classList.add("dragging");
});
$("input-step").addEventListener("dragleave", (event) => {
  if (event.target === $("input-step")) $("input-step").classList.remove("dragging");
});
$("input-step").addEventListener("drop", onDrop);
$("show-replacements").addEventListener("change", (event) => {
  showReplacements = event.target.checked;
  if (resultView) resultView.dispatch({ effects: refreshEffect.of(null) });
});
$("sel-mask").addEventListener("click", maskSelection);
$("sel-mask-all").addEventListener("click", maskSelectionEverywhere);
$("sel-keep").addEventListener("click", keepSelection);
$("find-previous").addEventListener("click", () => moveToFind(-1));
$("find-next").addEventListener("click", () => moveToFind(1));
$("find-unsure").addEventListener("click", () => moveToFind(1, true));
for (const action of ["mask", "keep", "skip", "back"]) $(`check-${action}`).addEventListener("click", () => checkStep(action));
$("unsure-mask").addEventListener("click", () => decide(unsureIds(), 1));
$("unsure-keep").addEventListener("click", () => decide(unsureIds(), 0));
for (const name of ["always", "ignore"]) {
  $(`${name}-add`).addEventListener("click", () => onAddTerm(name));
  $(`${name}-input`).addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
      onAddTerm(name);
    }
  });
}
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
