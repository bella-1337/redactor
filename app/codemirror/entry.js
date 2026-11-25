// The parts of CodeMirror 6 the review page uses, bundled into one file so the
// page needs no build step and loads nothing from outside the app.
export { EditorState, RangeSetBuilder, StateEffect } from "@codemirror/state";
export { Decoration, EditorView, ViewPlugin, WidgetType, keymap } from "@codemirror/view";
export { search, searchKeymap } from "@codemirror/search";
