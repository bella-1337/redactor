// Bundles entry.js into app/pii_review/static/codemirror.js, with the licence
// notice of every bundled package at the top of the file.
import { readFileSync } from "node:fs";
import { build } from "esbuild";

const BUNDLED = ["@codemirror/state", "@codemirror/view", "@codemirror/search", "style-mod", "crelt", "w3c-keyname", "@marijn/find-cluster-break"];
const here = new URL(".", import.meta.url);

const notices = BUNDLED.map((name) => {
  const { version } = JSON.parse(readFileSync(new URL(`node_modules/${name}/package.json`, here), "utf8"));
  const licence = readFileSync(new URL(`node_modules/${name}/LICENSE`, here), "utf8").trim();
  return `${name} ${version}\n\n${licence}`;
});

await build({
  entryPoints: [new URL("entry.js", here).pathname],
  outfile: new URL("../pii_review/static/codemirror.js", here).pathname,
  bundle: true,
  format: "esm",
  minify: true,
  target: "es2020",
  legalComments: "none",
  banner: { js: `/*!\n${notices.join("\n\n----\n\n").replaceAll("*/", "* /")}\n*/` },
  logLevel: "info",
});
