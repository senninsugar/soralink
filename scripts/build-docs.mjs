// docs/api.template.md から src/api_docs.js(Workerが /llms.txt で配信) と API.md(AIに渡す完成版) を生成する。
// 仕様書を編集したら `node scripts/build-docs.mjs [BaseURL]` を実行して、そのまま再デプロイしてください。
import { readFileSync, writeFileSync } from "node:fs";
const base = (process.argv[2] || "https://senninaccountv2.workers.dev").replace(/\/+$/, "");
const tpl = readFileSync(new URL("../docs/api.template.md", import.meta.url), "utf8");
writeFileSync(new URL("../API.md", import.meta.url), tpl.replaceAll("{{BASE}}", base));
writeFileSync(
  new URL("../src/api_docs.js", import.meta.url),
  "// 自動生成: scripts/build-docs.mjs (編集しないこと。元は docs/api.template.md)\nexport const API_DOCS_TEMPLATE = " + JSON.stringify(tpl) + ";\n"
);
console.log("generated API.md and src/api_docs.js for", base);
